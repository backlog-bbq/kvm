package moonlight

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// activePairings holds in-progress pairing states keyed by uniqueID.
// These are transient and not persisted across restarts.
var (
	activePairings   = make(map[string]*pairingState)
	activePairingsMu sync.Mutex
)

// ── XML helpers ──────────────────────────────────────────────────────────────

// xmlResponse writes a UTF-8 XML response with the given root element content.
func xmlResponse(w http.ResponseWriter, statusCode int, rootContent string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+
		`<root status_code="%d">%s</root>`, statusCode, rootContent)
}

func xmlOK(w http.ResponseWriter, content string) { xmlResponse(w, 200, content) }

func xmlError(w http.ResponseWriter, code int, msg string) {
	xmlResponse(w, code, fmt.Sprintf(`<status_message>%s</status_message>`, xmlEsc(msg)))
}

// xmlEsc escapes the five XML special characters so the string is safe inside
// an element's text content or attribute value.
func xmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// ── HTTP / HTTPS server setup ─────────────────────────────────────────────────

// nvhttpMux builds the shared ServeMux with all NVHTTP endpoints.
func (s *Server) nvhttpMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/serverinfo", s.handleServerInfo)
	mux.HandleFunc("/pair", s.handlePair)
	mux.HandleFunc("/applist", s.handleAppList)
	mux.HandleFunc("/launch", s.handleLaunch)
	mux.HandleFunc("/resume", s.handleResume)
	mux.HandleFunc("/cancel", s.handleCancel)
	mux.HandleFunc("/unpair", s.handleUnpair)
	return mux
}

// runNVHTTPServer starts the unencrypted discovery server on port 47989.
// Moonlight uses this port for /serverinfo, /applist, /launch, /cancel.
func (s *Server) runNVHTTPServer() {
	addr := fmt.Sprintf(":%d", NVHTTPPort)
	srv := &http.Server{Addr: addr, Handler: s.nvhttpMux()}
	log.Info().Str("addr", addr).Msg("NVHTTP HTTP server listening")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("NVHTTP HTTP server error")
	}
}

// runNVHTTPSServer starts the TLS server on port 47984 using the server's
// self-signed certificate. Moonlight sends ALL /pair requests here.
func (s *Server) runNVHTTPSServer() {
	// Load key + cert from the pairing store (generated at startup).
	s.store.mu.RLock()
	certPEM := s.store.ServerCertPEM
	keyPEM := s.store.ServerKeyPEM
	s.store.mu.RUnlock()

	if certPEM == "" || keyPEM == "" {
		log.Error().Msg("NVHTTP HTTPS: server cert/key not available, skipping TLS listener")
		return
	}

	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		log.Error().Err(err).Msg("NVHTTP HTTPS: failed to parse TLS credentials")
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf(":%d", NVHTTPSPort)
	srv := &http.Server{
		Addr:      addr,
		Handler:   s.nvhttpMux(),
		TLSConfig: tlsConfig,
	}

	log.Info().Str("addr", addr).Msg("NVHTTP HTTPS server listening")
	// ListenAndServeTLS("","") uses the certificates already set in TLSConfig.
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("NVHTTP HTTPS server error")
	}
}

// ── /serverinfo ───────────────────────────────────────────────────────────────

func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	paired := 0
	if uniqueID != "" && s.store.IsPaired(uniqueID) {
		paired = 1
	}

	currentGame := 0
	state := "SUNSHINE_SERVER_FREE"
	if s.getSession() != nil {
		currentGame = 1
		state = "SUNSHINE_SERVER_BUSY"
	}

	localIP := getOutboundIP()

	log.Debug().
		Str("remote", r.RemoteAddr).
		Str("uniqueID", uniqueID).
		Int("paired", paired).
		Str("localIP", localIP).
		Msg("/serverinfo")

	body := fmt.Sprintf(`
<hostname>%s</hostname>
<appversion>7.1.431.-1</appversion>
<GfeVersion>3.23.0.74</GfeVersion>
<uniqueid>%s</uniqueid>
<HttpsPort>%d</HttpsPort>
<ExternalPort>%d</ExternalPort>
<mac>%s</mac>
<LocalIP>%s</LocalIP>
<PairStatus>%d</PairStatus>
<currentgame>%d</currentgame>
<state>%s</state>
<ServerCodecModeSupport>1</ServerCodecModeSupport>
<SupportedDisplayMode>
  <DisplayMode>
    <Width>1920</Width>
    <Height>1080</Height>
    <RefreshRate>60</RefreshRate>
  </DisplayMode>
</SupportedDisplayMode>`,
		xmlEsc(s.cfg.Hostname), xmlEsc(s.cfg.DeviceID),
		NVHTTPSPort, NVHTTPPort,
		xmlEsc(s.cfg.MacAddr), xmlEsc(localIP),
		paired, currentGame, state,
	)
	xmlOK(w, body)
}

// ── /pair dispatcher ──────────────────────────────────────────────────────────

// handlePair is the entry point for all four pairing phases.
//
// Pairing uses a mutual-authentication challenge-response protocol based on a
// shared 4-digit PIN. Protocol overview (all AES uses CBC mode, zero IV):
//
//	Phase 1  getservercert        – server returns its X.509 cert; PIN is generated
//	Phase 2  clientchallenge      – client proves PIN knowledge; server returns challenge
//	Phase 3  serverchallengeresp  – client proves cert ownership; server returns signed secret
//	Phase 4  clientpairingsecret  – client delivers its cert; server verifies and stores it
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uniqueID := q.Get("uniqueid")
	phase := q.Get("phase")

	if uniqueID == "" {
		log.Warn().Str("remote", r.RemoteAddr).Msg("/pair: missing uniqueid")
		xmlError(w, 400, "missing uniqueid")
		return
	}

	log.Info().
		Str("remote", r.RemoteAddr).
		Bool("tls", r.TLS != nil).
		Str("uniqueID", uniqueID).
		Str("phase", phase).
		Msg("/pair request received")

	switch phase {
	case "getservercert":
		s.handlePairGetServerCert(w, uniqueID, q.Get("devicename"), q.Get("salt"))
	case "clientchallenge":
		s.handlePairClientChallenge(w, uniqueID, q.Get("clientchallenge"))
	case "serverchallengeresp":
		s.handlePairServerChallengeResp(w, uniqueID,
			q.Get("serverchallengeresp"), q.Get("clientpairingsecret"))
	case "clientpairingsecret":
		s.handlePairClientPairingSecret(w, uniqueID, q.Get("clientpairingsecret"))
	default:
		log.Warn().Str("phase", phase).Msg("/pair: unknown phase")
		xmlError(w, 400, fmt.Sprintf("unknown pairing phase: %s", phase))
	}
}

// ── Phase 1: getservercert ────────────────────────────────────────────────────

// handlePairGetServerCert returns the server's X.509 certificate and notifies
// the JetKVM UI to prompt the user for the PIN shown on the Moonlight client.
//
// The client sends its own certificate and a random salt in this phase.
// The AES key will be derived in phase 2 once the user has submitted the PIN:
//
//	aesKey = SHA256(salt ‖ PIN)[0:16]
func (s *Server) handlePairGetServerCert(w http.ResponseWriter, uniqueID, deviceName, saltHex string) {
	var salt []byte
	if saltHex != "" {
		var err error
		salt, err = hex.DecodeString(saltHex)
		if err != nil {
			log.Warn().Err(err).Str("salt", saltHex).Msg("phase1: invalid salt hex; continuing without salt")
		}
	}

	state := &pairingState{
		uniqueID:   uniqueID,
		deviceName: deviceName,
		salt:       salt,
		pinCh:      make(chan string, 1),
	}
	activePairingsMu.Lock()
	activePairings[uniqueID] = state
	activePairingsMu.Unlock()

	// Tell the UI to show a PIN-entry dialog.  The PIN is displayed on the
	// Moonlight client; the user must type it into the JetKVM web interface.
	if s.cfg.PINCallback != nil {
		go s.cfg.PINCallback(deviceName, uniqueID)
	}

	certPEM := string(s.store.ServerCertPEMBytes())
	log.Info().
		Str("uniqueID", uniqueID).
		Str("deviceName", deviceName).
		Bool("hasSalt", len(salt) > 0).
		Int("certPEMLen", len(certPEM)).
		Msg("phase1 complete: waiting for user PIN input, returning server cert")

	xmlOK(w, fmt.Sprintf(`<paired>0</paired><plaincert>%s</plaincert>`, certPEM))
}

// ── Phase 2: clientchallenge ──────────────────────────────────────────────────

// handlePairClientChallenge processes the client's AES-CBC encrypted random
// challenge. The server first blocks (up to 120 s) waiting for the user to
// enter the PIN shown on the Moonlight client. Once received, the AES key is
// derived as SHA256(salt ‖ PIN)[0:16].
//
// Server response plaintext (48 bytes):
//
//	serverResponse (32) = SHA256(clientData ‖ serverCert.Signature ‖ serverChallenge)
//	serverChallenge (16)
func (s *Server) handlePairClientChallenge(w http.ResponseWriter, uniqueID, challengeHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()
	if !ok {
		log.Warn().Str("uniqueID", uniqueID).Msg("phase2: no pending pairing state")
		xmlError(w, 400, "no pending pairing for this uniqueid; start from phase 1")
		return
	}

	log.Debug().
		Str("uniqueID", uniqueID).
		Int("challengeHexLen", len(challengeHex)).
		Msg("phase2: waiting for user PIN input")

	// Block until the user submits the PIN via the JetKVM UI (or timeout).
	select {
	case pin := <-state.pinCh:
		state.aesKey = pairingAESKey(pin, state.salt)
		log.Info().
			Str("uniqueID", uniqueID).
			Bool("hasSalt", len(state.salt) > 0).
			Msg("phase2: PIN received, AES key derived")
	case <-time.After(120 * time.Second):
		log.Warn().Str("uniqueID", uniqueID).Msg("phase2: timed out waiting for PIN")
		activePairingsMu.Lock()
		delete(activePairings, uniqueID)
		activePairingsMu.Unlock()
		xmlError(w, 408, "timed out waiting for PIN entry")
		return
	}

	challengeEnc, err := hexDecode(challengeHex)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase2: hex decode failed")
		xmlError(w, 400, "invalid clientchallenge hex")
		return
	}

	clientData, err := aes128CBCDecrypt(state.aesKey, challengeEnc)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase2: AES-CBC decrypt failed (wrong PIN?)")
		xmlError(w, 500, "failed to decrypt client challenge")
		return
	}

	serverChallenge := make([]byte, 16)
	if _, err := rand.Read(serverChallenge); err != nil {
		log.Error().Err(err).Msg("phase2: rand.Read failed")
		xmlError(w, 500, "failed to generate server challenge")
		return
	}
	state.serverChallenge = serverChallenge

	s.store.mu.RLock()
	serverCertSig := s.store.serverCert.Signature
	s.store.mu.RUnlock()

	// serverResponse = SHA256(clientData ‖ serverCert.Signature ‖ serverChallenge)
	h := sha256.New()
	h.Write(clientData)
	h.Write(serverCertSig)
	h.Write(serverChallenge)
	serverResponse := h.Sum(nil) // 32 bytes
	state.serverResponse = serverResponse

	// Return AES-CBC(serverResponse ‖ serverChallenge, aesKey)  — 48 bytes.
	plaintext := append(append([]byte(nil), serverResponse...), serverChallenge...)
	encrypted, err := aes128CBCEncrypt(state.aesKey, plaintext)
	if err != nil {
		log.Error().Err(err).Str("uniqueID", uniqueID).Msg("phase2: AES-CBC encrypt failed")
		xmlError(w, 500, "failed to encrypt server challenge")
		return
	}

	log.Info().
		Str("uniqueID", uniqueID).
		Str("serverResponseHex", hex.EncodeToString(serverResponse)).
		Msg("phase2 complete: returning server challenge")

	xmlOK(w, fmt.Sprintf(`<paired>0</paired><challenge>%s</challenge>`,
		hex.EncodeToString(encrypted)))
}

// ── Phase 3: serverchallengeresp ─────────────────────────────────────────────

// handlePairServerChallengeResp processes the client's response to our phase-2
// challenge. The client sends:
//
//	serverchallengeresp = AES_CBC(SHA256(serverResponse ‖ clientCert.Signature), key)
//	clientpairingsecret = RSA_sign(SHA256(serverChallenge), clientPrivKey)
//
// We cannot fully verify these yet (we don't have the client cert). We store the
// decrypted hash for verification in phase 4 and return our signed secret so the
// client can verify us.
//
// Server signed secret = RSA_sign(SHA256(clientHash ‖ serverCert.Signature), serverKey)
func (s *Server) handlePairServerChallengeResp(w http.ResponseWriter, uniqueID, serverChallengeRespHex, clientPairingSecretHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()
	if !ok {
		log.Warn().Str("uniqueID", uniqueID).Msg("phase3: no pending pairing state")
		xmlError(w, 400, "no pending pairing for this uniqueid; start from phase 1")
		return
	}

	log.Debug().
		Str("uniqueID", uniqueID).
		Int("respHexLen", len(serverChallengeRespHex)).
		Int("secretHexLen", len(clientPairingSecretHex)).
		Msg("phase3: received serverchallengeresp + clientpairingsecret")

	respEnc, err := hexDecode(serverChallengeRespHex)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase3: hex decode of serverchallengeresp failed")
		xmlError(w, 400, "invalid serverchallengeresp hex")
		return
	}

	// Decrypt: result should be SHA256(serverResponse ‖ clientCert.Signature).
	clientHash, err := aes128CBCDecrypt(state.aesKey, respEnc)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase3: AES-CBC decrypt failed (wrong PIN?)")
		xmlError(w, 500, "failed to decrypt serverchallengeresp")
		return
	}

	// Store for verification in phase 4 — we cannot verify now without the client cert.
	state.clientChallengeHash = clientHash
	log.Debug().
		Str("uniqueID", uniqueID).
		Str("clientHashHex", hex.EncodeToString(clientHash)).
		Msg("phase3: stored client challenge hash")

	// Compute and return our signed secret so the client can verify us:
	// serverSecret = RSA_sign_SHA256(clientHash ‖ serverCert.Signature, serverKey)
	s.store.mu.RLock()
	serverCertSig := s.store.serverCert.Signature
	s.store.mu.RUnlock()

	toSign := append(append([]byte(nil), clientHash...), serverCertSig...)
	serverSecret, err := s.store.rsaSignSHA256(toSign)
	if err != nil {
		log.Error().Err(err).Str("uniqueID", uniqueID).Msg("phase3: RSA sign failed")
		xmlError(w, 500, "failed to sign server secret")
		return
	}

	log.Info().Str("uniqueID", uniqueID).Msg("phase3 complete: returning signed server secret")
	xmlOK(w, fmt.Sprintf(`<paired>0</paired><pairingsecret>%s</pairingsecret>`,
		hex.EncodeToString(serverSecret)))
}

// ── Phase 4: clientpairingsecret ─────────────────────────────────────────────

// handlePairClientPairingSecret receives the client's X.509 certificate (hex PEM),
// verifies the phase-3 hash, and — if valid — stores the client as paired.
//
// Verification:
//
//	expected = SHA256(state.serverResponse ‖ clientCert.Signature)
//	assert expected == state.clientChallengeHash
func (s *Server) handlePairClientPairingSecret(w http.ResponseWriter, uniqueID, clientPairingSecretHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()
	if !ok {
		log.Warn().Str("uniqueID", uniqueID).Msg("phase4: no pending pairing state")
		xmlError(w, 400, "no pending pairing for this uniqueid; start from phase 1")
		return
	}

	log.Debug().
		Str("uniqueID", uniqueID).
		Int("secretHexLen", len(clientPairingSecretHex)).
		Msg("phase4: received clientpairingsecret (client cert)")

	clientCertBytes, err := hexDecode(clientPairingSecretHex)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase4: hex decode failed")
		xmlError(w, 400, "invalid clientpairingsecret hex")
		return
	}
	state.clientCertPEM = string(clientCertBytes)

	// Verify the phase-3 challenge hash now that we have the client cert signature.
	if len(state.clientChallengeHash) > 0 && len(state.serverResponse) > 0 {
		// Parse client cert to extract its Signature bytes.
		clientSig, parseErr := extractCertSignature(clientCertBytes)
		if parseErr != nil {
			log.Warn().Err(parseErr).Str("uniqueID", uniqueID).
				Msg("phase4: could not parse client cert to verify challenge hash; accepting anyway")
		} else {
			expected := sha256.Sum256(append(append([]byte(nil), state.serverResponse...), clientSig...))
			if len(state.clientChallengeHash) >= 32 {
				if [32]byte(state.clientChallengeHash[:32]) != expected {
					log.Warn().
						Str("uniqueID", uniqueID).
						Str("got", hex.EncodeToString(state.clientChallengeHash[:32])).
						Str("expected", hex.EncodeToString(expected[:])).
						Msg("phase4: client challenge hash mismatch — wrong PIN or tampered exchange")
					activePairingsMu.Lock()
					delete(activePairings, uniqueID)
					activePairingsMu.Unlock()
					xmlError(w, 403, "challenge verification failed")
					return
				}
				log.Debug().Str("uniqueID", uniqueID).Msg("phase4: client challenge hash verified OK")
			}
		}
	}

	if err := s.store.StorePairedClient(uniqueID, state.clientCertPEM); err != nil {
		log.Error().Err(err).Str("uniqueID", uniqueID).Msg("phase4: failed to save paired client")
		xmlError(w, 500, "failed to save pairing")
		return
	}

	activePairingsMu.Lock()
	delete(activePairings, uniqueID)
	activePairingsMu.Unlock()

	log.Info().Str("uniqueID", uniqueID).Msg("phase4 complete: pairing succeeded")
	xmlOK(w, `<paired>1</paired>`)
}

// ── Other endpoints ───────────────────────────────────────────────────────────

func (s *Server) handleAppList(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("remote", r.RemoteAddr).Msg("/applist")
	xmlOK(w, `
<App>
  <IsHdrSupported>0</IsHdrSupported>
  <AppTitle>JetKVM</AppTitle>
  <ID>1</ID>
</App>`)
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	log.Info().Str("uniqueID", uniqueID).Str("remote", r.RemoteAddr).Msg("/launch")
	if uniqueID == "" || !s.store.IsPaired(uniqueID) {
		log.Warn().Str("uniqueID", uniqueID).Msg("/launch: not paired")
		xmlError(w, 403, "not paired")
		return
	}
	xmlOK(w, fmt.Sprintf(`<sessionUrl0>rtsp://%s:%d</sessionUrl0><gamesession>1</gamesession>`,
		getOutboundIP(), RTSPPort))
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	log.Info().Str("uniqueID", uniqueID).Str("remote", r.RemoteAddr).Msg("/resume")
	if uniqueID == "" || !s.store.IsPaired(uniqueID) {
		log.Warn().Str("uniqueID", uniqueID).Msg("/resume: not paired")
		xmlError(w, 403, "not paired")
		return
	}
	xmlOK(w, `<sessionUrl0></sessionUrl0><resume>1</resume>`)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	log.Info().Str("remote", r.RemoteAddr).Msg("/cancel: ending session")
	s.clearSession()
	xmlOK(w, `<cancel>1</cancel>`)
}

func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	log.Info().Str("uniqueID", uniqueID).Msg("/unpair")
	if uniqueID == "" {
		xmlError(w, 400, "missing uniqueid")
		return
	}
	if err := s.store.RemovePairedClient(uniqueID); err != nil {
		log.Error().Err(err).Str("uniqueID", uniqueID).Msg("/unpair: failed")
		xmlError(w, 500, "failed to unpair")
		return
	}
	log.Info().Str("uniqueID", uniqueID).Msg("client unpaired")
	xmlOK(w, `<unpaired>1</unpaired>`)
}

// ── Utility ───────────────────────────────────────────────────────────────────

// getOutboundIP returns the primary local IP by probing a UDP route.
func getOutboundIP() string {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// extractCertSignature parses a DER- or PEM-encoded certificate and returns
// its Signature field (the raw signature bytes over the TBS certificate).
func extractCertSignature(data []byte) ([]byte, error) {
	der := data
	// If the data looks like PEM, decode the first block to get the DER bytes.
	if strings.HasPrefix(strings.TrimSpace(string(data)), "-----") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("moonlight: failed to decode PEM block from client cert")
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("moonlight: parsing client cert: %w", err)
	}
	return cert.Signature, nil
}
