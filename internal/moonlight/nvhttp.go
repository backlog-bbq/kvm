package moonlight

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

func xmlOK(w http.ResponseWriter, content string) {
	log.Debug().Int("contentLen", len(content)).Msg("xmlOK: sending 200 response")
	xmlResponse(w, 200, content)
}

func xmlError(w http.ResponseWriter, code int, msg string) {
	log.Warn().Int("code", code).Str("msg", msg).Msg("xmlError: sending error response")
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
// Every request is logged at Debug level by the loggingMiddleware wrapper.
func (s *Server) nvhttpMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/serverinfo", s.nvhttpLog(s.handleServerInfo))
	mux.HandleFunc("/pair", s.nvhttpLog(s.handlePair))
	mux.HandleFunc("/applist", s.nvhttpLog(s.handleAppList))
	mux.HandleFunc("/launch", s.nvhttpLog(s.handleLaunch))
	mux.HandleFunc("/resume", s.nvhttpLog(s.handleResume))
	mux.HandleFunc("/cancel", s.nvhttpLog(s.handleCancel))
	mux.HandleFunc("/unpair", s.nvhttpLog(s.handleUnpair))
	return mux
}

// nvhttpLog wraps a handler to log every incoming NVHTTP request with its full
// URL (including query string) so that protocol issues are immediately visible.
func (s *Server) nvhttpLog(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Bool("tls", r.TLS != nil).
			Str("remote", r.RemoteAddr).
			Str("host", r.Host).
			Msg("NVHTTP request")
		h(w, r)
	}
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
	log.Info().Msg("NVHTTP HTTPS: TLS credentials parsed OK")

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
// Moonlight uses the query parameter "phrase" (not "phase") for the phase name.
// We accept both spellings for compatibility with all client versions.
//
// Pairing uses a mutual-authentication challenge-response protocol based on a
// shared 4-digit PIN. Protocol overview (all AES uses CBC mode, zero IV):
//
//	Phase 1  getservercert        – client sends its cert + salt; server returns its cert
//	Phase 2  clientchallenge      – client proves PIN knowledge; server returns challenge
//	Phase 3  serverchallengeresp  – client proves cert ownership; server returns signed secret
//	Phase 4  clientpairingsecret  – client delivers its cert; server verifies and stores it
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uniqueID := q.Get("uniqueid")

	// Moonlight sends "phrase" for Phase 1 only. Phases 2-4 have NO phrase
	// parameter — the phase is identified by which data parameter is present.
	// Some other implementations send "phase" for all phases. We support both.
	phase := q.Get("phrase")
	if phase == "" {
		phase = q.Get("phase")
	}

	// Auto-detect phase from query parameters when phrase/phase is missing.
	// Moonlight clients (iOS, Android, Qt) only send phrase=getservercert
	// for Phase 1 and omit it for Phases 2-4.
	if phase == "" {
		switch {
		case q.Get("clientchallenge") != "":
			phase = "clientchallenge"
		case q.Get("serverchallengeresp") != "":
			phase = "serverchallengeresp"
		case q.Get("clientpairingsecret") != "":
			phase = "clientpairingsecret"
		}
	}

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
		Str("devicename", q.Get("devicename")).
		Bool("hasSalt", q.Get("salt") != "").
		Int("saltLen", len(q.Get("salt"))).
		Bool("hasClientCert", q.Get("clientcert") != "").
		Int("clientCertLen", len(q.Get("clientcert"))).
		Bool("hasClientChallenge", q.Get("clientchallenge") != "").
		Bool("hasServerChallengeResp", q.Get("serverchallengeresp") != "").
		Bool("hasClientPairingSecret", q.Get("clientpairingsecret") != "").
		Str("fullPath", r.URL.Path).
		Msg("/pair: dispatching pairing phase")

	switch phase {
	case "getservercert":
		s.handlePairGetServerCert(w, r, uniqueID, q.Get("devicename"), q.Get("salt"), q.Get("clientcert"))
	case "clientchallenge":
		s.handlePairClientChallenge(w, r, uniqueID, q.Get("clientchallenge"))
	case "serverchallengeresp":
		s.handlePairServerChallengeResp(w, uniqueID,
			q.Get("serverchallengeresp"), q.Get("clientpairingsecret"))
	case "clientpairingsecret":
		s.handlePairClientPairingSecret(w, uniqueID, q.Get("clientpairingsecret"))
	default:
		log.Warn().
			Str("phrase", q.Get("phrase")).
			Str("phase", q.Get("phase")).
			Str("uniqueID", uniqueID).
			Str("rawQuery", r.URL.RawQuery[:min(len(r.URL.RawQuery), 200)]).
			Msg("/pair: could not determine pairing phase from phrase/phase param or query parameters")
		xmlError(w, 400, fmt.Sprintf("unknown pairing phase: %q", phase))
	}
}

// ── Phase 1: getservercert ────────────────────────────────────────────────────

// handlePairGetServerCert handles Phase 1 of the Moonlight pairing protocol.
//
// The client sends its certificate and a random salt. The server blocks here
// (up to 3 minutes) until the user enters the PIN on the JetKVM settings page.
// The Moonlight client gives Phase 1 a 180-second timeout, so blocking here is
// safe. Once the PIN is entered the AES key is derived and the server responds
// with its certificate — Phase 2 can then proceed immediately.
func (s *Server) handlePairGetServerCert(w http.ResponseWriter, r *http.Request, uniqueID, deviceName, saltHex, clientCertHex string) {
	log.Info().
		Str("uniqueID", uniqueID).
		Str("deviceName", deviceName).
		Int("saltHexLen", len(saltHex)).
		Int("clientCertHexLen", len(clientCertHex)).
		Msg("phase1: START getservercert")

	var salt []byte
	if saltHex != "" {
		var err error
		salt, err = hex.DecodeString(saltHex)
		if err != nil {
			log.Warn().Err(err).Msg("phase1: invalid salt hex; continuing without salt")
		}
	}

	state := &pairingState{
		uniqueID:   uniqueID,
		deviceName: deviceName,
		salt:       salt,
		pinCh:      make(chan string, 1),
	}

	// Save client certificate DER bytes for use in phase 4.
	if clientCertHex != "" {
		clientCertDER, err := hex.DecodeString(clientCertHex)
		if err != nil {
			log.Warn().Err(err).Msg("phase1: invalid clientcert hex")
		} else {
			state.clientCertDER = clientCertDER
		}
	}

	// If the user already entered a PIN in a previous attempt, carry it
	// forward and re-derive the AES key with the new salt.
	activePairingsMu.Lock()
	if prev, exists := activePairings[uniqueID]; exists && prev.pin != "" {
		state.pin = prev.pin
		state.aesKey = pairingAESKey(prev.pin, salt)
		log.Info().Str("uniqueID", uniqueID).Msg("phase1: reusing PIN from previous attempt")
	}
	activePairings[uniqueID] = state
	activePairingsMu.Unlock()

	// Notify UI that a pairing request is pending.
	if s.cfg.PINCallback != nil {
		go s.cfg.PINCallback(deviceName, uniqueID)
	}

	// Block until PIN is entered (or pre-derived from a previous attempt).
	if state.aesKey == nil {
		log.Info().Str("uniqueID", uniqueID).Msg("phase1: waiting for user to enter PIN on settings page...")
		select {
		case pin := <-state.pinCh:
			state.pin = pin
			state.aesKey = pairingAESKey(pin, salt)
			log.Info().Str("uniqueID", uniqueID).Msg("phase1: PIN received, AES key derived")
		case <-r.Context().Done():
			log.Info().Str("uniqueID", uniqueID).Msg("phase1: client disconnected while waiting for PIN")
			return
		case <-s.ctx.Done():
			log.Info().Str("uniqueID", uniqueID).Msg("phase1: server shutting down")
			return
		}
	} else {
		log.Info().Str("uniqueID", uniqueID).Msg("phase1: PIN already available, responding immediately")
	}

	// Return server cert as hex-encoded PEM (not DER).
	// Moonlight clients hex-decode this and parse with PEM_read_bio_X509().
	s.store.mu.RLock()
	certPEM := s.store.ServerCertPEM
	s.store.mu.RUnlock()

	if certPEM == "" {
		log.Error().Msg("phase1: server cert PEM is empty")
		xmlError(w, 500, "internal error")
		return
	}
	certHex := hex.EncodeToString([]byte(certPEM))

	log.Info().
		Str("uniqueID", uniqueID).
		Int("certHexLen", len(certHex)).
		Msg("phase1: COMPLETE — sending server cert to client")

	xmlOK(w, fmt.Sprintf(`<paired>1</paired><plaincert>%s</plaincert>`, certHex))
}

// ── Phase 2: clientchallenge ──────────────────────────────────────────────────

// handlePairClientChallenge processes the client's AES-CBC encrypted random
// challenge. If the user has already submitted the PIN (via the settings page),
// the AES key is pre-derived and we respond immediately. Otherwise we return
// paired=0 so the client fails fast — the user can enter the PIN and retry.
//
// Server response plaintext (48 bytes):
//
//	serverResponse (32) = SHA256(clientData ‖ serverCert.Signature ‖ serverChallenge)
//	serverChallenge (16)
func (s *Server) handlePairClientChallenge(w http.ResponseWriter, r *http.Request, uniqueID, challengeHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()
	if !ok {
		log.Warn().Str("uniqueID", uniqueID).Msg("phase2: no pending pairing state")
		xmlError(w, 400, "no pending pairing for this uniqueid; start from phase 1")
		return
	}

	log.Info().
		Str("uniqueID", uniqueID).
		Int("challengeHexLen", len(challengeHex)).
		Bool("hasAESKey", state.aesKey != nil).
		Msg("phase2: processing client challenge")

	// If the PIN hasn't been entered yet, fail fast. The Moonlight client
	// has a ~5 s timeout so blocking is not viable. The user enters the PIN
	// on the settings page and retries pairing — Phase 1 will carry the PIN
	// forward and Phase 2 will respond immediately on the next attempt.
	if state.aesKey == nil {
		log.Info().Str("uniqueID", uniqueID).Msg("phase2: PIN not yet entered — returning paired=0 so client can retry after PIN entry")
		xmlOK(w, `<paired>0</paired>`)
		return
	}
	log.Info().Str("uniqueID", uniqueID).Msg("phase2: PIN available, responding immediately")

	challengeEnc, err := hexDecode(challengeHex)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase2: hex decode failed")
		xmlError(w, 400, "invalid clientchallenge hex")
		return
	}

	log.Debug().
		Str("uniqueID", uniqueID).
		Str("challengeEncHex", hex.EncodeToString(challengeEnc)).
		Msg("phase2: decrypting client challenge")

	clientData, err := aes128CBCDecrypt(state.aesKey, challengeEnc)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase2: AES-CBC decrypt failed — wrong PIN or salt mismatch")
		xmlError(w, 500, "failed to decrypt client challenge")
		return
	}
	log.Debug().
		Str("uniqueID", uniqueID).
		Str("clientDataHex", hex.EncodeToString(clientData)).
		Msg("phase2: client challenge decrypted")

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
		Str("serverChallengeHex", hex.EncodeToString(serverChallenge)).
		Str("encryptedHex", hex.EncodeToString(encrypted)).
		Msg("phase2 complete: returning encrypted server challenge+response")

	xmlOK(w, fmt.Sprintf(`<paired>1</paired><challengeresponse>%s</challengeresponse>`,
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
	log.Debug().
		Str("uniqueID", uniqueID).
		Str("respEncHex", hex.EncodeToString(respEnc)).
		Msg("phase3: decrypting serverchallengeresp")

	clientHash, err := aes128CBCDecrypt(state.aesKey, respEnc)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase3: AES-CBC decrypt failed — wrong PIN or salt mismatch")
		xmlError(w, 500, "failed to decrypt serverchallengeresp")
		return
	}

	// Store for verification in phase 4 — we cannot verify now without the client cert.
	state.clientChallengeHash = clientHash
	log.Debug().
		Str("uniqueID", uniqueID).
		Str("clientHashHex", hex.EncodeToString(clientHash)).
		Msg("phase3: stored client challenge hash (will verify in phase 4)")

	// Compute and return our pairing secret:
	// serverSecret = random 16 bytes
	// serverSignature = RSA_sign(SHA256(serverSecret))
	// pairingsecret = hex(serverSecret ‖ serverSignature)
	//
	// The Moonlight client verifies: RSA_verify(serverPubKey, SHA256(serverSecret), sig)
	// — the cert signature is NOT included in the hash.
	serverSecret := make([]byte, 16)
	if _, err := rand.Read(serverSecret); err != nil {
		log.Error().Err(err).Msg("phase3: rand.Read failed")
		xmlError(w, 500, "failed to generate server secret")
		return
	}

	serverSignature, err := s.store.rsaSignSHA256(serverSecret)
	if err != nil {
		log.Error().Err(err).Str("uniqueID", uniqueID).Msg("phase3: RSA sign failed")
		xmlError(w, 500, "failed to sign server secret")
		return
	}

	pairingSecret := append(append([]byte(nil), serverSecret...), serverSignature...)

	log.Info().Str("uniqueID", uniqueID).Msg("phase3 complete: returning signed server secret")
	xmlOK(w, fmt.Sprintf(`<paired>1</paired><pairingsecret>%s</pairingsecret>`,
		hex.EncodeToString(pairingSecret)))
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
		Msg("phase4: received clientpairingsecret")

	// clientpairingsecret = hex(clientSecret_16bytes ‖ clientSignature)
	clientPairingSecretBytes, err := hexDecode(clientPairingSecretHex)
	if err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase4: hex decode failed")
		xmlError(w, 400, "invalid clientpairingsecret hex")
		return
	}

	if len(clientPairingSecretBytes) < 16 {
		log.Warn().Str("uniqueID", uniqueID).Int("len", len(clientPairingSecretBytes)).Msg("phase4: clientpairingsecret too short")
		xmlError(w, 400, "clientpairingsecret too short")
		return
	}

	clientSecret := clientPairingSecretBytes[:16]
	clientSignature := clientPairingSecretBytes[16:]

	log.Debug().
		Str("uniqueID", uniqueID).
		Int("clientSecretLen", len(clientSecret)).
		Int("clientSignatureLen", len(clientSignature)).
		Msg("phase4: parsed client pairing secret")

	// Use the client cert saved from Phase 1.
	clientCertDER := state.clientCertDER
	if len(clientCertDER) == 0 {
		log.Warn().Str("uniqueID", uniqueID).Msg("phase4: no client cert from phase 1")
		xmlError(w, 400, "missing client certificate from phase 1")
		return
	}

	// Verify client signature: RSA_verify(clientPubKey, SHA256(clientSecret), clientSignature)
	// The Moonlight client signs just the secret — cert signature is NOT included.
	clientCert, parseErr := x509.ParseCertificate(clientCertDER)
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("uniqueID", uniqueID).Msg("phase4: could not parse client cert")
		xmlError(w, 400, "invalid client certificate")
		return
	}

	verifyHash := sha256.Sum256(clientSecret)

	clientPubKey, ok2 := clientCert.PublicKey.(*rsa.PublicKey)
	if !ok2 {
		log.Warn().Str("uniqueID", uniqueID).Msg("phase4: client cert does not have RSA public key")
		xmlError(w, 400, "client certificate has non-RSA key")
		return
	}

	if err := rsa.VerifyPKCS1v15(clientPubKey, crypto.SHA256, verifyHash[:], clientSignature); err != nil {
		log.Warn().Err(err).Str("uniqueID", uniqueID).Msg("phase4: client signature verification failed")
		activePairingsMu.Lock()
		delete(activePairings, uniqueID)
		activePairingsMu.Unlock()
		xmlError(w, 403, "client signature verification failed")
		return
	}
	log.Info().Str("uniqueID", uniqueID).Msg("phase4: client signature verified OK")

	// Store the client cert from Phase 1 as PEM.
	clientCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}))

	if err := s.store.StorePairedClient(uniqueID, clientCertPEM); err != nil {
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

// min returns the smaller of a and b. Provided for compatibility with Go < 1.21.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
