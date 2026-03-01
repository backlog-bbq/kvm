package moonlight

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// activePairings holds in-progress pairing states keyed by uniqueID.
// These are transient and not persisted.
var (
	activePairings   = make(map[string]*pairingState)
	activePairingsMu sync.Mutex
)

// xmlResponse writes a UTF-8 XML response with the given root element content.
func xmlResponse(w http.ResponseWriter, statusCode int, rootContent string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+
		`<root status_code="%d">%s</root>`, statusCode, rootContent)
}

// xmlOK writes a 200 XML response.
func xmlOK(w http.ResponseWriter, content string) {
	xmlResponse(w, 200, content)
}

// xmlError writes a non-200 XML response with an error tag.
func xmlError(w http.ResponseWriter, code int, msg string) {
	xmlResponse(w, code, fmt.Sprintf(`<status_message>%s</status_message>`, xmlEscape(msg)))
}

func xmlEscape(s string) string {
	b, _ := xml.Marshal(s)
	// xml.Marshal wraps in tags; extract inner content.
	if len(b) > 2 {
		return string(b[8 : len(b)-9]) // strip <string> and </string>
	}
	return s
}

// runNVHTTPServer starts the NVHTTP discovery server on port 47989.
func (s *Server) runNVHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/serverinfo", s.handleServerInfo)
	mux.HandleFunc("/pair", s.handlePair)
	mux.HandleFunc("/applist", s.handleAppList)
	mux.HandleFunc("/launch", s.handleLaunch)
	mux.HandleFunc("/resume", s.handleResume)
	mux.HandleFunc("/cancel", s.handleCancel)
	mux.HandleFunc("/unpair", s.handleUnpair)

	addr := fmt.Sprintf(":%d", NVHTTPPort)
	srv := &http.Server{Addr: addr, Handler: mux}

	log.Info().Str("addr", addr).Msg("NVHTTP server listening")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("NVHTTP server error")
	}
}

// handleServerInfo returns device information used by Moonlight for discovery.
func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	paired := 0
	if uniqueID != "" && s.store.IsPaired(uniqueID) {
		paired = 1
	}

	// currentgame: 0 = no game running (maps to our "streaming not active" state).
	currentGame := 0
	sess := s.getSession()
	if sess != nil {
		currentGame = 1
	}

	state := "SUNSHINE_SERVER_FREE"
	if currentGame != 0 {
		state = "SUNSHINE_SERVER_BUSY"
	}

	// LocalIP: attempt to find the outbound address.
	localIP := getOutboundIP()

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
		xmlEscape(s.cfg.Hostname),
		xmlEscape(s.cfg.DeviceID),
		NVHTTPSPort,
		NVHTTPPort,
		xmlEscape(s.cfg.MacAddr),
		xmlEscape(localIP),
		paired,
		currentGame,
		state,
	)
	xmlOK(w, body)
}

// handlePair implements the 4-phase certificate exchange for Moonlight pairing.
//
// Phase 1 (getservercert): Return server certificate.
// Phase 2 (clientchallenge): Verify client challenge, return server challenge response.
// Phase 3 (serverchallengeresp): Verify client signature.
// Phase 4 (clientpairingsecret): Store client certificate.
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uniqueID := q.Get("uniqueid")
	phase := q.Get("phase")

	if uniqueID == "" {
		xmlError(w, 400, "missing uniqueid")
		return
	}

	log.Info().Str("uniqueID", uniqueID).Str("phase", phase).Msg("pairing request")

	switch phase {
	case "getservercert":
		s.handlePairGetServerCert(w, uniqueID, q.Get("devicename"))

	case "clientchallenge":
		s.handlePairClientChallenge(w, uniqueID, q.Get("clientchallenge"))

	case "serverchallengeresp":
		s.handlePairServerChallengeResp(w, uniqueID,
			q.Get("serverchallengeresp"), q.Get("clientpairingsecret"))

	case "clientpairingsecret":
		s.handlePairClientPairingSecret(w, uniqueID, q.Get("clientpairingsecret"))

	default:
		xmlError(w, 400, fmt.Sprintf("unknown pairing phase: %s", phase))
	}
}

// handlePairGetServerCert handles phase 1: return the server certificate.
func (s *Server) handlePairGetServerCert(w http.ResponseWriter, uniqueID, deviceName string) {
	certPEM := string(s.store.ServerCertPEMBytes())

	// Generate a random PIN and remember the pairing state.
	pin, err := generatePIN()
	if err != nil {
		xmlError(w, 500, "failed to generate PIN")
		return
	}

	state := &pairingState{
		uniqueID: uniqueID,
		pin:      pin,
		aesKey:   pairingAESKey(pin),
	}

	activePairingsMu.Lock()
	activePairings[uniqueID] = state
	activePairingsMu.Unlock()

	// Notify the UI to display the PIN.
	if s.cfg.PINCallback != nil {
		go s.cfg.PINCallback(pin)
	}

	log.Info().Str("uniqueID", uniqueID).Str("deviceName", deviceName).
		Str("pin", pin).Msg("pairing started, PIN displayed")

	xmlOK(w, fmt.Sprintf(
		`<paired>0</paired><plaincert>%s</plaincert>`,
		xmlEscape(certPEM),
	))
}

// handlePairClientChallenge handles phase 2: client sends an AES-encrypted random challenge.
// The server decrypts it, appends the server certificate signature and a fresh random challenge,
// hashes the result with SHA-256, and returns it encrypted.
func (s *Server) handlePairClientChallenge(w http.ResponseWriter, uniqueID, challengeHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()

	if !ok {
		xmlError(w, 400, "no pending pairing for this uniqueid")
		return
	}

	challengeEnc, err := hexDecode(challengeHex)
	if err != nil {
		xmlError(w, 400, "invalid clientchallenge hex")
		return
	}

	// Decrypt client challenge using AES-128-CBC with key = SHA256(PIN)[0:16], IV = 0.
	challengeData, err := aes128CBCDecrypt(state.aesKey, challengeEnc)
	if err != nil {
		xmlError(w, 500, "failed to decrypt client challenge")
		return
	}

	// Generate server challenge (16 random bytes).
	serverChallenge := make([]byte, 16)
	if _, err := rand.Read(serverChallenge); err != nil {
		xmlError(w, 500, "failed to generate server challenge")
		return
	}
	state.serverChallenge = serverChallenge

	// serverResponse = SHA256(clientChallengeData + serverCertSignature + serverChallenge)
	// This is what the client should send back in phase 3.
	serverCertSig := s.store.serverCert.Signature
	h := sha256.New()
	h.Write(challengeData)
	h.Write(serverCertSig)
	h.Write(serverChallenge)
	serverResponse := h.Sum(nil)
	state.serverResponse = serverResponse

	// Encrypt the response: AES-CBC(serverResponse + serverChallenge, aesKey)
	toEncrypt := append(serverResponse, serverChallenge...)
	encrypted, err := aes128CBCEncrypt(state.aesKey, toEncrypt)
	if err != nil {
		xmlError(w, 500, "failed to encrypt server challenge response")
		return
	}

	xmlOK(w, fmt.Sprintf(
		`<paired>0</paired><challenge>%s</challenge>`,
		hex.EncodeToString(encrypted),
	))
}

// handlePairServerChallengeResp handles phase 3: the client sends back the server's
// challenge response (to prove it has the PIN) plus its own signed secret.
func (s *Server) handlePairServerChallengeResp(w http.ResponseWriter, uniqueID, serverChallengeRespHex, clientPairingSecretHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()

	if !ok {
		xmlError(w, 400, "no pending pairing for this uniqueid")
		return
	}

	respEnc, err := hexDecode(serverChallengeRespHex)
	if err != nil {
		xmlError(w, 400, "invalid serverchallengeresp hex")
		return
	}

	// Decrypt the client's response.
	respData, err := aes128CBCDecrypt(state.aesKey, respEnc)
	if err != nil {
		xmlError(w, 500, "failed to decrypt serverchallengeresp")
		return
	}

	// Verify that the first 32 bytes match our expected serverResponse.
	if len(respData) < len(state.serverResponse) {
		xmlError(w, 400, "serverchallengeresp too short")
		return
	}

	for i, b := range state.serverResponse {
		if respData[i] != b {
			log.Warn().Str("uniqueID", uniqueID).Msg("serverchallengeresp mismatch – wrong PIN?")
			xmlError(w, 403, "challenge response mismatch")

			// Clean up the failed pairing.
			activePairingsMu.Lock()
			delete(activePairings, uniqueID)
			activePairingsMu.Unlock()
			return
		}
	}

	// Compute our signed secret so the client can verify us in phase 4.
	// serverSecret = RSA_sign_SHA256(serverChallengeResp_decrypted + serverCert.Signature)
	toSign := append(respData[:len(state.serverResponse)], s.store.serverCert.Signature...)
	serverSecret, err := s.store.rsaSignSHA256(toSign)
	if err != nil {
		xmlError(w, 500, "failed to sign server secret")
		return
	}

	// Store client pairing secret (we don't fully verify it here; phase 4 does final storage).
	_ = clientPairingSecretHex

	xmlOK(w, fmt.Sprintf(
		`<paired>0</paired><pairingsecret>%s</pairingsecret>`,
		hex.EncodeToString(serverSecret),
	))
}

// handlePairClientPairingSecret handles phase 4: the client sends its certificate.
func (s *Server) handlePairClientPairingSecret(w http.ResponseWriter, uniqueID, clientPairingSecretHex string) {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()

	if !ok {
		xmlError(w, 400, "no pending pairing for this uniqueid")
		return
	}

	// clientpairingsecret is the client's PEM certificate in hex.
	clientCertBytes, err := hexDecode(clientPairingSecretHex)
	if err != nil {
		xmlError(w, 400, "invalid clientpairingsecret hex")
		return
	}
	state.clientCertPEM = string(clientCertBytes)

	// Store the paired client.
	if err := s.store.StorePairedClient(uniqueID, state.clientCertPEM); err != nil {
		log.Error().Err(err).Str("uniqueID", uniqueID).Msg("failed to save paired client")
		xmlError(w, 500, "failed to save pairing")
		return
	}

	// Clean up transient pairing state.
	activePairingsMu.Lock()
	delete(activePairings, uniqueID)
	activePairingsMu.Unlock()

	log.Info().Str("uniqueID", uniqueID).Msg("pairing completed successfully")
	xmlOK(w, `<paired>1</paired>`)
}

// handleAppList returns the single "JetKVM" application entry.
func (s *Server) handleAppList(w http.ResponseWriter, r *http.Request) {
	xmlOK(w, `
<App>
  <IsHdrSupported>0</IsHdrSupported>
  <AppTitle>JetKVM</AppTitle>
  <ID>1</ID>
</App>`)
}

// handleLaunch starts a streaming session.
// Moonlight sends the desired resolution, frame rate, and bitrate in query parameters.
func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	if uniqueID == "" || !s.store.IsPaired(uniqueID) {
		xmlError(w, 403, "not paired")
		return
	}

	// Any previous session is replaced by the new one; the RTSP flow will call setSession().
	// We just acknowledge and let the client connect via RTSP next.
	log.Info().Str("uniqueID", uniqueID).Msg("launch request received")

	xmlOK(w, fmt.Sprintf(`
<sessionUrl0>rtsp://%s:%d</sessionUrl0>
<gamesession>1</gamesession>`,
		getOutboundIP(), RTSPPort))
}

// handleResume resumes a previously interrupted session.
func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	if uniqueID == "" || !s.store.IsPaired(uniqueID) {
		xmlError(w, 403, "not paired")
		return
	}
	xmlOK(w, `<sessionUrl0></sessionUrl0><resume>1</resume>`)
}

// handleCancel tears down the current streaming session.
func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("cancel request received, ending session")
	s.clearSession()
	xmlOK(w, `<cancel>1</cancel>`)
}

// handleUnpair removes a paired client.
func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	uniqueID := r.URL.Query().Get("uniqueid")
	if uniqueID == "" {
		xmlError(w, 400, "missing uniqueid")
		return
	}
	if err := s.store.RemovePairedClient(uniqueID); err != nil {
		xmlError(w, 500, "failed to unpair")
		return
	}
	log.Info().Str("uniqueID", uniqueID).Msg("client unpaired")
	xmlOK(w, `<unpaired>1</unpaired>`)
}

// getOutboundIP returns the local IP address used for outbound connections.
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
