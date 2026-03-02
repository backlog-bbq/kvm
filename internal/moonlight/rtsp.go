package moonlight

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// runRTSPServer listens on TCP port 48010 and handles Moonlight RTSP signaling.
// RTSP is used to negotiate stream parameters (resolution, bitrate, codec) and
// exchange the AES session key (rikey/rikeyid) used by the control channel.
func (s *Server) runRTSPServer() {
	addr := fmt.Sprintf(":%d", RTSPPort)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("failed to listen for RTSP")
		return
	}
	defer ln.Close()

	log.Info().Str("addr", addr).Msg("RTSP server listening")

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("RTSP accept error")
			continue
		}
		go s.handleRTSPConn(conn)
	}
}

// rtspRequest holds a parsed RTSP request.
type rtspRequest struct {
	method  string
	uri     string
	version string
	headers map[string]string
	body    string
}

// handleRTSPConn processes all RTSP requests on a single TCP connection.
func (s *Server) handleRTSPConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().(*net.TCPAddr)
	clientIP := remote.IP

	log.Info().Str("remote", remote.String()).Msg("RTSP connection established")

	// Each RTSP connection may carry multiple requests (pipelining).
	scanner := bufio.NewReader(conn)
	for {
		req, err := readRTSPRequest(scanner)
		if err != nil {
			if err.Error() != "EOF" {
				log.Warn().Err(err).Msg("RTSP read error")
			}
			return
		}

		resp := s.dispatchRTSP(req, clientIP)
		if _, err := conn.Write([]byte(resp)); err != nil {
			log.Warn().Err(err).Msg("RTSP write error")
			return
		}
	}
}

// dispatchRTSP routes an RTSP request to the appropriate handler and returns
// the complete response string (including CRLF line endings per RFC 2326).
func (s *Server) dispatchRTSP(req *rtspRequest, clientIP net.IP) string {
	cseq := req.headers["CSeq"]
	log.Info().
		Str("method", req.method).
		Str("uri", req.uri).
		Int("bodyLen", len(req.body)).
		Msg("RTSP request")

	switch req.method {
	case "OPTIONS":
		return rtspResponse(200, "OK", cseq, map[string]string{
			"Public": "OPTIONS, DESCRIBE, SETUP, ANNOUNCE, PLAY, PAUSE, TEARDOWN",
		}, "")

	case "DESCRIBE":
		return s.handleRTSPDescribe(cseq, clientIP)

	case "SETUP":
		return s.handleRTSPSetup(req, cseq)

	case "ANNOUNCE":
		return s.handleRTSPAnnounce(req, cseq, clientIP)

	case "PLAY":
		return s.handleRTSPPlay(req, cseq, clientIP)

	case "TEARDOWN":
		s.clearSession()
		return rtspResponse(200, "OK", cseq, nil, "")

	default:
		log.Warn().Str("method", req.method).Msg("RTSP: unknown method")
		return rtspResponse(501, "Not Implemented", cseq, nil, "")
	}
}

// handleRTSPDescribe returns the SDP describing available video and audio tracks.
func (s *Server) handleRTSPDescribe(cseq string, clientIP net.IP) string {
	localIP := getOutboundIP()

	sdp := fmt.Sprintf("v=0\r\n"+
		"o=- 0 0 IN IP4 %s\r\n"+
		"s=JetKVM\r\n"+
		"t=0 0\r\n"+
		"a=x-ss-general.featureFlags:0\r\n"+
		// Video track: H.264 at 90kHz clock
		"m=video %d RTP/AVP 96\r\n"+
		"a=rtpmap:96 H264/90000\r\n"+
		"a=fmtp:96 packetization-mode=1\r\n"+
		"a=control:streamid=video\r\n"+
		// Audio track: Opus stereo at 48kHz
		"m=audio %d RTP/AVP 97\r\n"+
		"a=rtpmap:97 opus/48000/2\r\n"+
		"a=fmtp:97 surround-params=5210200\r\n"+
		"a=control:streamid=audio\r\n",
		localIP,
		VideoPort,
		AudioPort,
	)

	headers := map[string]string{
		"Content-Type": "application/sdp",
	}
	return rtspResponse(200, "OK", cseq, headers, sdp)
}

// handleRTSPSetup handles stream SETUP requests (audio, video, control).
// Returns the server port for the requested stream type and a session ID.
func (s *Server) handleRTSPSetup(req *rtspRequest, cseq string) string {
	// Determine stream type from the URI (e.g., "streamid=audio" or "streamid=video").
	uri := req.uri
	var port int
	switch {
	case strings.Contains(uri, "streamid=audio") || strings.Contains(uri, "streamid=1"):
		port = AudioPort
	case strings.Contains(uri, "streamid=video") || strings.Contains(uri, "streamid=0"):
		port = VideoPort
	case strings.Contains(uri, "streamid=control") || strings.Contains(uri, "streamid=2"):
		port = ControlPort
	default:
		port = VideoPort
	}

	log.Info().
		Str("uri", uri).
		Int("server_port", port).
		Msg("RTSP SETUP")

	return rtspResponse(200, "OK", cseq, map[string]string{
		"Session":   "DEADBEEFCAFE;timeout = 90",
		"Transport": fmt.Sprintf("server_port=%d", port),
	}, "")
}

// handleRTSPAnnounce processes the client's ANNOUNCE request which contains
// the SDP describing the client's desired stream configuration.
// We parse key parameters and return 200 OK.
func (s *Server) handleRTSPAnnounce(req *rtspRequest, cseq string, clientIP net.IP) string {
	log.Info().
		Str("remote", clientIP.String()).
		Int("bodyLen", len(req.body)).
		Msg("RTSP ANNOUNCE")

	if req.body != "" {
		log.Debug().Str("sdp", req.body).Msg("RTSP ANNOUNCE SDP")
	}

	return rtspResponse(200, "OK", cseq, nil, "")
}

// handleRTSPPlay signals the start of the streaming session.
// Session keys (rikey, rikeyid) were already extracted from the /launch HTTP request.
func (s *Server) handleRTSPPlay(req *rtspRequest, cseq string, clientIP net.IP) string {
	s.mu.Lock()
	rikey := s.pendingRIKey
	rikeyID := s.pendingRIKeyID
	gcmIV := s.pendingGCMIV
	s.mu.Unlock()

	if len(rikey) == 0 {
		log.Warn().Msg("RTSP PLAY: no rikey available (was /launch called?)")
		return rtspResponse(400, "Bad Request", cseq, nil, "")
	}

	ctx, cancel := context.WithCancel(s.ctx)
	sess := &Session{
		ClientIP:    clientIP,
		VideoPort:   uint16(VideoPort),
		AudioPort:   uint16(AudioPort),
		ControlPort: uint16(ControlPort),
		RIKey:       rikey,
		RIKeyID:     rikeyID,
		GCMIV:       gcmIV,
		ctx:         ctx,
		cancel:      cancel,
	}
	s.setSession(sess)

	log.Info().
		Str("clientIP", clientIP.String()).
		Uint32("rikeyID", rikeyID).
		Msg("RTSP PLAY: session started")

	return rtspResponse(200, "OK", cseq, map[string]string{
		"Session": "DEADBEEFCAFE;timeout = 90",
	}, "")
}

// rtspResponse formats a complete RTSP response with the given status, CSeq, optional
// headers, and optional body. All lines are terminated with CRLF per RFC 2326.
func rtspResponse(code int, reason, cseq string, extraHeaders map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("RTSP/1.0 %d %s\r\n", code, reason))
	if cseq != "" {
		sb.WriteString(fmt.Sprintf("CSeq: %s\r\n", cseq))
	}
	for k, v := range extraHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// readRTSPRequest reads a single RTSP request from a buffered reader.
// RTSP requests have the form:
//
//	METHOD URI RTSP/1.0\r\n
//	Header: Value\r\n
//	...
//	\r\n
//	[body if Content-Length is present]
func readRTSPRequest(r *bufio.Reader) (*rtspRequest, error) {
	// Read the request line.
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed RTSP request line: %q", line)
	}

	req := &rtspRequest{
		method:  parts[0],
		uri:     parts[1],
		version: parts[2],
		headers: make(map[string]string),
	}

	// Read headers until blank line.
	for {
		line, err = readLine(r)
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		req.headers[key] = val
	}

	// Read body if Content-Length is present.
	if cl, ok := req.headers["Content-Length"]; ok {
		n, err := strconv.Atoi(cl)
		if err == nil && n > 0 {
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
			req.body = string(buf)
		}
	}

	return req, nil
}

// readLine reads a CRLF-terminated line from r, returning the line without the terminator.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
