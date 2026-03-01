// Package moonlight implements a Moonlight-compatible streaming server for JetKVM.
//
// Moonlight connects to servers that speak the NVIDIA GameStream / Sunshine protocol,
// a multi-port suite built on HTTP, RTSP, RTP, and ENet. This package provides a
// clean-room Go implementation of that protocol, using Wolf project's MIT-licensed
// documentation as the specification.
//
// Protocol port assignments:
//   - 47989: NVHTTP discovery (unauthenticated HTTP)
//   - 47984: NVHTTP pairing (HTTPS)
//   - 48010: RTSP signaling (TCP)
//   - 47998: RTP video (UDP)
//   - 47999: ENet control (UDP)
//   - 48000: RTP audio (UDP)
package moonlight

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jetkvm/kvm/internal/logging"
)

// Protocol port constants.
const (
	NVHTTPPort  = 47989
	NVHTTPSPort = 47984
	RTSPPort    = 48010
	VideoPort   = 47998
	ControlPort = 47999
	AudioPort   = 48000
)

var log = logging.GetSubsystemLogger("moonlight")

// HIDCallbacks holds the HID input callback functions that the moonlight server
// calls when it receives input events from a Moonlight client.
type HIDCallbacks struct {
	RelMouseMove func(dx, dy int8, buttons uint8) error
	AbsMouseMove func(x, y int, buttons uint8) error
	Keyboard     func(key byte, press bool) error
	KeyboardFull func(modifier byte, keys []byte) error
	Scroll       func(dy int8) error
}

// ServerConfig holds configuration for the Moonlight server.
type ServerConfig struct {
	DeviceID string
	Hostname string
	MacAddr  string
	HID      HIDCallbacks
	// PINCallback is called when a Moonlight client initiates pairing and the
	// JetKVM UI must prompt the user to enter the PIN shown on the Moonlight
	// client. The callback receives the connecting device name and its unique ID
	// (which must be passed back to SubmitPIN).
	PINCallback func(deviceName, uniqueID string)
}

// videoFrame holds a single H.264 video frame for delivery to the RTP sender.
type videoFrame struct {
	data     []byte
	duration time.Duration
}

// Server manages all Moonlight protocol servers and session state.
type Server struct {
	cfg    ServerConfig
	store  *PairingStore
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	// activeSession is set when a Moonlight client has launched a stream.
	activeSession *Session

	// videoFrameCh buffers incoming H.264 frames from the capture pipeline.
	videoFrameCh chan videoFrame
}

// Session represents an active Moonlight streaming session.
type Session struct {
	ClientIP    net.IP
	VideoPort   uint16
	AudioPort   uint16
	ControlPort uint16

	// RIKey is the 16-byte AES key negotiated during RTSP for control/audio encryption.
	RIKey []byte
	// RIKeyID is the key-ID counter used to construct GCM/CBC IVs.
	RIKeyID uint32
	// GCMIV is the 12-byte base IV for AES-GCM (control channel).
	GCMIV []byte

	// mouseButtons tracks the current state of mouse buttons (bitmask).
	mouseButtons uint8
	// seqNum is the control-stream sequence number (server side).
	seqNum uint32

	cancel context.CancelFunc
	ctx    context.Context
}

// NewServer creates a Moonlight server with the given configuration.
func NewServer(cfg ServerConfig) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	store, err := LoadPairingStore()
	if err != nil {
		log.Warn().Err(err).Msg("failed to load pairing store, starting fresh")
		store = NewPairingStore()
	}

	s := &Server{
		cfg:          cfg,
		store:        store,
		ctx:          ctx,
		cancel:       cancel,
		videoFrameCh: make(chan videoFrame, 120), // ~2s buffer at 60fps
	}
	return s, nil
}

// Start starts all Moonlight protocol listeners.
func (s *Server) Start() error {
	if err := s.store.EnsureServerKeys(); err != nil {
		return fmt.Errorf("moonlight: failed to ensure server keys: %w", err)
	}

	go s.runNVHTTPServer()
	go s.runNVHTTPSServer()
	go s.runRTSPServer()
	go s.runVideoStream()
	go s.runAudioStream()
	go s.runControlStream()

	log.Info().
		Str("deviceID", s.cfg.DeviceID).
		Str("hostname", s.cfg.Hostname).
		Msg("Moonlight server started")
	return nil
}

// Stop shuts down the server and terminates any active session.
func (s *Server) Stop() {
	s.cancel()
}

// WriteVideoFrame is called by the video capture pipeline with each H.264 frame.
// It implements the VideoFrameSink interface expected by native.go.
func (s *Server) WriteVideoFrame(frame []byte, duration time.Duration) {
	s.mu.RLock()
	sess := s.activeSession
	s.mu.RUnlock()
	if sess == nil {
		return
	}

	// Copy frame to avoid data race with the capture pipeline.
	frameCopy := make([]byte, len(frame))
	copy(frameCopy, frame)

	select {
	case s.videoFrameCh <- videoFrame{data: frameCopy, duration: duration}:
	default:
		// Drop frame when the buffer is full (client is too slow).
	}
}

// setSession installs a new active session (called by the RTSP PLAY handler).
func (s *Server) setSession(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeSession != nil {
		s.activeSession.cancel()
	}
	s.activeSession = sess
}

// clearSession removes the active session (called on disconnect or cancel).
func (s *Server) clearSession() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeSession != nil {
		s.activeSession.cancel()
		s.activeSession = nil
	}
}

// GetPairedClientIDs returns the uniqueIDs of all paired Moonlight clients.
func (s *Server) GetPairedClientIDs() []string {
	return s.store.GetPairedClientIDs()
}

// UnpairClient removes a paired client by its uniqueID.
func (s *Server) UnpairClient(uniqueID string) error {
	return s.store.RemovePairedClient(uniqueID)
}

// SubmitPIN delivers a PIN entered by the user to the pending pairing
// handshake identified by uniqueID. It returns an error if there is no
// pending pairing for that uniqueID or if the channel has already been fed.
func (s *Server) SubmitPIN(uniqueID, pin string) error {
	activePairingsMu.Lock()
	state, ok := activePairings[uniqueID]
	activePairingsMu.Unlock()
	if !ok {
		return fmt.Errorf("no pending Moonlight pairing for uniqueID %q", uniqueID)
	}
	select {
	case state.pinCh <- pin:
		log.Info().Str("uniqueID", uniqueID).Msg("PIN submitted to pairing state")
		return nil
	default:
		return fmt.Errorf("pairing for uniqueID %q is not waiting for a PIN", uniqueID)
	}
}

// getSession returns the current active session (nil if none).
func (s *Server) getSession() *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeSession
}
