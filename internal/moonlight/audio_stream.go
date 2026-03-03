package moonlight

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

const (
	// audioPayloadType is the RTP payload type for Opus (dynamic).
	audioPayloadType = 97
	// audioClockRate is the RTP clock rate for Opus (48kHz).
	audioClockRate = 48000
	// audioFrameInterval is the duration of each Opus frame (20ms).
	audioFrameInterval = 20 * time.Millisecond
	// audioSamplesPerFrame = 48000 Hz × 0.020 s = 960 samples/frame.
	audioSamplesPerFrame = 960
	// audioSSRC is the fixed SSRC for the audio stream.
	audioSSRC = 0x41555449
)

// opusSilenceFrame is a minimal pre-encoded 2-channel 48kHz 20ms Opus silence packet.
// This is a CELT-mode stereo comfort noise frame (3 bytes) that all Opus decoders
// interpret as silence. It avoids the need for a full Opus encoder dependency.
//
// TOC byte 0xF8: config=62 (CELT, 48kHz, stereo), count=1 frame
// 0xFF 0xFE = minimal CELT frame body for silence
var opusSilenceFrame = []byte{0xF8, 0xFF, 0xFE}

// runAudioStream sends silent Opus frames to the active Moonlight session's
// audio endpoint at 50 frames per second (one frame every 20ms).
//
// JetKVM currently has no HDMI audio capture capability. The silent stream
// satisfies Moonlight's expectation of an audio track. When audio capture is
// added in the future, replace opusSilenceFrame with real encoded frames here.
func (s *Server) runAudioStream() {
	log.Info().Int("port", AudioPort).Msg("audio RTP sender ready")

	ticker := time.NewTicker(audioFrameInterval)
	defer ticker.Stop()

	var (
		conn     *net.UDPConn
		seq      uint16
		rtpTS    uint32
		lastDest string
	)
	// Start timestamp at a random value per RFC 3550.
	rtpTS = rand.Uint32() //nolint:gosec // non-cryptographic RTP timestamp

	for {
		select {
		case <-s.ctx.Done():
			if conn != nil {
				conn.Close()
			}
			return

		case <-ticker.C:
			sess := s.getSession()
			if sess == nil {
				continue
			}

			dest := fmt.Sprintf("%s:%d", sess.ClientIP.String(), sess.AudioPort)

			if dest != lastDest || conn == nil {
				if conn != nil {
					conn.Close()
				}
				var err error
				conn, err = openAudioUDP(dest)
				if err != nil {
					log.Warn().Err(err).Str("dest", dest).Msg("failed to open audio UDP socket")
					conn = nil
					continue
				}
				lastDest = dest
				log.Info().Str("dest", dest).Msg("audio RTP stream connected")
			}

			payload, err := encryptAudioPayload(opusSilenceFrame, sess.RIKey, sess.RIKeyID, seq)
			if err != nil {
				log.Warn().Err(err).Msg("audio encryption error")
				seq++
				rtpTS += audioSamplesPerFrame
				continue
			}

			pkt := buildAudioRTPPacket(seq, rtpTS, payload)
			if _, err := conn.Write(pkt); err != nil {
				log.Warn().Err(err).Msg("audio RTP write error")
			}

			seq++
			rtpTS += audioSamplesPerFrame
		}
	}
}

// openAudioUDP creates a connected UDP socket to the Moonlight client's audio port.
func openAudioUDP(dest string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", dest)
	if err != nil {
		return nil, fmt.Errorf("moonlight: resolve audio UDP %q: %w", dest, err)
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("moonlight: dial audio UDP %q: %w", dest, err)
	}
	return conn, nil
}

// encryptAudioPayload encrypts an Opus frame with AES-128-CBC.
//
// The Moonlight audio encryption scheme (per moonlight-common-c/src/AudioStream.c):
//   - Key: rikey (16 bytes, from RTSP)
//   - IV: BigEndian(rikeyID + sequenceNumber) in first 4 bytes, remaining 12 bytes zero
//   - Mode: CBC, zero-padded plaintext to block boundary
func encryptAudioPayload(frame, rikey []byte, rikeyID uint32, seq uint16) ([]byte, error) {
	if len(rikey) != 16 {
		// No key set (pre-pairing); send unencrypted.
		return frame, nil
	}

	block, err := aes.NewCipher(rikey)
	if err != nil {
		return nil, err
	}

	// Pad frame to AES block size.
	padLen := aes.BlockSize - (len(frame) % aes.BlockSize)
	if padLen == aes.BlockSize {
		padLen = 0
	}
	plaintext := make([]byte, len(frame)+padLen)
	copy(plaintext, frame)

	// IV = BigEndian(rikeyID + uint32(seq)) + 12 zero bytes.
	iv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(iv[0:4], rikeyID+uint32(seq))

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// buildAudioRTPPacket assembles a minimal RTP packet for the Opus payload.
// The RTP header layout (12 bytes) per RFC 3550:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|V=2|P|X|  CC   |M|     PT      |       sequence number         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           timestamp                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           synchronization source (SSRC) identifier           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func buildAudioRTPPacket(seq uint16, ts uint32, payload []byte) []byte {
	pkt := make([]byte, 12+len(payload))
	pkt[0] = 0x80                        // V=2, P=0, X=0, CC=0
	pkt[1] = audioPayloadType & 0x7F     // M=0, PT=97
	binary.BigEndian.PutUint16(pkt[2:4], seq)
	binary.BigEndian.PutUint32(pkt[4:8], ts)
	binary.BigEndian.PutUint32(pkt[8:12], audioSSRC)
	copy(pkt[12:], payload)
	return pkt
}
