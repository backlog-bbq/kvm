package moonlight

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
)

const (
	// videoPayloadType is the RTP payload type for H.264 (dynamic, 96-127 range).
	videoPayloadType = 96
	// videoClockRate is the standard RTP clock rate for video (90kHz).
	videoClockRate = 90000
	// videoMTU is the maximum RTP packet size; kept below the typical 1500-byte
	// Ethernet MTU to leave headroom for IP (20) + UDP (8) + RTP (12) headers.
	videoMTU = 1400
	// videoSSRC is the fixed SSRC for the video stream.
	videoSSRC = 0x53535243
)

// runVideoStream reads H.264 frames from videoFrameCh and sends them as RTP
// packets to the active Moonlight session's video endpoint (UDP port 47998).
func (s *Server) runVideoStream() {
	log.Info().Int("port", VideoPort).Msg("video RTP sender ready")

	var (
		conn       *net.UDPConn
		packetizer rtp.Packetizer
		lastDest   string
	)

	for {
		select {
		case <-s.ctx.Done():
			if conn != nil {
				conn.Close()
			}
			return
		case vf := <-s.videoFrameCh:
			sess := s.getSession()
			if sess == nil {
				continue
			}

			dest := fmt.Sprintf("%s:%d", sess.ClientIP.String(), sess.VideoPort)

			// (Re)open the UDP socket when the destination changes.
			if dest != lastDest || conn == nil {
				if conn != nil {
					conn.Close()
				}
				var err error
				conn, err = openVideoUDP(dest)
				if err != nil {
					log.Warn().Err(err).Str("dest", dest).Msg("failed to open video UDP socket")
					conn = nil
					continue
				}
				lastDest = dest

				packetizer = rtp.NewPacketizer(
					videoMTU,
					videoPayloadType,
					videoSSRC,
					&codecs.H264Payloader{},
					rtp.NewRandomSequencer(),
					videoClockRate,
				)
				log.Info().Str("dest", dest).Msg("video RTP stream connected")
			}

			if err := sendVideoFrame(conn, packetizer, vf); err != nil {
				log.Warn().Err(err).Msg("video RTP send error")
			}
		}
	}
}

// openVideoUDP creates a connected UDP socket to the Moonlight client's video port.
func openVideoUDP(dest string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", dest)
	if err != nil {
		return nil, fmt.Errorf("moonlight: resolve video UDP %q: %w", dest, err)
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("moonlight: dial video UDP %q: %w", dest, err)
	}
	return conn, nil
}

// sendVideoFrame packetizes a raw H.264 frame and sends the resulting RTP packets.
func sendVideoFrame(conn *net.UDPConn, p rtp.Packetizer, vf videoFrame) error {
	// Convert duration to RTP timestamp units (90kHz).
	samples := uint32(vf.duration.Seconds() * videoClockRate)
	if samples == 0 {
		samples = videoClockRate / 60 // default: 60fps interval
	}

	packets := p.Packetize(vf.data, samples)
	for _, pkt := range packets {
		raw, err := pkt.Marshal()
		if err != nil {
			return fmt.Errorf("moonlight: marshal RTP: %w", err)
		}
		if _, err := conn.Write(raw); err != nil {
			return fmt.Errorf("moonlight: write RTP: %w", err)
		}
	}
	return nil
}

// moonlightRTPHeader adds the Moonlight-specific 4-byte extension header that
// carries the frame type and sequence information expected by some client versions.
// This is inserted between the standard RTP header and the H.264 payload.
//
// NOTE: Standard Moonlight clients (6.x) accept plain RFC 6184 RTP without this
// extension. Enable only if a specific client version requires it.
func moonlightRTPHeader(frameIndex uint32, frameType uint8) []byte {
	hdr := make([]byte, 4)
	hdr[0] = frameType // 1 = IDR (keyframe), 0 = P-frame
	binary.LittleEndian.PutUint16(hdr[1:], uint16(frameIndex))
	hdr[3] = 0 // reserved
	return hdr
}

// isIDRFrame returns true if the first byte of the H.264 NALU data indicates
// an IDR (instantaneous decoder refresh / keyframe) slice.
func isIDRFrame(frame []byte) bool {
	// Walk over NALU start codes (0x00 0x00 0x01 or 0x00 0x00 0x00 0x01) to find
	// the first NALU and check its type field.
	for i := 0; i+4 < len(frame); i++ {
		if frame[i] == 0 && frame[i+1] == 0 {
			start := -1
			if frame[i+2] == 1 {
				start = i + 3
			} else if frame[i+2] == 0 && frame[i+3] == 1 {
				start = i + 4
			}
			if start >= 0 && start < len(frame) {
				naluType := frame[start] & 0x1F
				return naluType == 5 // IDR slice
			}
		}
	}
	return false
}

// keepVideoAlive sends a keep-alive RTP packet when no frames are available.
// Some Moonlight clients will disconnect if they receive no video for >1s.
func keepVideoAlive(conn *net.UDPConn) {
	// Send an empty RTP packet with no payload. Most clients ignore it gracefully.
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    videoPayloadType,
			SSRC:           videoSSRC,
			Timestamp:      uint32(time.Now().UnixNano() / 1000 * 90 / 1000),
		},
	}
	if raw, err := pkt.Marshal(); err == nil {
		_, _ = conn.Write(raw)
	}
}
