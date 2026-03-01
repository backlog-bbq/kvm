// Package moonlight – control_stream.go
//
// The Moonlight control channel runs over UDP port 47999 using the ENet reliable
// UDP transport library protocol. Incoming payloads are AES-GCM-128 encrypted.
// After decryption the payloads are parsed as Moonlight input messages, which are
// then dispatched to the USB HID stack via the HIDCallbacks registered with Server.
//
// ENet protocol overview (all multi-byte fields are big-endian):
//
//	Protocol Header (4 bytes):
//	  uint16  peerID       – sender's peer ID; bit15 = SENT_TIME flag
//	  uint16  sentTime     – low 16 bits of send timestamp (ms), present when bit15 set
//
//	Command Header (4 bytes):
//	  uint8   command      – upper nibble: flags; lower nibble: command type
//	  uint8   channelID
//	  uint16  reliableSequenceNumber
//
// Commands used here:
//   0x01 CONNECT          – client requests connection
//   0x02 VERIFY_CONNECT   – server confirms connection
//   0x06 SEND_RELIABLE    – carries encrypted Moonlight input messages
//   0x07 ACKNOWLEDGE      – acknowledges a SEND_RELIABLE
//   0x05 PING             – keep-alive
//
// Moonlight control message types (16-bit little-endian header in decrypted payload):
//   0x0206  MOUSE_MOVE_REL   – relative mouse move (dx, dy as int32)
//   0x0507  MOUSE_BUTTON     – mouse button press/release
//   0x0510  MOUSE_MOVE_ABS   – absolute mouse move (x, y as uint16)
//   0x0307  KEYBOARD         – keyboard key down/up
//   0x0509  SCROLL           – vertical scroll
package moonlight

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

// ENet command identifiers (lower nibble of the command byte).
const (
	enetCmdConnect       = 0x01
	enetCmdVerifyConnect = 0x02
	enetCmdDisconnect    = 0x03
	enetCmdPing          = 0x05
	enetCmdSendReliable  = 0x06
	enetCmdAcknowledge   = 0x07
)

// ENet header flag: when set in peerID, the sentTime field is present.
const enetFlagSentTime = 0x8000

// ENet command flag: receiver must ACK this command.
const enetFlagAcknowledge = 0x80

// Moonlight control message type identifiers (little-endian uint16).
const (
	msgMouseMoveRel = 0x0206
	msgMouseButton  = 0x0507
	msgMouseMoveAbs = 0x0510
	msgKeyboard     = 0x0307
	msgScroll       = 0x0509
	msgScrollV2     = 0x0115
)

// Mouse button bit-flags used by Moonlight (maps to USB HID button order).
const (
	mlButtonLeft   = 0x01
	mlButtonRight  = 0x02
	mlButtonMiddle = 0x04
)

// runControlStream listens on UDP port 47999 for ENet control messages from
// the active Moonlight client.
func (s *Server) runControlStream() {
	addr := fmt.Sprintf(":%d", ControlPort)
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("failed to listen on control port")
		return
	}
	defer pc.Close()

	log.Info().Str("addr", addr).Msg("ENet control receiver listening")

	// enetState tracks per-peer connection state.
	type enetPeer struct {
		addr       *net.UDPAddr
		peerID     uint16 // the client's outgoing peer ID (we put this in our headers)
		myPeerID   uint16 // our peer ID (random, sent in VERIFY_CONNECT)
		connected  bool
		outSeqNum  uint16
		inSeqNum   uint16
	}

	var peer *enetPeer
	buf := make([]byte, 4096)

	for {
		if s.ctx.Err() != nil {
			return
		}

		pc.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("control stream read error")
			continue
		}

		udpAddr := remoteAddr.(*net.UDPAddr)
		data := buf[:n]

		if len(data) < 4 {
			continue
		}

		// Parse ENet protocol header.
		peerIDField := binary.BigEndian.Uint16(data[0:2])
		hasSentTime := peerIDField&enetFlagSentTime != 0
		senderPeerID := peerIDField &^ enetFlagSentTime

		offset := 2
		var sentTime uint16
		if hasSentTime {
			if len(data) < 4 {
				continue
			}
			sentTime = binary.BigEndian.Uint16(data[2:4])
			offset = 4
		}

		// Process all commands in the datagram.
		for offset+4 <= n {
			cmd := data[offset] & 0x0F
			cmdFlags := data[offset] & 0xF0
			channelID := data[offset+1]
			relSeqNum := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4

			_ = channelID
			_ = cmdFlags

			switch cmd {
			case enetCmdConnect:
				// CONNECT payload layout (44 bytes):
				//   +0  outgoingPeerID (2)
				//   +2  incomingSessionID (1)
				//   +3  outgoingSessionID (1)
				//   +4  mtu (4)
				//   +8  windowSize (4)
				//   +12 channelCount (4)
				//   +16 incomingBandwidth (4)
				//   +20 outgoingBandwidth (4)
				//   +24 packetThrottleInterval (4)
				//   +28 packetThrottleAcceleration (4)
				//   +32 packetThrottleDeceleration (4)
				//   +36 connectID (4)
				//   +40 data (4)
				if offset+44 > n {
					continue
				}
				outgoingPeerID := binary.BigEndian.Uint16(data[offset : offset+2])
				connectID := binary.BigEndian.Uint32(data[offset+36 : offset+40])
				offset += 44

				// Initialise peer state.
				peer = &enetPeer{
					addr:      udpAddr,
					peerID:    outgoingPeerID,
					myPeerID:  0x0001,
					connected: false,
				}

				// Send ACK for the CONNECT.
				ack := buildENetAck(peer.peerID, peer.myPeerID, relSeqNum, sentTime)
				_, _ = pc.WriteTo(ack, udpAddr)

				// Send VERIFY_CONNECT.
				vc := buildENetVerifyConnect(outgoingPeerID, connectID)
				_, _ = pc.WriteTo(vc, udpAddr)
				peer.connected = true
				peer.outSeqNum++

				log.Info().
					Str("remote", udpAddr.String()).
					Uint16("peerID", outgoingPeerID).
					Msg("ENet CONNECT received, sent VERIFY_CONNECT")

			case enetCmdSendReliable:
				if offset+2 > n {
					continue
				}
				dataLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+dataLen > n {
					continue
				}
				payload := data[offset : offset+dataLen]
				offset += dataLen

				if peer == nil {
					continue
				}

				// Send ACK.
				ack := buildENetAck(peer.peerID, peer.myPeerID, relSeqNum, sentTime)
				_, _ = pc.WriteTo(ack, udpAddr)

				// Decrypt and dispatch the Moonlight control message.
				sess := s.getSession()
				if sess == nil {
					continue
				}
				plain, err := decryptControlPayload(payload, sess)
				if err != nil {
					log.Warn().Err(err).Msg("control payload decryption failed")
					continue
				}
				s.dispatchControlMessage(plain, sess)
				sess.seqNum++

			case enetCmdAcknowledge:
				// 4-byte ACK payload: receivedSeqNum (2) + receivedSentTime (2).
				offset += 4

			case enetCmdPing:
				// Reply with ACK; no payload.
				if peer != nil {
					ack := buildENetAck(peer.peerID, peer.myPeerID, relSeqNum, sentTime)
					_, _ = pc.WriteTo(ack, udpAddr)
				}

			case enetCmdDisconnect:
				log.Info().Str("remote", udpAddr.String()).Msg("ENet DISCONNECT received")
				peer = nil
				s.clearSession()
				offset = n // stop processing further commands

			default:
				log.Debug().Uint8("cmd", cmd).Msg("unknown ENet command, skipping")
				// We cannot know the payload size of unknown commands; stop parsing.
				offset = n
			}
		}
		_ = senderPeerID
	}
}

// decryptControlPayload decrypts an AES-GCM-128 encrypted Moonlight control payload.
//
// Wire format (from moonlight-common-c/src/Control.c):
//
//	[4 bytes: sequence number, big-endian]
//	[ciphertext]
//	[16 bytes: GCM authentication tag, appended at end]
//
// Nonce: rikeyID (4 bytes, big-endian) padded to 12 bytes
func decryptControlPayload(data []byte, sess *Session) ([]byte, error) {
	if len(sess.RIKey) != 16 {
		// No key; pass through for debugging (should not happen in production).
		return data, nil
	}

	if len(data) < 4+16 {
		return nil, fmt.Errorf("moonlight: control payload too short (%d bytes)", len(data))
	}

	// Extract sequence number (used to construct the nonce).
	seqNum := binary.BigEndian.Uint32(data[0:4])
	ciphertextAndTag := data[4:]

	// Split ciphertext and 16-byte GCM tag.
	if len(ciphertextAndTag) < 16 {
		return nil, fmt.Errorf("moonlight: control payload too short for GCM tag")
	}
	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-16]
	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]

	// Nonce: rikeyID (4 bytes BE) + seqNum (4 bytes BE) + 4 zero bytes.
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[0:4], sess.RIKeyID)
	binary.BigEndian.PutUint32(nonce[4:8], seqNum)

	block, err := aes.NewCipher(sess.RIKey)
	if err != nil {
		return nil, fmt.Errorf("moonlight: AES init: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, fmt.Errorf("moonlight: GCM init: %w", err)
	}

	// Reassemble ciphertext+tag for cipher.Open().
	combined := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, combined, nil)
	if err != nil {
		return nil, fmt.Errorf("moonlight: GCM decrypt: %w", err)
	}
	return plaintext, nil
}

// dispatchControlMessage parses a decrypted Moonlight input message and routes
// it to the appropriate HID callback.
func (s *Server) dispatchControlMessage(data []byte, sess *Session) {
	if len(data) < 2 {
		return
	}
	msgType := binary.LittleEndian.Uint16(data[0:2])

	switch msgType {
	case msgMouseMoveRel:
		// [2 type][2 zero][4 dx int32 BE][4 dy int32 BE]
		if len(data) < 12 {
			return
		}
		dx32 := int32(binary.BigEndian.Uint32(data[4:8]))
		dy32 := int32(binary.BigEndian.Uint32(data[8:12]))
		dx := clampInt8(dx32)
		dy := clampInt8(dy32)
		if s.cfg.HID.RelMouseMove != nil {
			if err := s.cfg.HID.RelMouseMove(dx, dy, sess.mouseButtons); err != nil {
				log.Warn().Err(err).Msg("RelMouseMove error")
			}
		}

	case msgMouseMoveAbs:
		// [2 type][2 zero][2 x uint16][2 y uint16][2 width][2 height]
		if len(data) < 12 {
			return
		}
		x := int(binary.BigEndian.Uint16(data[4:6]))
		y := int(binary.BigEndian.Uint16(data[6:8]))
		// Moonlight coordinates are 0–65535; map to 0–32767 for HID.
		x = x >> 1
		y = y >> 1
		if s.cfg.HID.AbsMouseMove != nil {
			if err := s.cfg.HID.AbsMouseMove(x, y, sess.mouseButtons); err != nil {
				log.Warn().Err(err).Msg("AbsMouseMove error")
			}
		}

	case msgMouseButton:
		// [2 type][2 zero][1 buttonFlags][1 action]
		// action: 0x07 = press, 0x08 = release
		if len(data) < 6 {
			return
		}
		btnFlags := data[4]
		action := data[5]

		hidBtn := mlToHIDButtons(btnFlags)
		if action == 0x07 {
			sess.mouseButtons |= hidBtn
		} else {
			sess.mouseButtons &^= hidBtn
		}

		// Send updated absolute position with new button state.
		if s.cfg.HID.AbsMouseMove != nil {
			_ = s.cfg.HID.AbsMouseMove(0, 0, sess.mouseButtons)
		}

	case msgKeyboard:
		// [2 type][1 action][1 zero][2 keyCode LE][1 modifiers][1 zero]
		if len(data) < 8 {
			return
		}
		action := data[2]    // 0x03 = down, 0x04 = up
		vkCode := binary.LittleEndian.Uint16(data[4:6])
		winMods := data[6]

		hidKey := vkToHID(vkCode)
		if hidKey == 0 {
			log.Debug().Uint16("vk", vkCode).Msg("unmapped VK keycode")
			return
		}

		pressed := action == 0x03
		modifier := winModsToHID(winMods)

		// Use full keyboard report when modifier changes; otherwise keypress.
		if s.cfg.HID.KeyboardFull != nil {
			var keys []byte
			if pressed {
				keys = []byte{hidKey}
			}
			if err := s.cfg.HID.KeyboardFull(modifier, keys); err != nil {
				log.Warn().Err(err).Msg("KeyboardFull error")
			}
		} else if s.cfg.HID.Keyboard != nil {
			if err := s.cfg.HID.Keyboard(hidKey, pressed); err != nil {
				log.Warn().Err(err).Msg("Keyboard error")
			}
		}

	case msgScroll, msgScrollV2:
		// [2 type][2 zero][2 scrollAmt int16 BE]
		if len(data) < 6 {
			return
		}
		scrollAmt := int16(binary.BigEndian.Uint16(data[4:6]))
		dy := int8(clampScrollInt8(int32(scrollAmt)))
		if s.cfg.HID.Scroll != nil {
			if err := s.cfg.HID.Scroll(dy); err != nil {
				log.Warn().Err(err).Msg("Scroll error")
			}
		}

	default:
		log.Debug().Uint16("type", msgType).Msg("unknown Moonlight control message")
	}
}

// mlToHIDButtons converts Moonlight mouse button flags to USB HID button byte.
// Moonlight: bit0=left, bit1=right, bit2=middle
// HID:       bit0=left, bit1=right, bit2=middle (same order)
func mlToHIDButtons(ml uint8) uint8 {
	var hid uint8
	if ml&mlButtonLeft != 0 {
		hid |= 0x01
	}
	if ml&mlButtonRight != 0 {
		hid |= 0x02
	}
	if ml&mlButtonMiddle != 0 {
		hid |= 0x04
	}
	return hid
}

// winModsToHID converts Windows modifier flags to USB HID modifier byte.
//
//	Windows: bit0=shift, bit1=ctrl, bit2=alt, bit3=meta
//	HID:     bit0=LCtrl, bit1=LShift, bit2=LAlt, bit3=LGUI
func winModsToHID(win uint8) byte {
	var hid byte
	if win&0x02 != 0 {
		hid |= 0x01 // LCtrl
	}
	if win&0x01 != 0 {
		hid |= 0x02 // LShift
	}
	if win&0x04 != 0 {
		hid |= 0x04 // LAlt
	}
	if win&0x08 != 0 {
		hid |= 0x08 // LGUI
	}
	return hid
}

// clampInt8 clamps an int32 to the int8 range [-128, 127].
func clampInt8(v int32) int8 {
	if v > math.MaxInt8 {
		return math.MaxInt8
	}
	if v < math.MinInt8 {
		return math.MinInt8
	}
	return int8(v)
}

// clampScrollInt8 clamps a scroll amount, halving large values to avoid jumps.
func clampScrollInt8(v int32) int8 {
	if v > 120 || v < -120 {
		v /= 10 // normalise Windows-style scroll deltas (WHEEL_DELTA=120)
	}
	return clampInt8(v)
}

// vkToHID maps a Windows Virtual Key code to a USB HID Usage ID (keyboard page 0x07).
// Only the most common keys are mapped here; extend as needed.
func vkToHID(vk uint16) byte {
	switch vk {
	// Control keys
	case 0x08:
		return 0x2A // Backspace
	case 0x09:
		return 0x2B // Tab
	case 0x0D:
		return 0x28 // Return / Enter
	case 0x1B:
		return 0x29 // Escape
	case 0x20:
		return 0x2C // Space

	// Navigation
	case 0x21:
		return 0x4B // Page Up
	case 0x22:
		return 0x4E // Page Down
	case 0x23:
		return 0x4D // End
	case 0x24:
		return 0x4A // Home
	case 0x25:
		return 0x50 // Left
	case 0x26:
		return 0x52 // Up
	case 0x27:
		return 0x4F // Right
	case 0x28:
		return 0x51 // Down
	case 0x2D:
		return 0x49 // Insert
	case 0x2E:
		return 0x4C // Delete
	case 0x2F:
		return 0x00 // (unassigned in VK)

	// Digits 0–9
	case 0x30:
		return 0x27
	case 0x31:
		return 0x1E
	case 0x32:
		return 0x1F
	case 0x33:
		return 0x20
	case 0x34:
		return 0x21
	case 0x35:
		return 0x22
	case 0x36:
		return 0x23
	case 0x37:
		return 0x24
	case 0x38:
		return 0x25
	case 0x39:
		return 0x26

	// Letters A–Z (VK = ASCII; HID = 0x04 + (VK - 0x41))
	case 0x41:
		return 0x04
	case 0x42:
		return 0x05
	case 0x43:
		return 0x06
	case 0x44:
		return 0x07
	case 0x45:
		return 0x08
	case 0x46:
		return 0x09
	case 0x47:
		return 0x0A
	case 0x48:
		return 0x0B
	case 0x49:
		return 0x0C
	case 0x4A:
		return 0x0D
	case 0x4B:
		return 0x0E
	case 0x4C:
		return 0x0F
	case 0x4D:
		return 0x10
	case 0x4E:
		return 0x11
	case 0x4F:
		return 0x12
	case 0x50:
		return 0x13
	case 0x51:
		return 0x14
	case 0x52:
		return 0x15
	case 0x53:
		return 0x16
	case 0x54:
		return 0x17
	case 0x55:
		return 0x18
	case 0x56:
		return 0x19
	case 0x57:
		return 0x1A
	case 0x58:
		return 0x1B
	case 0x59:
		return 0x1C
	case 0x5A:
		return 0x1D

	// Numpad 0–9
	case 0x60:
		return 0x62
	case 0x61:
		return 0x59
	case 0x62:
		return 0x5A
	case 0x63:
		return 0x5B
	case 0x64:
		return 0x5C
	case 0x65:
		return 0x5D
	case 0x66:
		return 0x5E
	case 0x67:
		return 0x5F
	case 0x68:
		return 0x60
	case 0x69:
		return 0x61

	// Numpad operators
	case 0x6A:
		return 0x55 // *
	case 0x6B:
		return 0x57 // +
	case 0x6D:
		return 0x56 // -
	case 0x6E:
		return 0x63 // .
	case 0x6F:
		return 0x54 // /

	// Function keys F1–F12
	case 0x70:
		return 0x3A
	case 0x71:
		return 0x3B
	case 0x72:
		return 0x3C
	case 0x73:
		return 0x3D
	case 0x74:
		return 0x3E
	case 0x75:
		return 0x3F
	case 0x76:
		return 0x40
	case 0x77:
		return 0x41
	case 0x78:
		return 0x42
	case 0x79:
		return 0x43
	case 0x7A:
		return 0x44
	case 0x7B:
		return 0x45

	// Lock keys
	case 0x14:
		return 0x39 // Caps Lock
	case 0x90:
		return 0x53 // Num Lock
	case 0x91:
		return 0x47 // Scroll Lock

	// Punctuation / symbols
	case 0xBA:
		return 0x33 // ; :
	case 0xBB:
		return 0x2E // = +
	case 0xBC:
		return 0x36 // , <
	case 0xBD:
		return 0x2D // - _
	case 0xBE:
		return 0x37 // . >
	case 0xBF:
		return 0x38 // / ?
	case 0xC0:
		return 0x35 // ` ~
	case 0xDB:
		return 0x2F // [ {
	case 0xDC:
		return 0x31 // \ |
	case 0xDD:
		return 0x30 // ] }
	case 0xDE:
		return 0x34 // ' "

	// Print screen / Pause
	case 0x2C:
		return 0x46 // Print Screen
	case 0x13:
		return 0x48 // Pause

	default:
		return 0x00 // unmapped
	}
}

// buildENetAck constructs an ENet ACKNOWLEDGE datagram.
func buildENetAck(remotePeerID, myPeerID, rcvSeqNum, rcvSentTime uint16) []byte {
	buf := make([]byte, 12) // 4-byte header + 4-byte command header + 4-byte ack payload
	// Protocol header: peerID with SENT_TIME flag, sentTime
	now := uint16(time.Now().UnixMilli() & 0xFFFF)
	binary.BigEndian.PutUint16(buf[0:2], remotePeerID|enetFlagSentTime)
	binary.BigEndian.PutUint16(buf[2:4], now)
	// Command header: ACKNOWLEDGE command (no flags needed), channelID=0xFF, seqNum=0
	buf[4] = enetCmdAcknowledge
	buf[5] = 0xFF
	binary.BigEndian.PutUint16(buf[6:8], 0)
	// ACK payload: received seq + received sentTime
	binary.BigEndian.PutUint16(buf[8:10], rcvSeqNum)
	binary.BigEndian.PutUint16(buf[10:12], rcvSentTime)
	_ = myPeerID
	return buf
}

// buildENetVerifyConnect constructs an ENet VERIFY_CONNECT response datagram.
// VERIFY_CONNECT payload (40 bytes, same as CONNECT minus the trailing data field):
//
//	+0  outgoingPeerID (2) – server's own peer ID for the client to use
//	+2  incomingSessionID (1)
//	+3  outgoingSessionID (1)
//	+4  mtu (4)
//	+8  windowSize (4)
//	+12 channelCount (4)
//	+16 incomingBandwidth (4)
//	+20 outgoingBandwidth (4)
//	+24 packetThrottleInterval (4)
//	+28 packetThrottleAcceleration (4)
//	+32 packetThrottleDeceleration (4)
//	+36 connectID (4)  – echo of client's connectID
func buildENetVerifyConnect(clientPeerID uint16, connectID uint32) []byte {
	const serverPeerID = uint16(0x0001)
	// 4 protocol header + 4 command header + 40 payload = 48 bytes total.
	buf := make([]byte, 48)

	// Protocol header: addressed to client's peer ID, with sentTime flag.
	now := uint16(time.Now().UnixMilli() & 0xFFFF)
	binary.BigEndian.PutUint16(buf[0:2], clientPeerID|enetFlagSentTime)
	binary.BigEndian.PutUint16(buf[2:4], now)

	// Command header: VERIFY_CONNECT with ACK flag, channel 0xFF (connection-level).
	buf[4] = enetCmdVerifyConnect | enetFlagAcknowledge
	buf[5] = 0xFF
	binary.BigEndian.PutUint16(buf[6:8], 1) // outgoing reliable sequence number

	// VERIFY_CONNECT payload (40 bytes starting at buf[8]).
	p := buf[8:]
	binary.BigEndian.PutUint16(p[0:2], serverPeerID) // server's peer ID
	p[2] = 0                                          // incomingSessionID
	p[3] = 0                                          // outgoingSessionID
	binary.BigEndian.PutUint32(p[4:8], 1400)          // mtu
	binary.BigEndian.PutUint32(p[8:12], 32768)         // windowSize
	binary.BigEndian.PutUint32(p[12:16], 2)            // channelCount
	binary.BigEndian.PutUint32(p[16:20], 0)            // incomingBandwidth (unlimited)
	binary.BigEndian.PutUint32(p[20:24], 0)            // outgoingBandwidth (unlimited)
	binary.BigEndian.PutUint32(p[24:28], 5000)         // packetThrottleInterval
	binary.BigEndian.PutUint32(p[28:32], 2)            // packetThrottleAcceleration
	binary.BigEndian.PutUint32(p[32:36], 2)            // packetThrottleDeceleration
	binary.BigEndian.PutUint32(p[36:40], connectID)    // echo of client connectID
	return buf
}
