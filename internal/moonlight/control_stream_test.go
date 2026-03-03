package moonlight

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlGCMNonce(t *testing.T) {
	tests := []struct {
		name   string
		seqNum uint32
	}{
		{"seq=0", 0},
		{"seq=1", 1},
		{"seq=255", 255},
		{"seq=0xDEADBEEF", 0xDEADBEEF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := buildControlGCMNonce(tt.seqNum)

			assert.Len(t, nonce, 12)

			// First 4 bytes = seqNum in LE.
			gotSeq := binary.LittleEndian.Uint32(nonce[0:4])
			assert.Equal(t, tt.seqNum, gotSeq)

			// Bytes 4-9 should be zeros.
			for i := 4; i < 10; i++ {
				assert.Equal(t, byte(0), nonce[i], "nonce[%d] should be zero", i)
			}

			// Bytes 10 and 11 should be 'C' (0x43).
			assert.Equal(t, byte(0x43), nonce[10])
			assert.Equal(t, byte(0x43), nonce[11])
		})
	}
}

func TestControlEncryptedHeaderParsing(t *testing.T) {
	// Build a synthetic encrypted control packet.
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	seqNum := uint32(42)

	// Build inner V2 header + payload.
	innerType := uint16(msgMouseMoveRel)
	innerPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	innerPayloadLen := uint16(len(innerPayload))

	plaintext := make([]byte, 4+len(innerPayload))
	binary.LittleEndian.PutUint16(plaintext[0:2], innerType)
	binary.LittleEndian.PutUint16(plaintext[2:4], innerPayloadLen)
	copy(plaintext[4:], innerPayload)

	// Encrypt with GCM.
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	require.NoError(t, err)

	nonce := buildControlGCMNonce(seqNum)
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// sealed = ciphertext + 16-byte tag.
	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	// Build the full NVCTL_ENCRYPTED_PACKET wire format:
	// [2B type=0x0001 LE][2B length LE][4B seq LE][16B tag][ciphertext]
	wireLen := uint16(4 + 16 + len(ciphertext)) // seq + tag + ciphertext
	wire := make([]byte, 8+16+len(ciphertext))
	binary.LittleEndian.PutUint16(wire[0:2], 0x0001)
	binary.LittleEndian.PutUint16(wire[2:4], wireLen)
	binary.LittleEndian.PutUint32(wire[4:8], seqNum)
	copy(wire[8:24], tag)
	copy(wire[24:], ciphertext)

	// Decrypt.
	sess := &Session{
		RIKey:   key,
		RIKeyID: 0,
	}
	result, err := decryptControlPayload(wire, sess)
	require.NoError(t, err)

	// Result should be [2B type][payload] (V2 payloadLength stripped).
	assert.Equal(t, 2+len(innerPayload), len(result))
	gotType := binary.LittleEndian.Uint16(result[0:2])
	assert.Equal(t, innerType, gotType)
	assert.Equal(t, innerPayload, result[2:])
}

func TestControlDecryptPayload(t *testing.T) {
	key := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	seqNum := uint32(100)

	// Inner message: [type LE][payloadLen LE][payload bytes]
	innerMsg := make([]byte, 12)
	binary.LittleEndian.PutUint16(innerMsg[0:2], msgKeyboard)
	binary.LittleEndian.PutUint16(innerMsg[2:4], 8) // payload length
	// Keyboard payload: [action][zero][keycode LE][mods][zero]
	innerMsg[4] = 0x03 // key down
	innerMsg[5] = 0
	binary.LittleEndian.PutUint16(innerMsg[6:8], 0x41) // VK_A
	innerMsg[8] = 0
	innerMsg[9] = 0

	// Encrypt.
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	require.NoError(t, err)

	nonce := buildControlGCMNonce(seqNum)
	sealed := gcm.Seal(nil, nonce, innerMsg, nil)

	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	// Build wire packet.
	wire := make([]byte, 8+16+len(ciphertext))
	binary.LittleEndian.PutUint16(wire[0:2], 0x0001)
	binary.LittleEndian.PutUint16(wire[2:4], uint16(4+16+len(ciphertext)))
	binary.LittleEndian.PutUint32(wire[4:8], seqNum)
	copy(wire[8:24], tag)
	copy(wire[24:], ciphertext)

	sess := &Session{RIKey: key, RIKeyID: 0}
	result, err := decryptControlPayload(wire, sess)
	require.NoError(t, err)

	// Result: [type(2)][payload after V2 header]
	gotType := binary.LittleEndian.Uint16(result[0:2])
	assert.Equal(t, uint16(msgKeyboard), gotType)
	assert.Equal(t, byte(0x03), result[2]) // action = key down
}

func TestControlV2HeaderParsing(t *testing.T) {
	key := make([]byte, 16)
	seqNum := uint32(0)

	// V2 header: type=0x0206 (mouse rel), payloadLen=8
	// payload: 8 bytes of mouse data
	v2 := make([]byte, 12)
	binary.LittleEndian.PutUint16(v2[0:2], msgMouseMoveRel)
	binary.LittleEndian.PutUint16(v2[2:4], 8)
	binary.BigEndian.PutUint32(v2[4:8], 10)  // dx
	binary.BigEndian.PutUint32(v2[8:12], 20) // dy

	// Encrypt.
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	require.NoError(t, err)

	nonce := buildControlGCMNonce(seqNum)
	sealed := gcm.Seal(nil, nonce, v2, nil)

	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	wire := make([]byte, 8+16+len(ciphertext))
	binary.LittleEndian.PutUint16(wire[0:2], 0x0001)
	binary.LittleEndian.PutUint16(wire[2:4], uint16(4+16+len(ciphertext)))
	binary.LittleEndian.PutUint32(wire[4:8], seqNum)
	copy(wire[8:24], tag)
	copy(wire[24:], ciphertext)

	sess := &Session{RIKey: key}
	result, err := decryptControlPayload(wire, sess)
	require.NoError(t, err)

	// After V2 header stripping: [2B type][8B payload]
	assert.Equal(t, 10, len(result))
	assert.Equal(t, uint16(msgMouseMoveRel), binary.LittleEndian.Uint16(result[0:2]))
	// Mouse payload starts at offset 2.
	assert.Equal(t, uint32(10), binary.BigEndian.Uint32(result[2:6])) // dx
	assert.Equal(t, uint32(20), binary.BigEndian.Uint32(result[6:10])) // dy
}

func TestDecryptRoundTrip(t *testing.T) {
	key := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00}

	// Test multiple sequence numbers.
	for seq := uint32(0); seq < 5; seq++ {
		// Build inner message with V2 header.
		inner := make([]byte, 6)
		binary.LittleEndian.PutUint16(inner[0:2], msgScroll)
		binary.LittleEndian.PutUint16(inner[2:4], 2) // payload len
		binary.BigEndian.PutUint16(inner[4:6], uint16(seq*10))

		// Encrypt.
		block, err := aes.NewCipher(key)
		require.NoError(t, err)
		gcm, err := cipher.NewGCMWithNonceSize(block, 12)
		require.NoError(t, err)

		nonce := buildControlGCMNonce(seq)
		sealed := gcm.Seal(nil, nonce, inner, nil)

		ciphertext := sealed[:len(sealed)-16]
		tag := sealed[len(sealed)-16:]

		// Build wire packet.
		wire := make([]byte, 8+16+len(ciphertext))
		binary.LittleEndian.PutUint16(wire[0:2], 0x0001)
		binary.LittleEndian.PutUint16(wire[2:4], uint16(4+16+len(ciphertext)))
		binary.LittleEndian.PutUint32(wire[4:8], seq)
		copy(wire[8:24], tag)
		copy(wire[24:], ciphertext)

		sess := &Session{RIKey: key}
		result, err := decryptControlPayload(wire, sess)
		require.NoError(t, err)

		// Verify: [type][payload]
		gotType := binary.LittleEndian.Uint16(result[0:2])
		assert.Equal(t, uint16(msgScroll), gotType)
		gotScrollAmt := binary.BigEndian.Uint16(result[2:4])
		assert.Equal(t, uint16(seq*10), gotScrollAmt)
	}
}

func TestControlDecryptWrongKey(t *testing.T) {
	key := make([]byte, 16)
	wrongKey := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	inner := make([]byte, 4)
	binary.LittleEndian.PutUint16(inner[0:2], msgKeyboard)
	binary.LittleEndian.PutUint16(inner[2:4], 0)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 12)
	nonce := buildControlGCMNonce(0)
	sealed := gcm.Seal(nil, nonce, inner, nil)

	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	wire := make([]byte, 8+16+len(ciphertext))
	binary.LittleEndian.PutUint16(wire[0:2], 0x0001)
	binary.LittleEndian.PutUint16(wire[2:4], uint16(4+16+len(ciphertext)))
	binary.LittleEndian.PutUint32(wire[4:8], 0)
	copy(wire[8:24], tag)
	copy(wire[24:], ciphertext)

	sess := &Session{RIKey: wrongKey}
	_, err := decryptControlPayload(wire, sess)
	assert.Error(t, err, "decryption should fail with wrong key")
}

func TestControlPayloadTooShort(t *testing.T) {
	sess := &Session{RIKey: make([]byte, 16)}

	// Less than 24 bytes (8 header + 16 tag minimum).
	_, err := decryptControlPayload(make([]byte, 10), sess)
	assert.Error(t, err)
}
