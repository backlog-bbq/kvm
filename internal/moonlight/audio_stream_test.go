package moonlight

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAudioIVConstruction(t *testing.T) {
	tests := []struct {
		name     string
		rikeyID  uint32
		seq      uint16
		wantIV0  uint32 // expected first 4 bytes as BE uint32
	}{
		{"zero/zero", 0, 0, 0},
		{"rikeyID=1, seq=0", 1, 0, 1},
		{"rikeyID=0, seq=1", 0, 1, 1},
		{"rikeyID=100, seq=50", 100, 50, 150},
		{"rikeyID=0xFFFFFF00, seq=0xFF", 0xFFFFFF00, 0xFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct IV the same way as encryptAudioPayload.
			iv := make([]byte, aes.BlockSize)
			binary.BigEndian.PutUint32(iv[0:4], tt.rikeyID+uint32(tt.seq))

			gotIV0 := binary.BigEndian.Uint32(iv[0:4])
			assert.Equal(t, tt.wantIV0, gotIV0)
			// Remaining 12 bytes should be zeros.
			for i := 4; i < aes.BlockSize; i++ {
				assert.Equal(t, byte(0), iv[i], "iv[%d] should be zero", i)
			}
		})
	}
}

func TestAudioIVWrap(t *testing.T) {
	// When seq wraps from 0xFFFF to 0x0000, the IV should change accordingly.
	rikeyID := uint32(10)

	iv1 := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(iv1[0:4], rikeyID+uint32(uint16(0xFFFF)))

	iv2 := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(iv2[0:4], rikeyID+uint32(uint16(0x0000)))

	// iv1 should be rikeyID + 65535, iv2 should be rikeyID + 0.
	assert.Equal(t, rikeyID+65535, binary.BigEndian.Uint32(iv1[0:4]))
	assert.Equal(t, rikeyID, binary.BigEndian.Uint32(iv2[0:4]))
}

func TestAudioCBCEncryption(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	rikeyID := uint32(42)
	seq := uint16(7)

	plaintext := opusSilenceFrame // 3 bytes

	ciphertext, err := encryptAudioPayload(plaintext, key, rikeyID, seq)
	require.NoError(t, err)

	// Output should be padded to block size.
	assert.Equal(t, aes.BlockSize, len(ciphertext))

	// Decrypt to verify roundtrip.
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	iv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(iv[0:4], rikeyID+uint32(seq))

	decrypted := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, ciphertext)

	// First 3 bytes should match original, rest is zero padding.
	assert.Equal(t, plaintext, decrypted[:len(plaintext)])
	for i := len(plaintext); i < len(decrypted); i++ {
		assert.Equal(t, byte(0), decrypted[i], "padding byte %d should be zero", i)
	}
}

func TestAudioCBCEncryptionNoKey(t *testing.T) {
	// With no key, should return plaintext unencrypted.
	plaintext := []byte{0xAA, 0xBB, 0xCC}
	result, err := encryptAudioPayload(plaintext, nil, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, plaintext, result)
}

func TestAudioRTPPacket(t *testing.T) {
	seq := uint16(1234)
	ts := uint32(56789)
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	pkt := buildAudioRTPPacket(seq, ts, payload)

	assert.Equal(t, 12+len(payload), len(pkt))

	// RTP header fields.
	assert.Equal(t, byte(0x80), pkt[0])             // V=2
	assert.Equal(t, byte(97), pkt[1]&0x7F)          // PT=97 (Opus)
	assert.Equal(t, seq, binary.BigEndian.Uint16(pkt[2:4]))
	assert.Equal(t, ts, binary.BigEndian.Uint32(pkt[4:8]))
	assert.Equal(t, uint32(audioSSRC), binary.BigEndian.Uint32(pkt[8:12]))

	// Payload.
	assert.Equal(t, payload, pkt[12:])
}
