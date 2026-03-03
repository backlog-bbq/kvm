package moonlight

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPairingAESKey(t *testing.T) {
	// Verify key derivation from PIN + salt produces consistent results.
	pin := "1234"
	salt := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	key1 := pairingAESKey(pin, salt)
	key2 := pairingAESKey(pin, salt)

	assert.Equal(t, 16, len(key1))
	assert.Equal(t, key1, key2, "same inputs should produce same key")

	// Different PIN should produce different key.
	key3 := pairingAESKey("5678", salt)
	assert.NotEqual(t, key1, key3, "different PIN should produce different key")

	// Different salt should produce different key.
	key4 := pairingAESKey(pin, []byte{0x11, 0x22, 0x33, 0x44})
	assert.NotEqual(t, key1, key4, "different salt should produce different key")

	// Nil salt should work (falls back to SHA256(PIN)).
	key5 := pairingAESKey(pin, nil)
	assert.Equal(t, 16, len(key5))
}

func TestAES128ECBRoundTrip(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	// Plaintext must be multiple of 16.
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertext, err := aes128ECBEncrypt(key, plaintext)
	require.NoError(t, err)
	assert.Equal(t, len(plaintext), len(ciphertext))
	assert.NotEqual(t, plaintext, ciphertext, "ciphertext should differ from plaintext")

	decrypted, err := aes128ECBDecrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAES128ECBInvalidInput(t *testing.T) {
	key := make([]byte, 16)

	// Non-multiple of block size should error.
	_, err := aes128ECBEncrypt(key, []byte{0x01, 0x02, 0x03})
	assert.Error(t, err)

	_, err = aes128ECBDecrypt(key, []byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestPairingStoreSerialize(t *testing.T) {
	store := NewPairingStore()
	store.PairedClients["client1"] = "-----BEGIN CERTIFICATE-----\ntest1\n-----END CERTIFICATE-----"
	store.PairedClients["client2"] = "-----BEGIN CERTIFICATE-----\ntest2\n-----END CERTIFICATE-----"

	// Serialize.
	data, err := json.MarshalIndent(store, "", "  ")
	require.NoError(t, err)

	// Deserialize.
	var loaded PairingStore
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)

	assert.Equal(t, 2, len(loaded.PairedClients))
	assert.Equal(t, store.PairedClients["client1"], loaded.PairedClients["client1"])
	assert.Equal(t, store.PairedClients["client2"], loaded.PairedClients["client2"])
}

func TestPairingStoreIsPaired(t *testing.T) {
	store := NewPairingStore()
	assert.False(t, store.IsPaired("unknown"))

	store.PairedClients["known"] = "cert-pem"
	assert.True(t, store.IsPaired("known"))
	assert.False(t, store.IsPaired("other"))
}

func TestPairingStoreGetPairedClientIDs(t *testing.T) {
	store := NewPairingStore()
	assert.Empty(t, store.GetPairedClientIDs())

	store.PairedClients["a"] = "cert"
	store.PairedClients["b"] = "cert"

	ids := store.GetPairedClientIDs()
	assert.Len(t, ids, 2)
	assert.Contains(t, ids, "a")
	assert.Contains(t, ids, "b")
}
