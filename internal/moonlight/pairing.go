package moonlight

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

const pairingStorePath = "/userdata/moonlight_pairing.json"

// PairingStore persists the server's RSA key pair, certificate, and paired client certs.
type PairingStore struct {
	mu sync.RWMutex

	// ServerKey is the RSA-2048 private key (PEM-encoded).
	ServerKeyPEM string `json:"server_key_pem"`
	// ServerCert is the self-signed X.509 certificate (PEM-encoded).
	ServerCertPEM string `json:"server_cert_pem"`
	// PairedClients maps uniqueID → client certificate PEM.
	PairedClients map[string]string `json:"paired_clients"`

	serverKey  *rsa.PrivateKey
	serverCert *x509.Certificate
}

// NewPairingStore creates an empty store (keys not yet generated).
func NewPairingStore() *PairingStore {
	return &PairingStore{
		PairedClients: make(map[string]string),
	}
}

// LoadPairingStore loads the pairing store from disk.
func LoadPairingStore() (*PairingStore, error) {
	data, err := os.ReadFile(pairingStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewPairingStore(), nil
		}
		return nil, fmt.Errorf("moonlight: reading pairing store: %w", err)
	}

	var s PairingStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("moonlight: parsing pairing store: %w", err)
	}
	if s.PairedClients == nil {
		s.PairedClients = make(map[string]string)
	}
	return &s, nil
}

// Save persists the pairing store to disk.
func (s *PairingStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("moonlight: marshaling pairing store: %w", err)
	}
	if err := os.WriteFile(pairingStorePath, data, 0600); err != nil {
		return fmt.Errorf("moonlight: writing pairing store: %w", err)
	}
	return nil
}

// EnsureServerKeys generates a new RSA key pair and self-signed certificate if not
// already present, then saves the store to disk.
func (s *PairingStore) EnsureServerKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ServerKeyPEM != "" && s.ServerCertPEM != "" {
		// Keys already exist; parse and cache them.
		return s.parseKeys()
	}

	log.Info().Msg("generating new RSA-2048 server key pair for Moonlight pairing")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("moonlight: generating RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("moonlight: generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "JetKVM",
			Organization: []string{"JetKVM"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour), // 20 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("moonlight: creating certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	s.ServerKeyPEM = string(keyPEM)
	s.ServerCertPEM = string(certPEM)
	s.serverKey = key

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("moonlight: parsing certificate: %w", err)
	}
	s.serverCert = cert

	// Save without lock (we already hold it).
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pairingStorePath, data, 0600)
}

// parseKeys decodes the PEM-encoded key and cert from the store fields.
// Must be called with the write lock held.
func (s *PairingStore) parseKeys() error {
	block, _ := pem.Decode([]byte(s.ServerKeyPEM))
	if block == nil {
		return fmt.Errorf("moonlight: invalid server key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("moonlight: parsing server key: %w", err)
	}
	s.serverKey = key

	block, _ = pem.Decode([]byte(s.ServerCertPEM))
	if block == nil {
		return fmt.Errorf("moonlight: invalid server cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("moonlight: parsing server cert: %w", err)
	}
	s.serverCert = cert
	return nil
}

// ServerCertPEMBytes returns the server certificate PEM as bytes.
func (s *PairingStore) ServerCertPEMBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return []byte(s.ServerCertPEM)
}

// IsPaired returns true if the given uniqueID is already paired.
func (s *PairingStore) IsPaired(uniqueID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.PairedClients[uniqueID]
	return ok
}

// StorePairedClient saves a client certificate for a given uniqueID.
func (s *PairingStore) StorePairedClient(uniqueID, certPEM string) error {
	s.mu.Lock()
	s.PairedClients[uniqueID] = certPEM
	s.mu.Unlock()
	return s.Save()
}

// RemovePairedClient removes a paired client.
func (s *PairingStore) RemovePairedClient(uniqueID string) error {
	s.mu.Lock()
	delete(s.PairedClients, uniqueID)
	s.mu.Unlock()
	return s.Save()
}

// pairingState holds intermediate state during the multi-phase pairing flow.
type pairingState struct {
	uniqueID string
	pin      string // 4-digit PIN shown to the user
	aesKey   []byte // SHA256(PIN)[0:16]

	// Phase 2 outputs (used to verify phase 3/4)
	serverChallenge []byte // random 16 bytes generated by the server
	serverResponse  []byte // SHA256(clientData ‖ serverCert.Sig ‖ serverChallenge)

	// Phase 3 output (verified in phase 4 once we have the client cert)
	// clientChallengeHash = AES_decrypt(serverchallengeresp) = SHA256(serverResponse ‖ clientCert.Sig)
	clientChallengeHash []byte

	clientCertPEM string // received in phase 4
}

// pairingAESKey derives the 128-bit AES key from the pairing PIN using SHA-256.
// This follows the Sunshine/Moonlight protocol: key = SHA256(PIN)[0:16].
func pairingAESKey(pin string) []byte {
	sum := sha256.Sum256([]byte(pin))
	return sum[:16]
}

// aes128CBCDecrypt decrypts AES-128-CBC with a zero IV.
func aes128CBCDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("moonlight: ciphertext not a multiple of block size")
	}
	iv := make([]byte, aes.BlockSize) // all-zero IV per Moonlight spec
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// aes128CBCEncrypt encrypts AES-128-CBC with a zero IV.
func aes128CBCEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Pad to block size.
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padLen == aes.BlockSize {
		padLen = 0
	}
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)

	iv := make([]byte, aes.BlockSize) // all-zero IV per Moonlight spec
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

// generatePIN generates a random 4-digit decimal PIN.
func generatePIN() (string, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := (int(b[0])<<8 | int(b[1])) % 10000
	return fmt.Sprintf("%04d", n), nil
}

// rsaSignSHA256 signs data with SHA-256 using the server's private key.
func (s *PairingStore) rsaSignSHA256(data []byte) ([]byte, error) {
	s.mu.RLock()
	key := s.serverKey
	s.mu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("moonlight: server key not loaded")
	}
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
}

// hexDecode decodes a hex string, returning an error on failure.
func hexDecode(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("moonlight: hex decode %q: %w", s, err)
	}
	return b, nil
}
