package httpsignatures

import (
	"crypto/sha256"
	"crypto/subtle"
)

const algoSha256 = "SHA-256"

// Sha256 Sha256 Algorithm
type Sha256 struct{}

// Algorithm Return algorithm name
func (a Sha256) Algorithm() string {
	return algoSha256
}

// Create Create hash
func (a Sha256) Create(data []byte) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating hash", err}
	}
	return h.Sum(nil), nil
}

// Verify Verify hash
func (a Sha256) Verify(data []byte, digest []byte) error {
	expected, err := a.Create(data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &CryptoError{"wrong hash", nil}
	}
	return nil
}
