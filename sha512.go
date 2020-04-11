package httpsignatures

import (
	"crypto/sha512"
	"crypto/subtle"
)

const algoSha512 = "SHA-512"

// Sha512 Sha512 Algorithm
type Sha512 struct{}

// Algorithm Return algorithm name
func (a Sha512) Algorithm() string {
	return algoSha512
}

// Create Create hash
func (a Sha512) Create(data []byte) ([]byte, error) {
	h := sha512.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating hash", err}
	}
	return h.Sum(nil), nil
}

// Verify Verify hash
func (a Sha512) Verify(data []byte, digest []byte) error {
	expected, err := a.Create(data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &CryptoError{"wrong hash", nil}
	}
	return nil
}
