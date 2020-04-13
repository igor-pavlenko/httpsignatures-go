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
	h.Write(data)
	return h.Sum(nil), nil
}

// Verify Verify hash
func (a Sha512) Verify(data []byte, digest []byte) error {
	expected, _ := a.Create(data)
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &CryptoError{"wrong hash", nil}
	}
	return nil
}
