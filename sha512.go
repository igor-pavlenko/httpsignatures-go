package httpsignatures

import (
	"crypto/sha512"
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
	return digestHashAlgorithmCreate(sha512.New, data)
}

// Verify Verify hash
func (a Sha512) Verify(data []byte, digest []byte) error {
	return digestHashAlgorithmVerify(sha512.New, data, digest)
}
