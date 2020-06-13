package httpsignatures

import (
	"crypto/sha512"
)

const algHmacSha512 = "HMAC-SHA512"

// HmacSha512 HMAC-SHA512 Algorithm
type HmacSha512 struct{}

// Algorithm Return algorithm name
func (a HmacSha512) Algorithm() string {
	return algHmacSha512
}

// Create Create signature using passed privateKey from secret
func (a HmacSha512) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureHashAlgorithmCreate(sha512.New, secret, data)
}

// Verify Verify signature using passed privateKey from secret
func (a HmacSha512) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureHashAlgorithmVerify(sha512.New, secret, data, signature)
}
