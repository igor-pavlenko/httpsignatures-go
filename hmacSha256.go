package httpsignatures

import (
	"crypto/sha256"
)

const algoHmacSha256 = "HMAC-SHA256"

// HmacSha256 HMAC-SHA256 Algorithm
type HmacSha256 struct{}

// Algorithm Return algorithm name
func (a HmacSha256) Algorithm() string {
	return algoHmacSha256
}

// Create Create signature using passed privateKey from secret
func (a HmacSha256) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureHashAlgorithmCreate(sha256.New, secret, data)
}

// Verify Verify signature using passed privateKey from secret
func (a HmacSha256) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureHashAlgorithmVerify(sha256.New, secret, data, signature)
}
