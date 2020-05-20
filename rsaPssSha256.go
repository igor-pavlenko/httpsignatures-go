package httpsignatures

import (
	"crypto"
	"crypto/sha256"
)

const algoRsaPssSha256 = "RSA-PSS-SHA256"

// RsaPssSha256 RSA-PSS-SHA256 Algorithm
type RsaPssSha256 struct{}

// Algorithm Return algorithm name
func (a RsaPssSha256) Algorithm() string {
	return algoRsaPssSha256
}

// Create Create signature using passed privateKey from secret
func (a RsaPssSha256) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(algoRsaPssSha256, sha256.New, crypto.SHA256, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a RsaPssSha256) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(algoRsaPssSha256, sha256.New, crypto.SHA256, secret, data, signature)
}
