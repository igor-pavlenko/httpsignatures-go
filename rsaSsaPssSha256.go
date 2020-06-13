package httpsignatures

import (
	"crypto"
	"crypto/sha256"
)

const algRsaSsaPssSha256 = "RSASSA-PSS-SHA256"

// RsaSsaPssSha256 RSA-PSS-SHA256 Algorithm
//
// Deprecated: specifying signature algorithm enables attack vector.
type RsaSsaPssSha256 struct{}

// Algorithm Return algorithm name
func (a RsaSsaPssSha256) Algorithm() string {
	return algRsaSsaPssSha256
}

// Create Create signature using passed privateKey from secret
func (a RsaSsaPssSha256) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(algRsaSsaPssSha256, sha256.New, crypto.SHA256, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a RsaSsaPssSha256) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(algRsaSsaPssSha256, sha256.New, crypto.SHA256, secret, data, signature)
}
