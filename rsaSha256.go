package httpsignatures

import (
	"crypto"
	"crypto/sha256"
)

const algoRsaSha256 = "RSA-SHA256"

// RsaSha256 RSA-SHA265 Algorithm
//
// Deprecated: specifying signature algorithm enables attack vector.
type RsaSha256 struct{}

// Algorithm Return algorithm name
func (a RsaSha256) Algorithm() string {
	return algoRsaSha256
}

// Create Create signature using passed privateKey from secret
func (a RsaSha256) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(algoRsaSha256, sha256.New, crypto.SHA256, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a RsaSha256) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(algoRsaSha256, sha256.New, crypto.SHA256, secret, data, signature)
}
