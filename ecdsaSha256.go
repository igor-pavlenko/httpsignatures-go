package httpsignatures

import (
	"crypto/sha256"
)

const algEcdsaSha256 = "ECDSA-SHA256"

// EcdsaSha256 ECDSA with SHA256 Algorithm
type EcdsaSha256 struct{}

// Algorithm Return algorithm name
func (a EcdsaSha256) Algorithm() string {
	return algEcdsaSha256
}

// Create Create signature using passed privateKey from secret
func (a EcdsaSha256) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureEcdsaAlgorithmCreate(algEcdsaSha256, sha256.New, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a EcdsaSha256) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureEcdsaAlgorithmVerify(algEcdsaSha256, sha256.New, secret, data, signature)
}
