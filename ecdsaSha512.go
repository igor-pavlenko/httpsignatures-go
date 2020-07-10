package httpsignatures

import (
	"crypto/sha512"
)

const algEcdsaSha512 = "ECDSA-SHA512"

// EcdsaSha512 ECDSA with SHA512 Algorithm
type EcdsaSha512 struct{}

// Algorithm Return algorithm name
func (a EcdsaSha512) Algorithm() string {
	return algEcdsaSha512
}

// Create Create signature using passed privateKey from secret
func (a EcdsaSha512) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureEcdsaAlgorithmCreate(algEcdsaSha512, sha512.New, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a EcdsaSha512) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureEcdsaAlgorithmVerify(algEcdsaSha512, sha512.New, secret, data, signature)
}
