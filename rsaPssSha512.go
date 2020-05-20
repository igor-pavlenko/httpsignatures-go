package httpsignatures

import (
	"crypto"
	"crypto/sha512"
)

const algoRsaPssSha512 = "RSA-PSS-SHA512"

// RsaPssSha512 RSA-PSS-SHA512 Algorithm
type RsaPssSha512 struct{}

// Algorithm Return algorithm name
func (a RsaPssSha512) Algorithm() string {
	return algoRsaPssSha512
}

// Create Create signature using passed privateKey from secret
func (a RsaPssSha512) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(algoRsaPssSha512, sha512.New, crypto.SHA512, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a RsaPssSha512) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(algoRsaPssSha512, sha512.New, crypto.SHA512, secret, data, signature)
}
