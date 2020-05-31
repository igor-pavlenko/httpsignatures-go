package httpsignatures

import (
	"crypto"
	"crypto/sha512"
)

const algoRsaSsaPssSha512 = "RSASSA-PSS-SHA512"

// RsaSsaPssSha512 RSA-PSS-SHA512 Algorithm
type RsaSsaPssSha512 struct{}

// Algorithm Return algorithm name
func (a RsaSsaPssSha512) Algorithm() string {
	return algoRsaSsaPssSha512
}

// Create Create signature using passed privateKey from secret
func (a RsaSsaPssSha512) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(algoRsaSsaPssSha512, sha512.New, crypto.SHA512, secret, data)
}

// Verify Verify signature using passed publicKey from secret
func (a RsaSsaPssSha512) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(algoRsaSsaPssSha512, sha512.New, crypto.SHA512, secret, data, signature)
}
