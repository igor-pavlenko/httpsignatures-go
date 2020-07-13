package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"github.com/igor-pavlenko/httpsignatures.go"
)

// To create your own signature hash algorithm, implement httpsignatures.SignatureHashAlgorithm interface
// type SignatureHashAlgorithm interface {
// 	   Algorithm() string
// 	   Create(secret Secret, data []byte) ([]byte, error)
// 	   Verify(secret Secret, data []byte, signature []byte) error
// }

// Digest algorithm name
const algHmacSha1Name = "HMAC-SHA1"

// algHmacSha1 HMAC-SHA1 Algorithm
type algHmacSha1 struct{}

// Algorithm Return algorithm name
func (a algHmacSha1) Algorithm() string {
	return algHmacSha1Name
}

// Create Create hash
func (a algHmacSha1) Create(secret httpsignatures.Secret, data []byte) ([]byte, error) {
	if len(secret.PrivateKey) == 0 {
		return nil, &httpsignatures.ErrCrypto{Message: "no private key found"}
	}
	mac := hmac.New(sha1.New, []byte(secret.PrivateKey))
	_, err := mac.Write(data)
	if err != nil {
		return nil, &httpsignatures.ErrCrypto{Message: "error creating signature", Err: err}
	}
	return mac.Sum(nil), nil
}

// Verify Verify hash
func (a algHmacSha1) Verify(secret httpsignatures.Secret, data []byte, signature []byte) error {
	expected, err := a.Create(secret, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expected) {
		return &httpsignatures.ErrCrypto{Message: "wrong signature"}
	}
	return nil
}

func main() {
	hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
	hs.SetSignatureHashAlgorithm(algHmacSha1{})
}
