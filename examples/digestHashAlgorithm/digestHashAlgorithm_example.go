package main

import (
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"github.com/igor-pavlenko/httpsignatures.go"
)

// To create new digest algorithm, implement httpsignatures.DigestHashAlgorithm interface
// type DigestHashAlgorithm interface {
//	 Algorithm() string
//	 Create(data []byte) ([]byte, error)
// 	 Verify(data []byte, digest []byte) error
// }

// Digest algorithm name
const algSha1Name = "sha1"

// algSha1 sha1 Algorithm
type algSha1 struct{}

// Algorithm Return algorithm name
func (a algSha1) Algorithm() string {
	return algSha1Name
}

// Create Create hash
func (a algSha1) Create(data []byte) ([]byte, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, &httpsignatures.ErrCrypto{Message: "error creating hash", Err: err}
	}
	return h.Sum(nil), nil
}

// Verify Verify hash
func (a algSha1) Verify(data []byte, digest []byte) error {
	expected, err := a.Create(data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &httpsignatures.ErrCrypto{Message: "wrong hash"}
	}
	return nil
}

func main() {
	hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
	// Add algorithm implementation
	hs.SetDigestAlgorithm(algSha1{})
	// Set `algSha1Name` as default algorithm for digest
	err := hs.SetDefaultDigestAlgorithm(algSha1Name)
	if err != nil {
		fmt.Println(err)
	}
}
