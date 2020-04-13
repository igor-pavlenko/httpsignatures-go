package httpsignatures

import (
	"crypto/md5"
	"crypto/subtle"
)

const algoMd5 = "MD5"

// Md5 MD5 Algorithm
type Md5 struct{}

// Algorithm Return algorithm name
func (a Md5) Algorithm() string {
	return algoMd5
}

// Create Create hash
func (a Md5) Create(data []byte) ([]byte, error) {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// Verify Verify hash
func (a Md5) Verify(data []byte, digest []byte) error {
	expected, _ := a.Create(data)
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &CryptoError{"wrong hash", nil}
	}
	return nil
}
