package httpsignatures

import (
	"crypto/md5"
	"crypto/subtle"
)

const algoMd5 = "MD5"

// MD5 MD5 Algorithm
type Md5 struct{}

// Algorithm Return algorithm name
func (a Md5) Algorithm() string {
	return algoMd5
}

// Create Create hash
func (a Md5) Create(data []byte) ([]byte, error) {
	h := md5.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating hash", err}
	}
	return h.Sum(nil), nil
}

// Verify Verify hash
func (a Md5) Verify(data []byte, digest []byte) error {
	expected, err := a.Create(data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &CryptoError{"wrong hash", nil}
	}
	return nil
}
