package httpsignatures

import (
	"crypto/md5"
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
	return digestHashAlgorithmCreate(md5.New, data)
}

// Verify Verify hash
func (a Md5) Verify(data []byte, digest []byte) error {
	return digestHashAlgorithmVerify(md5.New, data, digest)
}
