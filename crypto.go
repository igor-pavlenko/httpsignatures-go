package httpsignatures

import (
	"crypto/subtle"
	"fmt"
	"hash"
)

// SignatureHashAlgorithm interface to create/verify Signature using secret keys
// Algorithm return algorithm name
// Create create new signature
// Verify verify passed signature
type SignatureHashAlgorithm interface {
	Algorithm() string
	Create(secret Secret, data []byte) ([]byte, error)
	Verify(secret Secret, data []byte, signature []byte) error
}

// DigestHashAlgorithm interface to create/verify digest HMAC hash
type DigestHashAlgorithm interface {
	Algorithm() string
	Create(data []byte) ([]byte, error)
	Verify(data []byte, digest []byte) error
}

// CryptoError errors during Create/Verify signature functions
type CryptoError struct {
	Message string
	Err     error
}

// Error error message
func (e *CryptoError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("CryptoError: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("CryptoError: %s", e.Message)
}

func digestHashAlgorithmVerify(newHash func() hash.Hash, data []byte, digest []byte) error {
	expected, err := digestHashAlgorithmCreate(newHash, data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &CryptoError{"wrong hash", nil}
	}
	return nil
}

func digestHashAlgorithmCreate(newHash func() hash.Hash, data []byte) ([]byte, error) {
	h := newHash()
	_, err := h.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating hash", err}
	}
	return h.Sum(nil), nil
}
