package httpsignatures

import (
	"crypto/hmac"
	"crypto/sha512"
)

const algoHmacSha512 = "HMAC-SHA512"

// HmacSha512 HMAC-SHA512 Algorithm
type HmacSha512 struct{}

// Algorithm Return algorithm name
func (a HmacSha512) Algorithm() string {
	return algoHmacSha512
}

// Create Create signature using passed privateKey from secret
func (a HmacSha512) Create(secret Secret, data []byte) ([]byte, error) {
	if len(secret.PrivateKey) == 0 {
		return nil, &CryptoError{"no private key found", nil}
	}
	mac := hmac.New(sha512.New, []byte(secret.PrivateKey))
	_, err := mac.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating signature", err}
	}
	return mac.Sum(nil), nil
}

// Verify Verify signature using passed privateKey from secret
func (a HmacSha512) Verify(secret Secret, data []byte, signature []byte) error {
	expected, err := a.Create(secret, data)
	if err != nil {
		return err
	}
	if hmac.Equal(signature, expected) == false {
		return &CryptoError{"wrong signature", nil}
	}
	return nil
}
