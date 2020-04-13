package httpsignatures

import (
	"crypto/hmac"
	"crypto/sha256"
)

const algoHmacSha256 = "HMAC-SHA256"

// HmacSha256 HMAC-SHA256 Algorithm
type HmacSha256 struct{}

// Algorithm Return algorithm name
func (a HmacSha256) Algorithm() string {
	return algoHmacSha256
}

// Create Create signature using passed privateKey from secret
func (a HmacSha256) Create(secret Secret, data []byte) ([]byte, error) {
	if len(secret.PrivateKey) == 0 {
		return nil, &CryptoError{"no private key found", nil}
	}
	mac := hmac.New(sha256.New, []byte(secret.PrivateKey))
	_, err := mac.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating signature", err}
	}
	return mac.Sum(nil), nil
}

// Verify Verify signature using passed privateKey from secret
func (a HmacSha256) Verify(secret Secret, data []byte, signature []byte) error {
	expected, err := a.Create(secret, data)
	if err != nil {
		return err
	}
	if hmac.Equal(signature, expected) == false {
		return &CryptoError{"wrong signature", nil}
	}
	return nil
}
