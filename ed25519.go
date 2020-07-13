package httpsignatures

import (
	"crypto/ed25519"
	"encoding/asn1"
	"encoding/pem"
)

const algED25519 = "ED25519"

// ED25519 ED25519 Algorithm
type ED25519 struct{}

// Algorithm Return algorithm name
func (a ED25519) Algorithm() string {
	return algED25519
}

// Create Create signature using passed privateKey from secret
func (a ED25519) Create(secret Secret, data []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(secret.PrivateKey))
	if block == nil {
		return nil, &ErrCrypto{"no private key found", nil}
	}

	var asn1PrivateKey ED25519PrivateKey
	_, err := asn1.Unmarshal(block.Bytes, &asn1PrivateKey)
	if err != nil {
		return nil, &ErrCrypto{"error unmarshal private key", err}
	}

	privateKey := ed25519.NewKeyFromSeed(asn1PrivateKey.PrivateKey[2:])
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, &ErrCrypto{"invalid private key size", nil}
	}

	return ed25519.Sign(privateKey, data), nil
}

// Verify Verify signature using passed publicKey from secret
func (a ED25519) Verify(secret Secret, data []byte, signature []byte) error {
	block, _ := pem.Decode([]byte(secret.PublicKey))
	if block == nil {
		return &ErrCrypto{"no public key found", nil}
	}

	var asn1PublicKey ED25519PublicKey
	_, err := asn1.Unmarshal(block.Bytes, &asn1PublicKey)
	if err != nil {
		return &ErrCrypto{"error unmarshal public key", err}
	}

	publicKey := ed25519.PublicKey(asn1PublicKey.PublicKey.Bytes)
	if len(publicKey) != ed25519.PublicKeySize {
		return &ErrCrypto{"invalid public key size", nil}
	}

	res := ed25519.Verify(publicKey, data, signature)
	if !res {
		return &ErrCrypto{"signature verification error", nil}
	}
	return nil
}
