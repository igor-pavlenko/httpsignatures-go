package httpsignatures

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const algoRsaSha256 = "RSA-SHA256"

// RsaSha256 RSA-SHA265 Algorithm
type RsaSha256 struct{}

// Algorithm Return algorithm name
func (a RsaSha256) Algorithm() string {
	return algoRsaSha256
}

// Create Create signature using passed privateKey from secret
func (a RsaSha256) Create(secret Secret, data []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(secret.PrivateKey))
	if block == nil {
		return nil, &CryptoError{"no private key found", nil}
	}

	var privateKey *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, &CryptoError{"error ParsePKCS1PrivateKey", err}
		}
	default:
		return nil, &CryptoError{fmt.Sprintf("unsupported key type %s", block.Type), err}
	}

	h := sha256.New()
	_, _ = h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
}

// Verify Verify signature using passed publicKey from secret
func (a RsaSha256) Verify(secret Secret, data []byte, signature []byte) error {
	block, _ := pem.Decode([]byte(secret.PublicKey))
	if block == nil {
		return &CryptoError{"no public key found", nil}
	}

	var pub interface{}
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return &CryptoError{"error ParsePKIXPublicKey", err}
		}
	default:
		return &CryptoError{fmt.Sprintf("unsupported key type %s", block.Type), err}
	}

	var publicKey *rsa.PublicKey
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKey = pub
	default:
		return &CryptoError{"unknown type of public key", nil}
	}

	h := sha256.New()
	_, _ = h.Write(data)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h.Sum(nil), signature)
	if err != nil {
		return &CryptoError{"error verify signature", err}
	}
	return nil
}
