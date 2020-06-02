package httpsignatures

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
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

func signatureHashAlgorithmVerify(newHash func() hash.Hash, secret Secret, data []byte, signature []byte) error {
	expected, err := signatureHashAlgorithmCreate(newHash, secret, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expected) {
		return &CryptoError{"wrong signature", nil}
	}
	return nil
}

func signatureHashAlgorithmCreate(newHash func() hash.Hash, secret Secret, data []byte) ([]byte, error) {
	if len(secret.PrivateKey) == 0 {
		return nil, &CryptoError{"no private key found", nil}
	}
	mac := hmac.New(newHash, []byte(secret.PrivateKey))
	_, err := mac.Write(data)
	if err != nil {
		return nil, &CryptoError{"error creating signature", err}
	}
	return mac.Sum(nil), nil
}

func signatureRsaAlgorithmVerify(t string, newHash func() hash.Hash, hash crypto.Hash, secret Secret, data []byte,
	signature []byte) error {
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

	h := newHash()
	_, _ = h.Write(data)
	if t == algoRsaSha256 || t == algoRsaSha512 {
		err = rsa.VerifyPKCS1v15(publicKey, hash, h.Sum(nil), signature)
	} else if t == algoRsaSsaPssSha256 || t == algoRsaSsaPssSha512 {
		var opts rsa.PSSOptions
		opts.SaltLength = rsa.PSSSaltLengthEqualsHash
		err = rsa.VerifyPSS(publicKey, hash, h.Sum(nil), signature, &opts)
	} else {
		return &CryptoError{fmt.Sprintf("unsupported verify algorithm type %s", t), err}
	}
	if err != nil {
		return &CryptoError{"error verify signature", err}
	}
	return nil
}

func signatureRsaAlgorithmCreate(t string, newHash func() hash.Hash, hash crypto.Hash, secret Secret,
	data []byte) ([]byte, error) {
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

	h := newHash()
	_, _ = h.Write(data)
	if t == algoRsaSha256 || t == algoRsaSha512 {
		return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, h.Sum(nil))
	} else if t == algoRsaSsaPssSha256 || t == algoRsaSsaPssSha512 {
		var opts rsa.PSSOptions
		opts.SaltLength = rsa.PSSSaltLengthEqualsHash
		return rsa.SignPSS(rand.Reader, privateKey, hash, h.Sum(nil), &opts)
	}
	return nil, &CryptoError{fmt.Sprintf("unsupported algorithm type %s", t), err}
}
