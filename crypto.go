package httpsignatures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
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

// ErrCrypto errors during Create/Verify signature functions
type ErrCrypto struct {
	Message string
	Err     error
}

// ErrHS error message
func (e *ErrCrypto) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("ErrCrypto: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("ErrCrypto: %s", e.Message)
}

// ECDSASignature ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// ED25519PrivateKey ED25519 PrivateKey
type ED25519PrivateKey struct {
	Version          int
	ObjectIdentifier struct {
		ObjectIdentifier asn1.ObjectIdentifier
	}
	PrivateKey []byte
}

// ED25519PublicKey ED25519 PublicKey
type ED25519PublicKey struct {
	ObjectIdentifier struct {
		ObjectIdentifier asn1.ObjectIdentifier
	}
	PublicKey asn1.BitString
}

func digestHashAlgorithmVerify(newHash func() hash.Hash, data []byte, digest []byte) error {
	expected, err := digestHashAlgorithmCreate(newHash, data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &ErrCrypto{"wrong hash", nil}
	}
	return nil
}

func digestHashAlgorithmCreate(newHash func() hash.Hash, data []byte) ([]byte, error) {
	h := newHash()
	_, err := h.Write(data)
	if err != nil {
		return nil, &ErrCrypto{"error creating hash", err}
	}
	return h.Sum(nil), nil
}

func signatureHashAlgorithmVerify(newHash func() hash.Hash, secret Secret, data []byte, signature []byte) error {
	expected, err := signatureHashAlgorithmCreate(newHash, secret, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expected) {
		return &ErrCrypto{"wrong signature", nil}
	}
	return nil
}

func signatureHashAlgorithmCreate(newHash func() hash.Hash, secret Secret, data []byte) ([]byte, error) {
	if len(secret.PrivateKey) == 0 {
		return nil, &ErrCrypto{"no private key found", nil}
	}
	mac := hmac.New(newHash, []byte(secret.PrivateKey))
	_, err := mac.Write(data)
	if err != nil {
		return nil, &ErrCrypto{"error creating signature", err}
	}
	return mac.Sum(nil), nil
}

func signatureRsaAlgorithmVerify(t string, newHash func() hash.Hash, hash crypto.Hash, secret Secret, data []byte,
	signature []byte) error {
	publicKey, err := loadPublicKey(secret.PublicKey)
	if err != nil {
		return err
	}

	var publicKeyRsa *rsa.PublicKey
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		publicKeyRsa = publicKey
	default:
		return &ErrCrypto{"unknown type of public key", nil}
	}

	h := newHash()
	_, _ = h.Write(data)

	switch t {
	case algRsaSha256, algRsaSha512:
		err = rsa.VerifyPKCS1v15(publicKeyRsa, hash, h.Sum(nil), signature)
	case algRsaSsaPssSha256, algRsaSsaPssSha512:
		var opts rsa.PSSOptions
		opts.SaltLength = rsa.PSSSaltLengthEqualsHash
		err = rsa.VerifyPSS(publicKeyRsa, hash, h.Sum(nil), signature, &opts)
	default:
		return &ErrCrypto{fmt.Sprintf("unsupported verify algorithm type %s", t), err}
	}

	if err != nil {
		return &ErrCrypto{"error verify signature", err}
	}
	return nil
}

func signatureRsaAlgorithmCreate(t string, newHash func() hash.Hash, hash crypto.Hash, secret Secret,
	data []byte) ([]byte, error) {
	privateKey, err := loadPrivateKey(secret.PrivateKey)
	if err != nil {
		return nil, err
	}

	var privateKeyRsa *rsa.PrivateKey
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyRsa = privateKey
	default:
		return nil, &ErrCrypto{"unknown private key type", nil}
	}

	h := newHash()
	_, _ = h.Write(data)

	switch t {
	case algRsaSha256, algRsaSha512:
		return rsa.SignPKCS1v15(rand.Reader, privateKeyRsa, hash, h.Sum(nil))
	case algRsaSsaPssSha256, algRsaSsaPssSha512:
		var opts rsa.PSSOptions
		opts.SaltLength = rsa.PSSSaltLengthEqualsHash
		return rsa.SignPSS(rand.Reader, privateKeyRsa, hash, h.Sum(nil), &opts)
	default:
		return nil, &ErrCrypto{fmt.Sprintf("unsupported algorithm type %s", t), err}
	}
}

func signatureEcdsaAlgorithmVerify(t string, newHash func() hash.Hash, secret Secret, data []byte,
	signature []byte) error {
	publicKey, err := loadPublicKey(secret.PublicKey)
	if err != nil {
		return err
	}

	var publicKeyEcdsa *ecdsa.PublicKey
	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		publicKeyEcdsa = publicKey
	default:
		return &ErrCrypto{"unknown type of public key", nil}
	}

	sig := &ECDSASignature{}
	_, err = asn1.Unmarshal(signature, sig)
	if err != nil {
		return &ErrCrypto{"error Unmarshal signature", err}
	}

	h := newHash()
	_, _ = h.Write(data)

	switch t {
	case algEcdsaSha256, algEcdsaSha512:
		res := ecdsa.Verify(publicKeyEcdsa, h.Sum(nil), sig.R, sig.S)
		if !res {
			return &ErrCrypto{"signature verification error", nil}
		}
	default:
		return &ErrCrypto{fmt.Sprintf("unsupported verify algorithm type %s", t), err}
	}

	return nil
}

func signatureEcdsaAlgorithmCreate(t string, newHash func() hash.Hash, secret Secret,
	data []byte) ([]byte, error) {
	privateKey, err := loadPrivateKey(secret.PrivateKey)
	if err != nil {
		return nil, err
	}

	var privateKeyEcdsa *ecdsa.PrivateKey
	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		privateKeyEcdsa = privateKey
	default:
		return nil, &ErrCrypto{"unknown private key type", nil}
	}

	h := newHash()
	_, _ = h.Write(data)

	switch t {
	case algEcdsaSha256, algEcdsaSha512:
		r, s, err := ecdsa.Sign(rand.Reader, privateKeyEcdsa, h.Sum(nil))
		if err != nil {
			return nil, err
		}
		sig, _ := asn1.Marshal(ECDSASignature{
			R: r,
			S: s,
		})
		return sig, nil
	default:
		return nil, &ErrCrypto{fmt.Sprintf("unsupported algorithm type %s", t), err}
	}
}

func loadPrivateKey(pk string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pk))
	if block == nil {
		return nil, &ErrCrypto{"no private key found", nil}
	}

	if privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch privateKey := privateKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return privateKey, nil
		default:
			return nil, &ErrCrypto{"unknown private key type in PKCS#8", nil}
		}
	}

	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}

	if privateKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}

	return nil, &ErrCrypto{fmt.Sprintf("unsupported private key type %s", block.Type), nil}
}

func loadPublicKey(pk string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pk))
	if block == nil {
		return nil, &ErrCrypto{"no public key found", nil}
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, &ErrCrypto{"error ParsePKIXPublicKey", err}
	}
	return pub, nil
}
