package httpsignatures

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
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
