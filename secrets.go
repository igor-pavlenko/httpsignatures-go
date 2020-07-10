package httpsignatures

import "fmt"

// SecretError errors during retrieving secret
type SecretError struct {
	Message string
	Err     error
}

// Error error message
func (e *SecretError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("SecretError: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("SecretError: %s", e.Message)
}

// Secrets interface to retrieve secrets from storage (local, DB, file etc)
type Secrets interface {
	Get(keyID string) (Secret, error)
}

// Secret struct to return/store secret
type Secret struct {
	KeyID      string
	PublicKey  string
	PrivateKey string
	Algorithm  string
}
