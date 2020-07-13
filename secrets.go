package httpsignatures

import "fmt"

// ErrSecret errors during retrieving secret
type ErrSecret struct {
	Message string
	Err     error
}

// ErrHS error message
func (e *ErrSecret) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("ErrSecret: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("ErrSecret: %s", e.Message)
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
