package httpsignatures

// SecretError errors during retrieving secret
type SecretError struct {
	Message string
	Err     error
}

// Error error message
func (e *SecretError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

// Secrets interface to retrieve secrets from storage (local, DB, file etc)
type Secrets interface {
	Get(keyID string) (Secret, error)
}

// Secret struct to return/store secret
type Secret struct {
	KeyID      string
	PrivateKey string
	Algorithm  string
}

// SecretsStorage local static secrets storage
type SecretsStorage struct {
	storage map[string]Secret
}

// NewSecretsStorage create new digest
func NewSecretsStorage(storage map[string]Secret) *SecretsStorage {
	s := new(SecretsStorage)
	s.storage = storage
	return s
}

// Get get secret from local storage by KeyID
func (s SecretsStorage) Get(keyID string) (Secret, error) {
	if secret, ok := s.storage[keyID]; ok {
		return secret, nil
	}
	return Secret{}, &SecretError{"secret not found", nil}
}
