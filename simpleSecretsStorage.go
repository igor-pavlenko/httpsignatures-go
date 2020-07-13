package httpsignatures

// SimpleSecretsStorage local static secrets storage
type SimpleSecretsStorage struct {
	storage map[string]Secret
}

// NewSimpleSecretsStorage create new digest
func NewSimpleSecretsStorage(storage map[string]Secret) Secrets {
	s := new(SimpleSecretsStorage)
	s.storage = storage
	return s
}

// Get get secret from local storage by KeyID
func (s SimpleSecretsStorage) Get(keyID string) (Secret, error) {
	if secret, ok := s.storage[keyID]; ok {
		return secret, nil
	}
	return Secret{}, &ErrSecret{"secret not found", nil}
}
