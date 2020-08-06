package main

import (
	"fmt"
	"github.com/igor-pavlenko/httpsignatures.go"
	"io/ioutil"
	"os"
	"regexp"
)

// To create your own secrets storage implement the httpsignatures.Secrets interface
// type Secrets interface {
//	   Get(keyID string) (Secret, error)
// }

const alg = "RSA-SHA512"

// FileSecretsStorage local files secrets storage
type FileSecretsStorage struct {
	dir     string
	storage map[string]httpsignatures.Secret
}

// Get get secret from local files by KeyID
func (s FileSecretsStorage) Get(keyID string) (httpsignatures.Secret, error) {
	if secret, ok := s.storage[keyID]; ok {
		return secret, nil
	}

	validKeyID, err := regexp.Match(`[a-zA-Z0-9]+`, []byte(keyID))
	if !validKeyID {
		return httpsignatures.Secret{}, &httpsignatures.ErrSecret{Message: "wrong keyID format allowed: [a-zA-Z0-9]+"}
	}

	publicKeyFile := fmt.Sprintf("%s/%s.pub", s.dir, keyID)
	publicKey, err := s.readFile(publicKeyFile)
	if err != nil {
		return httpsignatures.Secret{}, &httpsignatures.ErrSecret{Message: "public key file not found", Err: err}
	}

	privateKeyFile := fmt.Sprintf("%s/%s.key", s.dir, keyID)
	privateKey, err := s.readFile(privateKeyFile)
	if err != nil {
		return httpsignatures.Secret{}, &httpsignatures.ErrSecret{Message: "private key file not found", Err: err}
	}

	fmt.Println(privateKey, publicKey)
	s.storage[keyID] = httpsignatures.Secret{
		KeyID:      keyID,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Algorithm:  alg,
	}
	return s.storage[keyID], nil
}

// Get key from file
func (s FileSecretsStorage) readFile(f string) (string, error) {
	if !s.fileExists(f) {
		return "", &httpsignatures.ErrSecret{Message: fmt.Sprintf("file '%s' not found", f)}
	}
	key, err := ioutil.ReadFile(f)
	if err != nil {
		return "", &httpsignatures.ErrSecret{Message: fmt.Sprintf("read file error: '%s'", f), Err: err}
	}

	return string(key), nil
}

// Check if file exists
func (s FileSecretsStorage) fileExists(f string) bool {
	i, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !i.IsDir()
}

// NewFileSecretsStorage create new storage
func NewFileSecretsStorage(dir string) httpsignatures.Secrets {
	if len(dir) == 0 {
		return nil
	}
	s := new(FileSecretsStorage)
	s.dir = dir
	s.storage = make(map[string]httpsignatures.Secret)
	return s
}

func main() {
	hs := httpsignatures.NewHTTPSignatures(NewFileSecretsStorage("/tmp"))
	hs.SetDefaultExpiresSeconds(10)
}
