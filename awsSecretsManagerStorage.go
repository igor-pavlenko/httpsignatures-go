package httpsignatures

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/muesli/cache2go"
	"time"
)

// GetSecretValue function construct SecretId in aws secrets manager based on keyType (PrivateKey/PublicKey) & keyID
type GetSecretID = func(env string, keyType string, keyID string, requiredPrivateKeys map[string]bool) (string, error)

// GetSecretValue function convert value from secrets manager to Secret
type GetSecretValue = func(keyType string, value []byte, secret *Secret) error

// AwsSecretsManagerStorage AWS Secrets Manager storage
type AwsSecretsManagerStorage struct {
	env                 string
	storage             *cache2go.CacheTable
	defaultExpiresSec   uint32
	sm                  secretsmanageriface.SecretsManagerAPI
	getSecretID         GetSecretID
	getSecretValue      GetSecretValue
	requiredPrivateKeys map[string]bool
}

const privateKey = "PrivateKey"
const publicKey = "PublicKey"
const algorithm = "Algorithm"
const defaultCacheExpiresSec = 86400 // 24 Hours

// Default key format: /<env>/<keyID>/<keyType>
// Example: /prod/merchant/PrivateKey | /prod/merchant/publicKey
var defGetSecretID GetSecretID = func(env string, keyID string, keyType string, requiredPrivateKeys map[string]bool) (string, error) {
	var smKeyID string
	switch keyType {
	case publicKey:
		smKeyID = fmt.Sprintf("/%s/%s/%s", env, keyID, keyType)
	case algorithm:
		smKeyID = fmt.Sprintf("/%s/%s/%s", env, keyID, keyType)
	case privateKey:
		// Skip private key in case:
		// - key not in the list (requiredPrivateKeys)
		// - key is set as not required (requiredPrivateKeys[keyID] == false)
		// In case of empty requiredPrivateKeys list — privateKey is always required
		req, ok := requiredPrivateKeys[keyID]
		if len(requiredPrivateKeys) > 0 && (!ok || !req) {
			return "", nil
		}
		smKeyID = fmt.Sprintf("/%s/%s/%s", env, keyID, keyType)
	default:
		return "", &ErrSecret{
			fmt.Sprintf("unknown keyType '%s' for aws secrets manager", keyType),
			nil,
		}
	}
	return smKeyID, nil
}

var defGetSecretValue GetSecretValue = func(keyType string, value []byte, secret *Secret) error {
	switch keyType {
	case publicKey:
		secret.PublicKey = string(value)
	case algorithm:
		secret.Algorithm = string(value)
	case privateKey:
		secret.PrivateKey = string(value)
	default:
		return &ErrSecret{
			fmt.Sprintf("unknown keyType '%s' for aws secrets manager", keyType),
			nil,
		}
	}
	return nil
}

// NewAwsSecretsManagerStorage create storage
func NewAwsSecretsManagerStorage(env string, sm secretsmanageriface.SecretsManagerAPI) *AwsSecretsManagerStorage {
	s := new(AwsSecretsManagerStorage)
	s.env = env
	s.storage = cache2go.Cache("AwsSecretsManagerStorage")
	s.defaultExpiresSec = defaultCacheExpiresSec
	s.sm = sm
	s.getSecretID = defGetSecretID
	s.getSecretValue = defGetSecretValue
	s.requiredPrivateKeys = make(map[string]bool)

	return s
}

// SetCacheExpiresSeconds set default cache expires seconds.
func (s *AwsSecretsManagerStorage) SetCacheExpiresSeconds(e uint32) {
	s.defaultExpiresSec = e
}

// SetGetSecretID set custom function to build secret ID in AWS SecretsManager.
func (s *AwsSecretsManagerStorage) SetGetSecretID(f GetSecretID) {
	if f != nil {
		s.getSecretID = f
	}
}

// SetGetSecretValue set custom function to extract value from secret.
func (s *AwsSecretsManagerStorage) SetGetSecretValue(f GetSecretValue) {
	if f != nil {
		s.getSecretValue = f
	}
}

// SetRequiredPrivateKeys set keys with required PrivateKey secrets.
func (s *AwsSecretsManagerStorage) SetRequiredPrivateKeys(l map[string]bool) {
	if l == nil {
		l = make(map[string]bool)
	}
	s.requiredPrivateKeys = l
}

// Get get secret from cache by KeyID or from AWS Secrets Manager for first time
func (s AwsSecretsManagerStorage) Get(keyID string) (Secret, error) {
	secret, err := s.storage.Value(keyID)
	if err == nil {
		return secret.Data().(Secret), nil
	}
	secretVal, err := s.getSecret(keyID)
	if err != nil {
		return Secret{}, &ErrSecret{"secret not found", err}
	}
	s.storage.Add(keyID, 5*time.Second, *secretVal)

	return *secretVal, nil
}

// Use cases:
// 1) Service used to validate incoming requests from many other services
// 2) Service used to sign outgoing requests (signed by itself)
// 3) Service used to sign outgoing requests on behalf of other services
func (s AwsSecretsManagerStorage) getSecret(keyID string) (*Secret, error) {
	secret := &Secret{}
	keys := []string{publicKey, algorithm, privateKey}
	outputs := make(map[string][]byte)
	for _, keyType := range keys {
		smKeyID, err := s.getSecretID(s.env, keyID, keyType, s.requiredPrivateKeys)
		if err != nil {
			return nil, &ErrSecret{
				fmt.Sprintf("error get secretID for keyType '%s', keyID '%s'", keyType, keyID),
				err,
			}
		}
		// Skip secret
		if smKeyID == "" {
			continue
		}
		secret.KeyID = keyID
		output, ok := outputs[smKeyID]
		if !ok {
			output, err = s.getSMSecret(smKeyID)
			if err != nil {
				return nil, &ErrSecret{
					fmt.Sprintf("error get secret value '%s'", secret.KeyID),
					err,
				}
			}
			outputs[smKeyID] = output
		}
		err = s.getSecretValue(keyType, output, secret)
		if err != nil {
			return nil, &ErrSecret{
				fmt.Sprintf("error extract secret value '%s'", secret.KeyID),
				err,
			}
		}
	}

	return secret, nil
}

func (s AwsSecretsManagerStorage) getSMSecret(smKeyID string) ([]byte, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(smKeyID),
	}
	smOutput, err := s.sm.GetSecretValue(input)
	if err != nil {
		return nil, &ErrSecret{
			fmt.Sprintf("error get secret value '%s'", smKeyID),
			err,
		}
	}
	return smOutput.SecretBinary, nil
}