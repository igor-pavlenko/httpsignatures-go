package httpsignatures

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/muesli/cache2go"
)

// GetSecretValue function construct SecretId in aws secrets manager based on keyType (PrivateKey/PublicKey) & keyID
type GetSecretID = func(keyType string, keyID string, requiredPrivateKeys map[string]bool) (*secretsmanager.GetSecretValueInput, error)

// GetSecretValue function convert *secretsmanager.GetSecretValueOutput to Secret
type GetSecretValue = func(sv *secretsmanager.GetSecretValueOutput, secret *Secret, keyType string) error

// AwsSecretsManagerStorage AWS Secrets Manager storage
type AwsSecretsManagerStorage struct {
	storage             *cache2go.CacheTable
	cfg                 *aws.Config
	getSecretID         GetSecretID
	getSecretValue      GetSecretValue
	requiredPrivateKeys map[string]bool
}

const privateKey = "PrivateKey"
const publicKey = "PublicKey"
const algorithm = "Algorithm"

var defGetSecretID GetSecretID = func(keyType string, keyID string, requiredPrivateKeys map[string]bool) (*secretsmanager.GetSecretValueInput, error) {
	var smKeyID string
	switch keyType {
	case publicKey:
		smKeyID = fmt.Sprintf("/%s/%s", keyType, keyID)
	case algorithm:
		smKeyID = fmt.Sprintf("/%s/%s", keyType, keyID)
	case privateKey:
		// Skip private key in case:
		// - key not in the list (requiredPrivateKeys)
		// - key is set as not required (requiredPrivateKeys[keyID] == false)
		// In case of empty requiredPrivateKeys list — privateKey is always required
		req, ok := requiredPrivateKeys[keyID]
		if len(requiredPrivateKeys) > 0 && (!ok || !req) {
			return nil, nil
		}
		smKeyID = fmt.Sprintf("/%s/%s", keyType, keyID)
	default:
		return nil, &ErrSecret{
			fmt.Sprintf("unknown keyType '%s' for aws secrets manager", keyType),
			nil,
		}
	}
	return &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(smKeyID),
	}, nil
}

var defGetSecretValue GetSecretValue = func(sv *secretsmanager.GetSecretValueOutput, secret *Secret, keyType string) error {
	return nil
}

// NewAwsSecretsManagerStorage create storage
func NewAwsSecretsManagerStorage(
	cfg *aws.Config,
	getSecretID GetSecretID,
	getSecretValue GetSecretValue,
	requiredPrivateKeys map[string]bool) Secrets {
	s := new(AwsSecretsManagerStorage)
	s.storage = cache2go.Cache("AwsSecretsManagerStorage")
	s.cfg = cfg
	if getSecretID == nil {
		s.getSecretID = defGetSecretID
	} else {
		s.getSecretID = getSecretID
	}
	if getSecretValue == nil {
		s.getSecretValue = defGetSecretValue
	} else {
		s.getSecretValue = getSecretValue
	}
	if requiredPrivateKeys == nil {
		s.requiredPrivateKeys = make(map[string]bool)
	}

	return s
}

// Get get secret from cache by KeyID or from AWS Secrets Manager for first time
func (s AwsSecretsManagerStorage) Get(keyID string) (Secret, error) {
	secret, err := s.storage.Value(keyID)
	if err == nil {
		return secret.Data().(Secret), nil
	}
	_, _ = s.getSecret("")

	return Secret{}, &ErrSecret{"secret not found", nil}
}

func (s AwsSecretsManagerStorage) getSecret(keyID string) (*Secret, error) {
	sess, err := session.NewSession(s.cfg)
	if err != nil {
		return nil, &ErrSecret{"error aws new session", err}
	}

	sm := secretsmanager.New(sess)

	secret := &Secret{}

	// Use cases:
	// 1) Service used to validate incoming requests from many other services
	// 2) Service used to sign outgoing requests (signed by itself)
	// 3) Service used to sign outgoing requests on behalf of other services
	keys := []string{publicKey, algorithm, privateKey}
	outputs := make(map[string]*secretsmanager.GetSecretValueOutput)
	for _, k := range keys {
		input, err := s.getSecretID(k, keyID, s.requiredPrivateKeys)
		// Skip secret
		if input == nil {
			continue
		}
		if err != nil {
			return nil, &ErrSecret{
				fmt.Sprintf("error get secretID for keyType '%s', keyID '%s'", k, keyID),
				err,
			}
		}
		output, ok := outputs[*input.SecretId]
		if !ok {
			output, err = sm.GetSecretValue(input)
			if err != nil {
				return nil, &ErrSecret{
					fmt.Sprintf("error get secret value '%s'", *input.SecretId),
					err,
				}
			}
			outputs[*input.SecretId] = output
		}
		err = s.getSecretValue(output, secret, k)
		if err != nil {
			return nil, &ErrSecret{
				fmt.Sprintf("error extract secret value '%s'", *input.SecretId),
				err,
			}
		}
	}

	return secret, nil
}
