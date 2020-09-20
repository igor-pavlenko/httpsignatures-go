package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/go-test/deep"
	"github.com/igor-pavlenko/httpsignatures.go"
	"github.com/muesli/cache2go"
	"reflect"
	"testing"
)

const testSecretErrType = "*httpsignatures.ErrSecret"

func TestNewAwsSecretsManagerStorage(t *testing.T) {
	type args struct {
		env                 string
		cacheExpiresSec     uint32
		getSecretID         GetSecretID
		getSecretValue      GetSecretValue
		requiredPrivateKeys map[string]bool
	}
	defWant := &AwsSecretsManagerStorage{
		env:                 "",
		storage:             cache2go.Cache("AwsSecretsManagerStorage"),
		sm:                  &secretsmanager.SecretsManager{},
		defaultExpiresSec:   defaultCacheExpiresSec,
		getSecretID:         defGetSecretID,
		getSecretValue:      defGetSecretValue,
		requiredPrivateKeys: make(map[string]bool),
	}
	var testGetSecretID GetSecretID = func(env string, keyID string, keyType string, requiredPrivateKeys map[string]bool) (string, error) {
		return "test", nil
	}
	var testGetSecretValue GetSecretValue = func(keyType string, value []byte, secret *httpsignatures.Secret) error {
		return nil
	}
	tests := []struct {
		name string
		args args
		want *AwsSecretsManagerStorage
	}{
		{
			name: "Create ok with default getSecretID",
			args: args{
				env:             "prod",
				cacheExpiresSec: defaultCacheExpiresSec,
			},
			want: func() *AwsSecretsManagerStorage {
				res := *defWant
				res.env = "prod"
				return &res
			}(),
		},
		{
			name: "Custom requiredPrivateKeys list",
			args: args{
				cacheExpiresSec:     defaultCacheExpiresSec,
				requiredPrivateKeys: map[string]bool{"k1": true},
			},
			want: func() *AwsSecretsManagerStorage {
				res := *defWant
				res.requiredPrivateKeys = map[string]bool{"k1": true}
				return &res
			}(),
		},
		{
			name: "GetSecretID",
			args: args{
				cacheExpiresSec: defaultCacheExpiresSec,
				getSecretID:     testGetSecretID,
			},
			want: func() *AwsSecretsManagerStorage {
				res := *defWant
				return &res
			}(),
		},
		{
			name: "GetSecretValue",
			args: args{
				cacheExpiresSec: defaultCacheExpiresSec,
				getSecretValue:  testGetSecretValue,
			},
			want: func() *AwsSecretsManagerStorage {
				res := *defWant
				return &res
			}(),
		},
	}
	deep.CompareUnexportedFields = true
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAwsSecretsManagerStorage(tt.args.env, &secretsmanager.SecretsManager{})
			got.SetCacheExpiresSeconds(tt.args.cacheExpiresSec)
			got.SetGetSecretID(tt.args.getSecretID)
			got.SetGetSecretValue(tt.args.getSecretValue)
			got.SetRequiredPrivateKeys(tt.args.requiredPrivateKeys)
			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}

func TestDefGetSecretID(t *testing.T) {
	type args struct {
		env                 string
		keyType             string
		keyID               string
		requiredPrivateKeys map[string]bool
	}
	tests := []struct {
		name        string
		args        args
		want        string
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "PrivateKey ok",
			args: args{
				env:     "test",
				keyType: "PrivateKey",
				keyID:   "k1",
			},
			want: "/test/k1/PrivateKey",
		},
		{
			name: "Not required PrivateKey ok",
			args: args{
				env:                 "prod",
				keyType:             "PrivateKey",
				keyID:               "k1",
				requiredPrivateKeys: map[string]bool{"k1": false},
			},
			want: "",
		},
		{
			name: "Required PrivateKey ok",
			args: args{
				env:                 "prod",
				keyType:             "PrivateKey",
				keyID:               "k1",
				requiredPrivateKeys: map[string]bool{"k1": true},
			},
			want: "/prod/k1/PrivateKey",
		},
		{
			name: "PublicKey ok",
			args: args{
				env:     "dev",
				keyType: "PublicKey",
				keyID:   "k1",
			},
			want: "/dev/k1/PublicKey",
		},
		{
			name: "Algorithm ok",
			args: args{
				env:     "prod",
				keyType: "Algorithm",
				keyID:   "k1",
			},
			want: "/prod/k1/Algorithm",
		},
		{
			name: "Unknown key type",
			args: args{
				env:     "prod",
				keyType: "SecretKey",
				keyID:   "k1",
			},
			wantErrType: testSecretErrType,
			wantErrMsg:  "ErrSecret: unknown keyType 'SecretKey' for aws secrets manager",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := defGetSecretID(tt.args.env, tt.args.keyID, tt.args.keyType, tt.args.requiredPrivateKeys)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestDefGetSecretValue(t *testing.T) {
	type args struct {
		keyType string
		value   []byte
	}
	tests := []struct {
		name        string
		args        args
		want        *httpsignatures.Secret
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "PrivateKey ok",
			args: args{
				keyType: "PrivateKey",
				value:   []byte("pk1"),
			},
			want: &httpsignatures.Secret{
				PrivateKey: "pk1",
			},
		},
		{
			name: "PublicKey ok",
			args: args{
				keyType: "PublicKey",
				value:   []byte("pk2"),
			},
			want: &httpsignatures.Secret{
				PublicKey: "pk2",
			},
		},
		{
			name: "Algorithm ok",
			args: args{
				keyType: "Algorithm",
				value:   []byte("a"),
			},
			want: &httpsignatures.Secret{
				Algorithm: "a",
			},
		},
		{
			name: "Unsupported",
			args: args{
				keyType: "Unsupported",
				value:   []byte("v1"),
			},
			want:        &httpsignatures.Secret{},
			wantErrType: testSecretErrType,
			wantErrMsg:  "ErrSecret: unknown keyType 'Unsupported' for aws secrets manager",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &httpsignatures.Secret{}
			err := defGetSecretValue(tt.args.keyType, tt.args.value, secret)
			assert(t, secret, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

type mockSecretsManagerClient struct {
	secretsmanageriface.SecretsManagerAPI
}

func (m *mockSecretsManagerClient) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	if *input.SecretId == "/prod/k1/PublicKey" {
		return &secretsmanager.GetSecretValueOutput{
			SecretBinary: []byte("PublicKey"),
		}, nil
	} else if *input.SecretId == "/prod/k1/Algorithm" {
		return &secretsmanager.GetSecretValueOutput{
			SecretBinary: []byte("Algorithm"),
		}, nil
	} else if *input.SecretId == "/prod/k1/PrivateKey" {
		return &secretsmanager.GetSecretValueOutput{
			SecretBinary: []byte("PrivateKey"),
		}, nil
	}
	return nil, fmt.Errorf("error")
}

func TestAwsSecretsManagerStorageGetSecret(t *testing.T) {
	type args struct {
		keyID               string
		getSecretID         GetSecretID
		getSecretValue      GetSecretValue
		requiredPrivateKeys map[string]bool
	}
	tests := []struct {
		name        string
		args        args
		want        *httpsignatures.Secret
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Ok",
			args: args{
				keyID: "k1",
			},
			want: &httpsignatures.Secret{
				KeyID:      "k1",
				PublicKey:  "PublicKey",
				PrivateKey: "PrivateKey",
				Algorithm:  "Algorithm",
			},
		},
		{
			name: "GetSecretID error",
			args: args{
				keyID: "k1",
				getSecretID: func(env string, keyID string, keyType string, requiredPrivateKeys map[string]bool) (string, error) {
					return "", fmt.Errorf("getSecretID error")
				},
			},
			want:        nil,
			wantErrMsg:  "ErrSecret: error get secretID for keyType 'PublicKey', keyID 'k1': getSecretID error",
			wantErrType: testSecretErrType,
		},
		{
			name: "getSMSecret error",
			args: args{
				keyID: "k2",
			},
			want:        nil,
			wantErrMsg:  "ErrSecret: error get secret value 'k2': ErrSecret: error get secret value '/prod/k2/PublicKey': error",
			wantErrType: testSecretErrType,
		},
		{
			name: "GetSecretValue error",
			args: args{
				keyID: "k1",
				getSecretValue: func(keyType string, value []byte, secret *httpsignatures.Secret) error {
					return fmt.Errorf("getSecretValue error")
				},
			},
			want:        nil,
			wantErrMsg:  "ErrSecret: error extract secret value 'k1': getSecretValue error",
			wantErrType: testSecretErrType,
		},
		{
			name: "Continue",
			args: args{
				keyID:               "k1",
				requiredPrivateKeys: map[string]bool{"k1": false},
			},
			want: &httpsignatures.Secret{
				KeyID:     "k1",
				PublicKey: "PublicKey",
				Algorithm: "Algorithm",
			},
		},
	}

	mockSvc := &mockSecretsManagerClient{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewAwsSecretsManagerStorage("prod", mockSvc)
			sm.SetGetSecretID(tt.args.getSecretID)
			sm.SetGetSecretValue(tt.args.getSecretValue)
			sm.SetRequiredPrivateKeys(tt.args.requiredPrivateKeys)
			got, err := sm.getSecret(tt.args.keyID)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestAwsSecretsManagerStorageGetSMSecret(t *testing.T) {
	type args struct {
		smKeyID string
	}
	tests := []struct {
		name        string
		args        args
		want        []byte
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Ok",
			args: args{
				smKeyID: "/prod/k1/PublicKey",
			},
			want: []byte("PublicKey"),
		},
		{
			name: "Error",
			args: args{
				smKeyID: "/prod/k2/PrivateKey",
			},
			wantErrType: testSecretErrType,
			wantErrMsg:  "ErrSecret: error get secret value '/prod/k2/PrivateKey': error",
		},
	}

	mockSvc := &mockSecretsManagerClient{}
	sm := NewAwsSecretsManagerStorage("prod", mockSvc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sm.getSMSecret(tt.args.smKeyID)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestAwsSecretsManagerStorageGet(t *testing.T) {
	type args struct {
		keyID string
	}
	tests := []struct {
		name        string
		args        args
		want        httpsignatures.Secret
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Ok",
			args: args{
				keyID: "k1",
			},
			want: httpsignatures.Secret{
				KeyID:      "k1",
				PublicKey:  "PublicKey",
				PrivateKey: "PrivateKey",
				Algorithm:  "Algorithm",
			},
		},
		{
			name: "From cache",
			args: args{
				keyID: "k1",
			},
			want: httpsignatures.Secret{
				KeyID:      "k1",
				PublicKey:  "PublicKey",
				PrivateKey: "PrivateKey",
				Algorithm:  "Algorithm",
			},
		},
		{
			name: "Not found",
			args: args{
				keyID: "k2",
			},
			want:        httpsignatures.Secret{},
			wantErrType: testSecretErrType,
			wantErrMsg: "ErrSecret: secret not found: ErrSecret: error get secret value 'k2': ErrSecret: error get " +
				"secret value '/prod/k2/PublicKey': error",
		},
	}

	mockSvc := &mockSecretsManagerClient{}
	sm := NewAwsSecretsManagerStorage("prod", mockSvc)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sm.Get(tt.args.keyID)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func assert(t *testing.T, got interface{}, err error, eType string, name string, want interface{}, wantErrMsg string) {
	if err != nil && reflect.TypeOf(err).String() != eType {
		t.Errorf(name+"\ngot error type %s, expected %s", reflect.TypeOf(err).String(), eType)
	}
	if err != nil && err.Error() != wantErrMsg {
		t.Errorf(name+"\nerror message = `%s`, wantErrMsg = `%s`", err.Error(), wantErrMsg)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(name+"\ngot  = %v,\nwant = %v", got, want)
	}
}