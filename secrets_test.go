package httpsignatures

import (
	"errors"
	"reflect"
	"testing"
)

const secretErrType = "*httpsignatures.SecretError"

func TestNewSecretsStorage(t *testing.T) {
	storageExample := map[string]Secret{
		"k1": {
			KeyID:      "k1",
			PublicKey:  "PublicKey1",
			PrivateKey: "PrivateKey1",
			Algorithm:  "md5",
		},
		"k2": {
			KeyID:      "k2",
			PublicKey:  "PublicKey2",
			PrivateKey: "PrivateKey2",
			Algorithm:  "sha1",
		},
	}
	type args struct {
		storage map[string]Secret
	}
	tests := []struct {
		name string
		args args
		want *SecretsStorage
	}{
		{
			name: "Valid NewSecretsStorage",
			args: args{
				storage: storageExample,
			},
			want: (func() *SecretsStorage {
				s := new(SecretsStorage)
				s.storage = storageExample
				return s
			})(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSecretsStorage(tt.args.storage)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf(tt.name+"\ngot  = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}

func TestSecretsStorageGet(t *testing.T) {
	storageExample := map[string]Secret{
		"k1": {
			KeyID:      "k1",
			PublicKey:  "PublicKey1",
			PrivateKey: "PrivateKey1",
			Algorithm:  "md5",
		},
	}
	type args struct {
		keyID string
	}
	tests := []struct {
		name        string
		args        args
		want        Secret
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Valid SecretsStorage Get",
			args: args{
				keyID: "k1",
			},
			want:        storageExample["k1"],
			wantErrType: secretErrType,
			wantErrMsg:  "",
		},
		{
			name: "Key Not Found",
			args: args{
				keyID: "k2",
			},
			want:        Secret{},
			wantErrType: secretErrType,
			wantErrMsg:  "SecretError: secret not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSecretsStorage(storageExample)
			got, err := s.Get(tt.args.keyID)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSecretsError(t *testing.T) {
	err := errors.New("test err")
	e := SecretError{"secret err", err}

	wantErrMsg := "SecretError: secret err: test err"

	if e.Error() != wantErrMsg {
		t.Errorf("error message = `%s`, wantErrMsg = `%s`", e.Error(), wantErrMsg)
	}
}
