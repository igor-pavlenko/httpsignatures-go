package httpsignatures

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"testing"
)

func TestNewAwsSecretsManagerStorage(t *testing.T) {
	type args struct {
		cfg                 *aws.Config
		getSecretID         GetSecretID
		getSecretValue      GetSecretValue
		requiredPrivateKeys map[string]bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Create ok with default getSecretID",
			args: args{
				cfg:                 nil,
				getSecretID:         nil,
				getSecretValue:      nil,
				requiredPrivateKeys: nil,
			},
		},
		{
			name: "Create ok with custom getSecretID",
			args: args{
				cfg:                 nil,
				getSecretID:         defGetSecretID,
				getSecretValue:      nil,
				requiredPrivateKeys: nil,
			},
		},
		{
			name: "Create ok with custom getSecretValue",
			args: args{
				cfg:                 nil,
				getSecretID:         nil,
				getSecretValue:      defGetSecretValue,
				requiredPrivateKeys: nil,
			},
		},
		{
			name: "Create ok with custom requiredPrivateKeys list",
			args: args{
				cfg:                 nil,
				getSecretID:         nil,
				getSecretValue:      defGetSecretValue,
				requiredPrivateKeys: map[string]bool{"k1": true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAwsSecretsManagerStorage(tt.args.cfg, tt.args.getSecretID, tt.args.getSecretValue,
				tt.args.requiredPrivateKeys)
			switch got.(type) {
			case Secrets:
				break
			default:
				t.Error("unknown type")
			}
		})
	}
}

func TestDefGetSecretID(t *testing.T) {
	type args struct {
		keyType             string
		keyID               string
		requiredPrivateKeys map[string]bool
	}
	tests := []struct {
		name        string
		args        args
		want        *secretsmanager.GetSecretValueInput
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "PrivateKey ok",
			args: args{
				keyType: "PrivateKey",
				keyID:   "k1",
			},
			want: &secretsmanager.GetSecretValueInput{
				SecretId: aws.String("/PrivateKey/k1"),
			},
		},
		{
			name: "Not required PrivateKey ok",
			args: args{
				keyType:             "PrivateKey",
				keyID:               "k1",
				requiredPrivateKeys: map[string]bool{"k1": false},
			},
			want: nil,
		},
		{
			name: "Required PrivateKey ok",
			args: args{
				keyType:             "PrivateKey",
				keyID:               "k1",
				requiredPrivateKeys: map[string]bool{"k1": true},
			},
			want: &secretsmanager.GetSecretValueInput{
				SecretId: aws.String("/PrivateKey/k1"),
			},
		},
		{
			name: "PublicKey ok",
			args: args{
				keyType: "PublicKey",
				keyID:   "k1",
			},
			want: &secretsmanager.GetSecretValueInput{
				SecretId: aws.String("/PublicKey/k1"),
			},
		},
		{
			name: "Algorithm ok",
			args: args{
				keyType: "Algorithm",
				keyID:   "k1",
			},
			want: &secretsmanager.GetSecretValueInput{
				SecretId: aws.String("/Algorithm/k1"),
			},
		},
		{
			name: "Unknown key type",
			args: args{
				keyType: "SecretKey",
				keyID:   "k1",
			},
			wantErrType: testSecretErrType,
			wantErrMsg:  "ErrSecret: unknown keyType 'SecretKey' for aws secrets manager",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := defGetSecretID(tt.args.keyType, tt.args.keyID, tt.args.requiredPrivateKeys)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}
