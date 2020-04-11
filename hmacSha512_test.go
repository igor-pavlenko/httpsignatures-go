package httpsignatures

import (
	"encoding/base64"
	"testing"
)

func TestHmacSha512Algorithm(t *testing.T) {
	a := HmacSha512{}
	got := a.Algorithm()
	want := "HMAC-SHA512"
	if got != want {
		t.Errorf("got = %s\nwant = %s", got, want)
	}
}

func TestHmacSha512Create(t *testing.T) {
	type args struct {
		data   []byte
		secret Secret
	}
	tests := []struct {
		name       string
		args       args
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "HMAC-SHA512 create ok",
			args: args{
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha512,
				},
			},
			want:       "xhrfZlhd8heV7O4w1nPbNRYdWSc2Qg8RuruZ5jDDHbVzSgd4NQOePJWN5xIKz74U/HhlLe138G8VLcH5atTZTg==",
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "HMAC-SHA512 no private key found",
			args: args{
				data:   []byte{},
				secret: Secret{},
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: "no private key found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := HmacSha512{}
			got, err := a.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			assertCrypto(t, sig, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func TestHmacSha512Verify(t *testing.T) {
	type args struct {
		sig    string
		data   []byte
		secret Secret
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "HMAC-SHA512 verify ok",
			args: args{
				sig:  "xhrfZlhd8heV7O4w1nPbNRYdWSc2Qg8RuruZ5jDDHbVzSgd4NQOePJWN5xIKz74U/HhlLe138G8VLcH5atTZTg==",
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha512,
				},
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "HMAC-SHA512 wrong signature",
			args: args{
				sig:  "MTIz",
				data: []byte("xx"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha512,
				},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "wrong signature",
		},
		{
			name: "HMAC-SHA512 no private key found",
			args: args{
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "no private key found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := HmacSha512{}
			sig, _ := base64.StdEncoding.DecodeString(tt.args.sig)
			err := a.Verify(tt.args.secret, tt.args.data, sig)
			got := err == nil
			assertCrypto(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}
