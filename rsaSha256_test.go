package httpsignatures

import (
	"encoding/base64"
	"testing"
)

const rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`
const rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

func TestRsaSha256Algorithm(t *testing.T) {
	a := RsaSha256{}
	got := a.Algorithm()
	want := "RSA-SHA256"
	if got != want {
		t.Errorf("got = %s\nwant = %s", got, want)
	}
}

func TestRsaSha256Create(t *testing.T) {
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
			name: "RSA-SHA256 create ok",
			args: args{
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: example.com\n" +
						"date: Sun, 05 Jan 2014 21:31:40 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: rsaPrivateKey,
					PublicKey:  rsaPublicKey,
					Algorithm:  algoRsaSha256,
				},
			},
			want:       "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "RSA-SHA256 no private key found",
			args: args{
				data:   []byte{},
				secret: Secret{},
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: "no private key found",
		},
		{
			name: "RSA-SHA256 unsupported key type",
			args: args{
				data: []byte{},
				secret: Secret{
					PrivateKey: `-----BEGIN SSH PRIVATE KEY-----
-----END SSH PRIVATE KEY-----`,
				},
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: "unsupported key type SSH PRIVATE KEY",
		},
		{
			name: "RSA-SHA256 error ParsePKCS1PrivateKey",
			args: args{
				data: []byte{},
				secret: Secret{
					PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END RSA PRIVATE KEY-----`,
				},
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: "error ParsePKCS1PrivateKey: asn1: syntax error: data truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := RsaSha256{}
			got, err := a.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			assertCrypto(t, sig, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func TestRsaSha256Verify(t *testing.T) {
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
			name: "RSA-SHA256 verify ok",
			args: args{
				sig: "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: example.com\n" +
						"date: Sun, 05 Jan 2014 21:31:40 GMT",
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: rsaPrivateKey,
					PublicKey:  rsaPublicKey,
					Algorithm:  algoRsaSha256,
				},
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "RSA-SHA256 wrong signature",
			args: args{
				sig:  "MTIz",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key3",
					PrivateKey: rsaPrivateKey,
					PublicKey:  rsaPublicKey,
					Algorithm:  algoRsaSha256,
				},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "wrong signature: crypto/rsa: verification error",
		},
		{
			name: "RSA-SHA256 no public key found",
			args: args{
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "no public key found",
		},
		{
			name: "RSA-SHA256 unsupported key type",
			args: args{
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "unsupported key type NO PUBLIC KEY",
		},
		{
			name: "RSA-SHA256 error ParsePKIXPublicKey",
			args: args{
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END PUBLIC KEY-----`,
				},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "error ParsePKIXPublicKey: asn1: syntax error: data truncated",
		}, {
			name: "RSA-SHA256 unknown type of public key",
			args: args{
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo
yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==
-----END PUBLIC KEY-----`,
				},
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "unknown type of public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := RsaSha256{}
			sig, _ := base64.StdEncoding.DecodeString(tt.args.sig)
			err := a.Verify(tt.args.secret, tt.args.data, sig)
			got := err == nil
			assertCrypto(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}
