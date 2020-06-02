package httpsignatures

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const hsErrType = "*httpsignatures.Error"
const hsBodyExample = `{"hello": "world"}`
const hsHostExample = "https://example.org/foo"
const hsHostExampleFull = "https://example.com/foo?param=value&pet=dog"

func TestNewHttpSignatures(t *testing.T) {
	ss := NewSecretsStorage(map[string]Secret{
		"key1": {
			KeyID:      "key1",
			PrivateKey: "SecretPrivateKey1",
			Algorithm:  "HMAC-SHA-256",
		},
	})
	type args struct {
		ss *SecretsStorage
	}
	tests := []struct {
		name       string
		args       args
		want       *HTTPSignatures
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Valid NewSecretsStorage",
			args: args{
				ss: ss,
			},
			want: (func() *HTTPSignatures {
				hs := new(HTTPSignatures)
				hs.ss = ss
				hs.d = NewDigest()
				return hs
			})(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewHTTPSignatures(tt.args.ss)
			if reflect.TypeOf(got).String() != "*httpsignatures.HTTPSignatures" {
				t.Errorf(tt.name+"\ngot wrong type: got=%s", reflect.TypeOf(got).String())
			}
		})
	}
}

func TestBuildSignatureString(t *testing.T) {
	ss := NewSecretsStorage(map[string]Secret{})
	type args struct {
		ph Headers
		r  *http.Request
	}
	tests := []struct {
		name        string
		args        args
		want        []byte
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Valid signature string",
			args: args{
				ph: Headers{
					algorithm: "md5",
					headers: []string{
						"(request-target)",
						"(created)",
						"(expires)",
						"host",
						"date",
						"digest",
						"content-length",
					},
					created: time.Unix(1402170695, 0),
					expires: time.Unix(1402170995, 0),
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, hsHostExample, strings.NewReader(hsBodyExample))
					r.Header.Set("Host", "example.org")
					r.Header.Set("Date", "Tue, 07 Jun 2014 20:51:35 GMT")
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					r.Header.Set("Content-Length", "18")
					return r
				})(),
			},
			want: []byte("(request-target): post /foo\n" +
				"(created): 1402170695\n" +
				"(expires): 1402170995\n" +
				"host: example.org\n" +
				"date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
				"digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\n" +
				"content-length: 18"),
			wantErrType: hsErrType,
			wantErrMsg:  "",
		},
		{
			name: "Has created header with 0 value",
			args: args{
				ph: Headers{
					algorithm: "md5",
					headers: []string{
						"(created)",
					},
					created: time.Unix(0, 0),
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, hsHostExample, strings.NewReader(hsBodyExample))
					return r
				})(),
			},
			want:        nil,
			wantErrType: hsErrType,
			wantErrMsg:  "param '(created)', required in signature, not found",
		},
		{
			name: "Has expires header with 0 value",
			args: args{
				ph: Headers{
					algorithm: "sha-256",
					headers: []string{
						"(expires)",
					},
					expires: time.Unix(0, 0),
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, hsHostExample, strings.NewReader(hsBodyExample))
					return r
				})(),
			},
			want:        nil,
			wantErrType: hsErrType,
			wantErrMsg:  "param '(expires)', required in signature, not found",
		},
		{
			name: "Header with 0 length",
			args: args{
				ph: Headers{
					algorithm: "md5",
					headers: []string{
						"host",
						"digest",
					},
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, hsHostExample, strings.NewReader(hsBodyExample))
					r.Header.Set("Host", "example.org")
					r.Header.Set("Digest", "")
					return r
				})(),
			},
			want: []byte(
				"host: example.org\n" +
					"digest: "),
			wantErrType: hsErrType,
			wantErrMsg:  "",
		},
		{
			name: "Header not found",
			args: args{
				ph: Headers{
					algorithm: "md5",
					headers: []string{
						"host",
						"digest",
					},
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, hsHostExample, strings.NewReader(hsBodyExample))
					r.Header.Set("Host", "example.org")
					return r
				})(),
			},
			want:        nil,
			wantErrType: hsErrType,
			wantErrMsg:  "header 'digest', required in signature, not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(ss)
			got, err := hs.buildSignatureString(tt.args.ph, tt.args.r)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestVerify(t *testing.T) {
	ss := NewSecretsStorage(map[string]Secret{
		"Test": {
			KeyID:      "Test",
			PrivateKey: rsaPrivateKey1024,
			PublicKey:  rsaPublicKey1024,
			Algorithm:  "RSA-SHA256",
		},
	})
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name        string
		args        args
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "No Signature header",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						hsHostExampleFull,
						strings.NewReader(hsBodyExample))
					return r
				})(),
			},
			want:        false,
			wantErrType: hsErrType,
			wantErrMsg:  "signature header not found",
		},
		{
			name: "Valid signature basic test",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						hsHostExampleFull,
						strings.NewReader(hsBodyExample))
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="`+
						`(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmo`+
						`xWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/`+
						`x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="`)
					r.Header.Set("Host", "example.com")
					r.Header.Set("Date", "Sun, 05 Jan 2014 21:31:40 GMT")
					return r
				})(),
			},
			want:        true,
			wantErrType: hsErrType,
			wantErrMsg:  "",
		},
		{
			name: "Valid signature all headers test",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						hsHostExampleFull,
						strings.NewReader(hsBodyExample))
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",created=1402170695,`+
						`expires=1402170699,headers="(request-target) (created) (expires) host date content-type `+
						`digest content-length",signature="nAkCW0wg9AbbStQRLi8fsS1mPPnA6S5+/0alANcoDFG9hG0bJ8NnMR`+
						`cB1Sz1eccNMzzLEke7nGXqoiJYZFfT81oaRqh/MNFwQVX4OZvTLZ5xVZQuchRkOSO7b2QX0aFWFOUq6dnwAyliHr`+
						`p6w3FOxwkGGJPaerw2lOYLdC/Bejk="`)
					r.Header.Set("Host", "example.com")
					r.Header.Set("Date", "Sun, 05 Jan 2014 21:31:40 GMT")
					r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Content-length", "18")
					return r
				})(),
			},
			want:        true,
			wantErrType: hsErrType,
			wantErrMsg:  "",
		},
		{
			name: "Parser error",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						hsHostExampleFull,
						strings.NewReader(hsBodyExample))
					r.Header.Set("Signature", `keyId=Test"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: parserErrType,
			wantErrMsg:  "ParserError: found 'T' — unsupported symbol, expected '\"' or space symbol",
		},
		{
			name: "Digest error",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						hsHostExampleFull,
						strings.NewReader(hsBodyExample))
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="digest",signature="xxx"`)
					r.Header.Set("Digest", "XXX-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					return r
				})(),
			},
			want:        false,
			wantErrType: digestErrType,
			wantErrMsg:  "DigestError: unsupported digest hash algorithm 'XXX-256'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(ss)
			err := hs.Verify(tt.args.r)
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHSVerifyDigest(t *testing.T) {
	type args struct {
		sh []string
		r  *http.Request
	}
	ss := NewSecretsStorage(map[string]Secret{})
	tests := []struct {
		name        string
		args        args
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Digest verify OK",
			args: args{
				sh: []string{"digest"},
				r:  getDigestRequestFunc(digestBodyExample, "MD5=Sd/dVLAcvNLSq16eXua5uQ=="),
			},
			want: true,
		},
		{
			name: "Digest verify Fail",
			args: args{
				sh: []string{"digest"},
				r:  getDigestRequestFunc(digestBodyExample, "MD5=MQ=="),
			},
			want:        false,
			wantErrType: "*httpsignatures.DigestError",
			wantErrMsg:  "DigestError: wrong digest: CryptoError: wrong hash",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(ss)
			err := hs.verifyDigest(tt.args.sh, tt.args.r)
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHSCreateDigest(t *testing.T) {
	type args struct {
		sh        []string
		r         *http.Request
		digestErr bool
	}
	ss := NewSecretsStorage(map[string]Secret{})
	tests := []struct {
		name        string
		args        args
		want        string
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Digest create OK",
			args: args{
				sh:        []string{"digest"},
				r:         getDigestRequestFunc(digestBodyExample, ""),
				digestErr: false,
			},
			want: "SHA-512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==",
		},
		{
			name: "No digest",
			args: args{
				sh:        []string{},
				r:         getDigestRequestFunc(digestBodyExample, ""),
				digestErr: false,
			},
		},
		{
			name: "Digest err",
			args: args{
				sh:        []string{"digest"},
				r:         getDigestRequestFunc(digestBodyExample, "MD5=Sd/dVLAcvNLSq16eXua5uQ=="),
				digestErr: true,
			},
			wantErrType: "*httpsignatures.DigestError",
			wantErrMsg:  "DigestError: error creating digest hash 'ERR': create hash error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(ss)
			if tt.args.digestErr {
				hs.SetDigestAlgorithm(errAlg{})
				_ = hs.SetDefaultDigestAlgorithm("ERR")
			}
			got, err := hs.createDigest(tt.args.sh, tt.args.r)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSetDigestAlgorithm(t *testing.T) {
	hs := NewHTTPSignatures(NewSecretsStorage(map[string]Secret{}))
	hs.SetDigestAlgorithm(testAlg{})
	if _, ok := hs.d.alg[testAlgName]; ok == false {
		t.Error("algorithm not found")
	}
}

func TestSetSignatureAlgorithm(t *testing.T) {
	hs := NewHTTPSignatures(NewSecretsStorage(map[string]Secret{}))
	hs.SetSignatureAlgorithm(RsaDummy{})
	if _, ok := hs.alg[rsaDummyName]; ok == false {
		t.Error("algorithm not found")
	}
}

func TestSetDefaultExpiresSeconds(t *testing.T) {
	var defaultExpiresSec int64 = 123
	hs := NewHTTPSignatures(NewSecretsStorage(map[string]Secret{}))
	hs.SetDefaultExpiresSeconds(defaultExpiresSec)
	if hs.defaultExpiresSec != defaultExpiresSec {
		t.Error("defaultExpiresSec not set")
	}
}

func TestBuildSignatureHeader(t *testing.T) {
	tests := []struct {
		name string
		arg  Headers
		want string
	}{
		{
			name: "Signature string OK",
			arg: Headers{
				keyID:     "key1",
				algorithm: "alg",
				created:   time.Unix(1591130723, 0),
				expires:   time.Unix(1591130723, 0),
				headers:   []string{"digest", "host"},
				signature: "signature",
			},
			want: `keyId="key1",algorithm="alg",created=1591130723,expires=1591130723,headers="digest,host",` +
				`signature="signature"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(NewSecretsStorage(map[string]Secret{}))
			got := hs.buildSignatureHeader(tt.arg)
			if got != tt.want {
				t.Errorf("wrong signature header\ngot  = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}
