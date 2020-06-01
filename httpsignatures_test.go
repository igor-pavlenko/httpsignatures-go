package httpsignatures

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const httpsignaturesErrType = "*httpsignatures.Error"
const httpsignaturesBodyExample = `{"hello": "world"}`
const httpsignaturesHostExample = "https://example.org/foo"
const httpsignaturesHostExampleFull = "https://example.com/foo?param=value&pet=dog"

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
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
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
			wantErrType: httpsignaturesErrType,
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
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
					return r
				})(),
			},
			want:        nil,
			wantErrType: httpsignaturesErrType,
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
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
					return r
				})(),
			},
			want:        nil,
			wantErrType: httpsignaturesErrType,
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
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
					r.Header.Set("Host", "example.org")
					r.Header.Set("Digest", "")
					return r
				})(),
			},
			want: []byte(
				"host: example.org\n" +
					"digest: "),
			wantErrType: httpsignaturesErrType,
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
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
					r.Header.Set("Host", "example.org")
					return r
				})(),
			},
			want:        nil,
			wantErrType: httpsignaturesErrType,
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
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
					return r
				})(),
			},
			want:        false,
			wantErrType: httpsignaturesErrType,
			wantErrMsg:  "signature header not found",
		},
		{
			name: "Valid signature basic test",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
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
			wantErrType: httpsignaturesErrType,
			wantErrMsg:  "",
		},
		{
			name: "Valid signature all headers test",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
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
			wantErrType: httpsignaturesErrType,
			wantErrMsg:  "",
		},
		{
			name: "Parser error",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
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
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
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
