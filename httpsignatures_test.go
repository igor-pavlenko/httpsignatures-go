package httpsignatures

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

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

func TestIsAlgoHasPrefix(t *testing.T) {
	type args struct {
		alg string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "rsa true",
			args: args{
				alg: "rsa",
			},
			want: true,
		},
		{
			name: "hamc_md5 true",
			args: args{
				alg: "HMAC_MD5",
			},
			want: true,
		},
		{
			name: "ecdsa true",
			args: args{
				alg: "ecdsa",
			},
			want: true,
		},
		{
			name: "md5 false",
			args: args{
				alg: "MD5",
			},
			want: false,
		},
	}
	hs := NewHTTPSignatures(NewSecretsStorage(map[string]Secret{}))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hs.isAlgoHasPrefix(tt.args.alg)
			if got != tt.want {
				t.Errorf(tt.name+"\ngot  = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}

func TestBuildSignatureString(t *testing.T) {
	ss := NewSecretsStorage(map[string]Secret{})
	type args struct {
		ph ParsedHeader
		r  *http.Request
	}
	tests := []struct {
		name       string
		args       args
		want       []byte
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Valid signature string",
			args: args{
				ph: ParsedHeader{
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
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Has only created header in signature & rsa algorithm",
			args: args{
				ph: ParsedHeader{
					algorithm: "rsa",
					headers: []string{
						"(created)",
					},
					created: time.Unix(1402170695, 0),
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
					return r
				})(),
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "param '(created)' and algorithm 'rsa'",
		},
		{
			name: "Has created header with 0 value",
			args: args{
				ph: ParsedHeader{
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
			want:       nil,
			wantErr:    true,
			wantErrMsg: "param '(created)', required in signature, not found",
		},
		{
			name: "Has only expires header in signature & hmac_sha-1 algorithm",
			args: args{
				ph: ParsedHeader{
					algorithm: "hmac_sha-1",
					headers: []string{
						"(expires)",
					},
					expires: time.Unix(1402170695, 0),
				},
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, httpsignaturesHostExample, strings.NewReader(httpsignaturesBodyExample))
					return r
				})(),
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "param '(expires)' and algorithm 'hmac_sha-1'",
		},
		{
			name: "Has expires header with 0 value",
			args: args{
				ph: ParsedHeader{
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
			want:       nil,
			wantErr:    true,
			wantErrMsg: "param '(expires)', required in signature, not found",
		},
		{
			name: "Header with 0 length",
			args: args{
				ph: ParsedHeader{
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
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Header not found",
			args: args{
				ph: ParsedHeader{
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
			want:       nil,
			wantErr:    true,
			wantErrMsg: "header 'digest', required in signature, not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(ss)
			got, err := hs.buildSignatureString(tt.args.ph, tt.args.r)
			assertHttpsignatures(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func TestVerifySignature(t *testing.T) {
	ss := NewSecretsStorage(map[string]Secret{
		"Test": {
			KeyID:      "Test",
			PrivateKey: rsaPrivateKey,
			PublicKey:  rsaPublicKey,
			Algorithm:  "RSA-SHA256",
		},
	})
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		wantErr    bool
		wantErrMsg string
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
			want:       false,
			wantErr:    true,
			wantErrMsg: "signature header not found",
		},
		{
			name: "Valid signature basic test",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="`)
					r.Header.Set("Host", "example.com")
					r.Header.Set("Date", "Sun, 05 Jan 2014 21:31:40 GMT")
					r.Header.Set("Content-Type", "application/json")
					return r
				})(),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Valid signature all headers test",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(
						http.MethodPost,
						httpsignaturesHostExampleFull,
						strings.NewReader(httpsignaturesBodyExample))
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",created=1402170695,expires=1402170699,headers="(request-target) (created) (expires) host date content-type digest content-length",signature="nAkCW0wg9AbbStQRLi8fsS1mPPnA6S5+/0alANcoDFG9hG0bJ8NnMRcB1Sz1eccNMzzLEke7nGXqoiJYZFfT81oaRqh/MNFwQVX4OZvTLZ5xVZQuchRkOSO7b2QX0aFWFOUq6dnwAyliHrp6w3FOxwkGGJPaerw2lOYLdC/Bejk="`)
					r.Header.Set("Host", "example.com")
					r.Header.Set("Date", "Sun, 05 Jan 2014 21:31:40 GMT")
					r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Content-length", "18")
					return r
				})(),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(ss)
			err := hs.VerifySignature(tt.args.r)
			got := err == nil
			assertHttpsignatures(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func assertHttpsignatures(t *testing.T, got interface{}, err error, name string, want interface{}, wantErr bool, wantErrMsg string) {
	if e, ok := err.(*Error); err != nil && ok == false {
		t.Errorf(name+"\nunexpected error type %v", e)
	}
	if err != nil && err.Error() != wantErrMsg {
		t.Errorf(name+"\nerror message = `%s`, wantErrMsg = `%s`", err.Error(), wantErrMsg)
	}
	if (err != nil) != wantErr {
		t.Errorf(name+"\nerror = `%v`, wantErr %v", err, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(name+"\ngot =\n%v\nwant =\n%v\n", got, want)
	}
}
