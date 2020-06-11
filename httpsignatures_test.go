package httpsignatures

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testHSErrType = "*httpsignatures.Error"

func testGetRequest() *http.Request {
	r, _ := http.NewRequest(
		http.MethodPost,
		testHostExampleFullPath,
		strings.NewReader(testBodyExample))
	return r
}

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

func TestVerify(t *testing.T) {
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
			name: "Valid signature basic test",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="`+
						`(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmo`+
						`xWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/`+
						`x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="`)
					r.Header.Set("Host", testHostExample)
					r.Header.Set("Date", testDateExample)
					return r
				})(),
			},
			want:        true,
			wantErrType: testHSErrType,
			wantErrMsg:  "",
		},
		{
			name: "Valid signature all headers test",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",created=1402170695,`+
						`expires=1402170699,headers="(request-target) (created) (expires) host date content-type `+
						`digest content-length",signature="nAkCW0wg9AbbStQRLi8fsS1mPPnA6S5+/0alANcoDFG9hG0bJ8NnMR`+
						`cB1Sz1eccNMzzLEke7nGXqoiJYZFfT81oaRqh/MNFwQVX4OZvTLZ5xVZQuchRkOSO7b2QX0aFWFOUq6dnwAyliHr`+
						`p6w3FOxwkGGJPaerw2lOYLdC/Bejk="`)
					r.Header.Set("Host", testHostExample)
					r.Header.Set("Date", testDateExample)
					r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					r.Header.Set(testContentTypeHeader, testContentTypeJSON)
					r.Header.Set("Content-length", "18")
					return r
				})(),
			},
			want:        true,
			wantErrType: testHSErrType,
			wantErrMsg:  "",
		},
		{
			name: "No Signature header",
			args: args{
				r: testGetRequest(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "signature header not found",
		},
		{
			name: "Parser error",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId=Test"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: found 'T' — unsupported symbol, expected '\"' or space symbol",
		},
		{
			name: "Required field not found",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `algorithm="rsa-sha256",headers="host",signature="qwe"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: keyId is not set in header",
		},
		{
			name: "KeyId not found in secrets",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="test3",algorithm="rsa-sha256",headers="host",`+
						`signature="MTIz"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "keyID 'test3' not found: SecretError: secret not found",
		},
		{
			name: "Algorithm does not match",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha512",headers="host",`+
						`signature="MTIz"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "wrong algorithm 'rsa-sha512' for keyId 'Test'",
		},
		{
			name: "Algorithm not supported",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="NotSupported",algorithm="rsa-dummy",headers="host",`+
						`signature="MTIz"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "algorithm 'rsa-dummy' not supported",
		},
		{
			name: "Digest error",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="digest",`+
						`signature="xxx"`)
					r.Header.Set("Digest", "XXX-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					return r
				})(),
			},
			want:        false,
			wantErrType: testDigestErrType,
			wantErrMsg:  "DigestError: unsupported digest hash algorithm 'XXX-256'",
		},
		{
			name: "Error building signature string",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="`+
						`host",signature="MTIz"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "build signature string error: header 'host', required in signature, not found",
		},
		{
			name: "Empty signature string",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",signature="MTIz"`)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "empty string for signature",
		},
		{
			name: "Error decode signature from base64",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="host",`+
						`signature="x"`)
					r.Header.Set("Host", testHostExample)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "error decode signature from base64: illegal base64 data at input byte 0",
		},
		{
			name: "Wrong signature",
			args: args{
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set("Signature", `keyId="Test",algorithm="rsa-sha256",headers="`+
						`(request-target) host date",signature="MTIz"`)
					r.Header.Set("Host", testHostExample)
					r.Header.Set("Date", testDateExample)
					return r
				})(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "wrong signature: CryptoError: error verify signature: crypto/rsa: verification error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			err := hs.Verify(tt.args.r)
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSign(t *testing.T) {
	type args struct {
		secretKeyID    string
		r              *http.Request
		defaultDigest  string
		defaultHeaders []string
	}
	tests := []struct {
		name        string
		args        args
		want        bool
		wantHeader  string
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Secret key not found",
			args: args{
				secretKeyID: "NotFound",
				r: testGetRequest(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "keyId 'NotFound' not found: SecretError: secret not found",
		},
		{
			name: "Not supported algorithm for secret key",
			args: args{
				secretKeyID: "NotSupported",
				r: testGetRequest(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "algorithm 'RSA-DUMMY' not supported",
		},
		{
			name: "Create digest error",
			args: args{
				secretKeyID: "Test",
				r: testGetRequest(),
				defaultDigest:  testErrAlgName,
				defaultHeaders: []string{"digest"},
			},
			want:        false,
			wantErrType: testDigestErrType,
			wantErrMsg:  "DigestError: error creating digest hash 'ERR': create hash error",
		},
		{
			name: "Build signature string error",
			args: args{
				secretKeyID: "Test",
				r: testGetRequest(),
				defaultHeaders: []string{"test"},
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "build signature string error: header 'test', required in signature, not found",
		},
		{
			name: "Create signature error",
			args: args{
				secretKeyID: "Err",
				r: testGetRequest(),
			},
			want:        false,
			wantErrType: testHSErrType,
			wantErrMsg:  "error creating signature: create error",
		},
		{
			name: "Create signature OK",
			args: args{
				secretKeyID: "Test",
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set(testContentTypeHeader, testContentTypeJSON)
					r.Header.Set("Server", "nginx")
					return r
				})(),
				defaultHeaders: []string{requestTarget, "content-type", "server"},
			},
			want: true,
			wantHeader: `keyId="Test",algorithm="RSA-SHA256",headers="(request-target) content-type server",` +
				`signature="VtEbFMQR4nD6VygasRJtJ02k10S7dbJ01D7vWFvib2zLN5eQDIzF9SgxR4kBTNWyP2Da5p9miDDPEk2QX/hm5HuzS` +
				`FrfuTCbr8I7YRuaiQlEW9KpjmuopAlaRji6iuJ2Zd+psbS335bF7eyl17M8QPR6tc7vI3EVmodcgitJlvs="`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			hs.SetDigestAlgorithm(testErrAlg{})
			hs.SetSignatureAlgorithm(TestRsaErr{})
			if len(tt.args.defaultDigest) > 0 {
				_ = hs.SetDefaultDigestAlgorithm(tt.args.defaultDigest)
			}
			if len(tt.args.defaultHeaders) > 0 {
				hs.SetDefaultSignatureHeaders(tt.args.defaultHeaders)
			}
			err := hs.Sign(tt.args.secretKeyID, tt.args.r)
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
			gotHeader := tt.args.r.Header.Get(signatureHeader)
			if gotHeader != tt.wantHeader {
				t.Errorf(tt.name+"\ngot header  = %v,\nwant header = %v", gotHeader, tt.wantHeader)
			}
		})
	}
}

func TestHSCrossCheck(t *testing.T) {
	type args struct {
		secretKeyID    string
		r              *http.Request
		defaultHeaders []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Sign & Verify OK",
			args: args{
				secretKeyID: "Test",
				r: (func() *http.Request {
					r := testGetRequest()
					r.Header.Set(testContentTypeHeader, testContentTypeJSON)
					return r
				})(),
				defaultHeaders: []string{requestTarget, "content-type"},
			},
			want: true,
		},
		{
			name: "Sign & Verify with default headers OK",
			args: args{
				secretKeyID: "Test",
				r: testGetRequest(),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			if len(tt.args.defaultHeaders) > 0 {
				hs.SetDefaultSignatureHeaders(tt.args.defaultHeaders)
			}
			err := hs.Sign(tt.args.secretKeyID, tt.args.r)
			if err != nil {
				t.Errorf(tt.name+"\nSign error = %v", err)
			}
			err = hs.Verify(tt.args.r)
			got := err == nil
			if got != tt.want {
				t.Errorf(tt.name+"\nerror = %s\ngot   = %v,\nwant  = %v", err, got, tt.want)
			}
		})
	}
}

func TestHSBuildSignatureString(t *testing.T) {
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
					r, _ := http.NewRequest(http.MethodPost, testHostExamplePath, strings.NewReader(testBodyExample))
					r.Header.Set("Host", testHostExample)
					r.Header.Set("Date", testDateExample)
					r.Header.Set(testContentTypeHeader, testContentTypeJSON)
					r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					r.Header.Set("Content-Length", "18")
					return r
				})(),
			},
			want: []byte("(request-target): post /foo\n" +
				"(created): 1402170695\n" +
				"(expires): 1402170995\n" +
				"host: " + testHostExample + "\n" +
				"date: " + testDateExample + "\n" +
				"digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\n" +
				"content-length: 18"),
			wantErrType: testHSErrType,
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
					r, _ := http.NewRequest(http.MethodPost, testHostExamplePath, strings.NewReader(testBodyExample))
					return r
				})(),
			},
			want:        nil,
			wantErrType: testHSErrType,
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
					r, _ := http.NewRequest(http.MethodPost, testHostExamplePath, strings.NewReader(testBodyExample))
					return r
				})(),
			},
			want:        nil,
			wantErrType: testHSErrType,
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
					r, _ := http.NewRequest(http.MethodPost, testHostExamplePath, strings.NewReader(testBodyExample))
					r.Header.Set("Host", testHostExample)
					r.Header.Set("Digest", "")
					return r
				})(),
			},
			want: []byte(
				"host: " + testHostExample + "\n" +
					"digest: "),
			wantErrType: testHSErrType,
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
					r, _ := http.NewRequest(http.MethodPost, testHostExamplePath, strings.NewReader(testBodyExample))
					r.Header.Set("Host", "example.org")
					return r
				})(),
			},
			want:        nil,
			wantErrType: testHSErrType,
			wantErrMsg:  "header 'digest', required in signature, not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			got, err := hs.buildSignatureString(tt.args.ph, tt.args.r)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHSVerifyDigest(t *testing.T) {
	type args struct {
		sh []string
		r  *http.Request
	}
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
				r:  testGetDigestRequestFunc(testBodyExample, "MD5=Sd/dVLAcvNLSq16eXua5uQ=="),
			},
			want: true,
		},
		{
			name: "Digest verify Fail",
			args: args{
				sh: []string{"digest"},
				r:  testGetDigestRequestFunc(testBodyExample, "MD5=MQ=="),
			},
			want:        false,
			wantErrType: "*httpsignatures.DigestError",
			wantErrMsg:  "DigestError: wrong digest: CryptoError: wrong hash",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
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
				r:         testGetDigestRequestFunc(testBodyExample, ""),
				digestErr: false,
			},
			want: "SHA-512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==",
		},
		{
			name: "No digest",
			args: args{
				sh:        []string{},
				r:         testGetDigestRequestFunc(testBodyExample, ""),
				digestErr: false,
			},
		},
		{
			name: "Digest err",
			args: args{
				sh:        []string{"digest"},
				r:         testGetDigestRequestFunc(testBodyExample, "MD5=Sd/dVLAcvNLSq16eXua5uQ=="),
				digestErr: true,
			},
			wantErrType: "*httpsignatures.DigestError",
			wantErrMsg:  "DigestError: error creating digest hash 'ERR': create hash error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			if tt.args.digestErr {
				hs.SetDigestAlgorithm(testErrAlg{})
				_ = hs.SetDefaultDigestAlgorithm("ERR")
			}
			got, err := hs.createDigest(tt.args.sh, tt.args.r)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHSSetDigestAlgorithm(t *testing.T) {
	hs := NewHTTPSignatures(testSecretsStorage)
	hs.SetDigestAlgorithm(testAlg{})
	if _, ok := hs.d.alg[testAlgName]; ok == false {
		t.Error("algorithm not found")
	}
}

func TestHSSetSignatureAlgorithm(t *testing.T) {
	hs := NewHTTPSignatures(testSecretsStorage)
	hs.SetSignatureAlgorithm(RsaDummy{})
	if _, ok := hs.alg[testRsaDummyName]; ok == false {
		t.Error("algorithm not found")
	}
}

func TestHSSetDefaultExpiresSeconds(t *testing.T) {
	var defaultExpiresSec int64 = 123
	hs := NewHTTPSignatures(testSecretsStorage)
	hs.SetDefaultExpiresSeconds(defaultExpiresSec)
	if hs.defaultExpiresSec != defaultExpiresSec {
		t.Error("defaultExpiresSec not set")
	}
}

func TestHSBuildSignatureHeader(t *testing.T) {
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
			want: `keyId="key1",algorithm="alg",headers="digest host",signature="signature"`,
		},
		{
			name: "Signature string with created & expires OK",
			arg: Headers{
				keyID:     "key2",
				algorithm: "alg",
				created:   time.Unix(1591130723, 0),
				expires:   time.Unix(1591130723, 0),
				headers:   []string{"(created)", "(expires)"},
				signature: "signature",
			},
			want: `keyId="key2",algorithm="alg",created=1591130723,expires=1591130723,headers="(created) (expires)",` +
				`signature="signature"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			got := hs.buildSignatureHeader(tt.arg)
			if got != tt.want {
				t.Errorf("wrong signature header\ngot  = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}

func TestHSSetDefaultSignatureHeaders(t *testing.T) {
	defaultHeaders := []string{"host", "digest"}
	hs := NewHTTPSignatures(testSecretsStorage)
	hs.SetDefaultSignatureHeaders(defaultHeaders)
	if !reflect.DeepEqual(hs.defaultHeaders, defaultHeaders) {
		t.Errorf("got headers  = %v,\nwant headers = %v", hs.defaultHeaders, defaultHeaders)
	}
}

func TestHSInHeaders(t *testing.T) {
	type args struct {
		h       string
		headers []string
	}
	tests := []struct {
		name string
		arg  args
		want bool
	}{
		{
			name: "Found",
			arg: args{
				h:       "key1",
				headers: []string{"key2", "key1"},
			},
			want: true,
		},
		{
			name: "Not found",
			arg: args{
				h:       "key1",
				headers: []string{"key2", "key3"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHTTPSignatures(testSecretsStorage)
			got := hs.inHeaders(tt.arg.h, tt.arg.headers)
			if got != tt.want {
				t.Errorf(tt.name+"\ngot  = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}
