package httpsignatures

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

const testCryptoErrType = "*httpsignatures.CryptoError"
const testHashData = "hello world"
const testRsaDummyName = "RSA-DUMMY"

// RsaDummy RSA-DUMMY Algorithm
type RsaDummy struct{}

// Algorithm Return algorithm name
func (a RsaDummy) Algorithm() string {
	return testRsaDummyName
}

// Create Create dummy
func (a RsaDummy) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(testRsaDummyName, sha256.New, crypto.SHA256, secret, data)
}

// Verify Verify dummy
func (a RsaDummy) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(testRsaDummyName, sha256.New, crypto.SHA256, secret, data, signature)
}

func TestHashAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		arg  DigestHashAlgorithm
		want string
	}{
		{
			name: "MD5 OK",
			arg:  Md5{},
			want: "MD5",
		},
		{
			name: "SHA256 OK",
			arg:  Sha256{},
			want: "SHA-256",
		},
		{
			name: "SHA512 OK",
			arg:  Sha512{},
			want: "SHA-512",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.arg.Algorithm() != tt.want {
				t.Errorf("algorithm not match. Got = %s, want = %s", tt.arg.Algorithm(), tt.want)
			}
		})
	}
}

func TestHashAlgorithmCreate(t *testing.T) {
	type args struct {
		alg  DigestHashAlgorithm
		data []byte
	}
	tests := []struct {
		name        string
		args        args
		want        string
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "MD5 create ok",
			args: args{
				alg:  Md5{},
				data: []byte(testHashData),
			},
			want:        "5eb63bbbe01eeed093cb22bb8f5acdc3",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "SHA256 create ok",
			args: args{
				alg:  Sha256{},
				data: []byte(testHashData),
			},
			want:        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "SHA512 create ok",
			args: args{
				alg:  Sha512{},
				data: []byte(testHashData),
			},
			want: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd8" +
				"30e81f605dcf7dc5542e93ae9cd76f",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.data)
			digest := hex.EncodeToString(got)
			assert(t, digest, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHashAlgorithmVerify(t *testing.T) {
	type args struct {
		alg    DigestHashAlgorithm
		digest string
		data   []byte
	}
	tests := []struct {
		name        string
		args        args
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "MD5 verify ok",
			args: args{
				alg:    Md5{},
				digest: "5eb63bbbe01eeed093cb22bb8f5acdc3",
				data:   []byte(testHashData),
			},
			want: true,
		},
		{
			name: "MD5 wrong hash",
			args: args{
				alg:    Md5{},
				digest: "5eb",
				data:   []byte(testHashData),
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong hash",
		},
		{
			name: "Sha256 verify ok",
			args: args{
				alg:    Sha256{},
				digest: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
				data:   []byte(testHashData),
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "Sha256 wrong hash",
			args: args{
				alg:    Sha256{},
				digest: "b94",
				data:   []byte(testHashData),
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong hash",
		},
		{
			name: "Sha512 verify ok",
			args: args{
				alg: Sha512{},
				digest: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45" +
					"b0cfd830e81f605dcf7dc5542e93ae9cd76f",
				data: []byte(testHashData),
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "Sha512 wrong hash",
			args: args{
				alg:    Sha512{},
				digest: "309",
				data:   []byte(testHashData),
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := hex.DecodeString(tt.args.digest)
			err := tt.args.alg.Verify(tt.args.data, b)
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHmacAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		arg  SignatureHashAlgorithm
		want string
	}{
		{
			name: "HMAC-SHA256 OK",
			arg:  HmacSha256{},
			want: "HMAC-SHA256",
		},
		{
			name: "HMAC-SHA512 OK",
			arg:  HmacSha512{},
			want: "HMAC-SHA512",
		},
		{
			name: "RSA-SHA256 OK",
			arg:  RsaSha256{},
			want: "RSA-SHA256",
		},
		{
			name: "RSA-SHA512 OK",
			arg:  RsaSha512{},
			want: "RSA-SHA512",
		},
		{
			name: "RSASSA-PSS-SHA256 OK",
			arg:  RsaSsaPssSha256{},
			want: "RSASSA-PSS-SHA256",
		},
		{
			name: "RSASSA-PSS-SHA512 OK",
			arg:  RsaSsaPssSha512{},
			want: "RSASSA-PSS-SHA512",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.arg.Algorithm() != tt.want {
				t.Errorf("algorithm not match. Got = %s, want = %s", tt.arg.Algorithm(), tt.want)
			}
		})
	}
}

func TestSignatureHashAlgorithmCreate(t *testing.T) {
	type args struct {
		alg    SignatureHashAlgorithm
		data   []byte
		secret Secret
	}
	tests := []struct {
		name        string
		args        args
		want        string
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "HMAC-SHA256 create ok",
			args: args{
				alg:  HmacSha256{},
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha256,
				},
			},
			want:        "7lksEgztUSEk34sJ8vGQpE0i+UK+ZexCQ0L8HpHBBJY=",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "HMAC-SHA256 no private key found",
			args: args{
				alg:    HmacSha256{},
				data:   []byte{},
				secret: Secret{},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "HMAC-SHA512 create ok",
			args: args{
				alg:  HmacSha512{},
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha512,
				},
			},
			want:        "xhrfZlhd8heV7O4w1nPbNRYdWSc2Qg8RuruZ5jDDHbVzSgd4NQOePJWN5xIKz74U/HhlLe138G8VLcH5atTZTg==",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "HMAC-SHA512 no private key found",
			args: args{
				alg:    HmacSha512{},
				data:   []byte{},
				secret: Secret{},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "RSA-SHA256 create ok",
			args: args{
				alg: RsaSha256{},
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 05 Jan 2014 21:31:40 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSha256,
				},
			},
			want: "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdK" +
				"FYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-SHA256 no private key found",
			args: args{
				alg:    RsaSha256{},
				data:   []byte{},
				secret: Secret{},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "RSA-SHA256 unsupported key type",
			args: args{
				alg:  RsaSha256{},
				data: []byte{},
				secret: Secret{
					PrivateKey: `-----BEGIN SSH PRIVATE KEY-----
-----END SSH PRIVATE KEY-----`,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported key type SSH PRIVATE KEY",
		},
		{
			name: "RSA-SHA256 error ParsePKCS1PrivateKey",
			args: args{
				alg:  RsaSha256{},
				data: []byte{},
				secret: Secret{
					PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END RSA PRIVATE KEY-----`,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKCS1PrivateKey: asn1: syntax error: data truncated",
		},
		{
			name: "RSA-SHA512 create ok",
			args: args{
				alg: RsaSha512{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 28 Apr 2020 00:47:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSha512,
				},
			},
			want: "j2EgWL0QOEmWjsKXRu1MxfYe2CzjdyNkkqbagIYpBNqBg2kevrQSSIocgfESHHoIgayK+we2SRAB59wVEM3gtQuQ9ef1BikcX5" +
				"4GuqCThSA63kcuGXZzUgQcGnFpy2KO6gV2gl2cCkB8X6ZRY5oFfpiPvFxVY1bg/Y3DXlsKZb0=",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSASSA-PSS-SHA256 create ok",
			args: args{
				alg: RsaSsaPssSha256{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSsaPssSha256,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSASSA-PSS-SHA512 create ok",
			args: args{
				alg: RsaSsaPssSha512{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey2048,
					PublicKey:  testRsaPublicKey2048,
					Algorithm:  algoRsaSsaPssSha512,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-DUMMY unsupported algorithm type",
			args: args{
				alg:  RsaDummy{},
				data: nil,
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  testRsaDummyName,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported algorithm type RSA-DUMMY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			// RSASSA-PSS Algorithm generate always different signature
			if tt.args.alg.Algorithm() == algoRsaSsaPssSha256 {
				if len(sig) != 172 {
					t.Errorf(tt.name+"\ngot = %v, expected length = 172 symbols", sig)
				}
				tt.want = sig
			} else if tt.args.alg.Algorithm() == algoRsaSsaPssSha512 {
				if len(sig) != 344 {
					t.Errorf(tt.name+"\ngot = %v, expected length = 344 symbols", sig)
				}
				tt.want = sig
			}
			assert(t, sig, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestHmacAlgorithmVerify(t *testing.T) {
	type args struct {
		alg    SignatureHashAlgorithm
		sig    string
		data   []byte
		secret Secret
	}
	tests := []struct {
		name        string
		args        args
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "HMAC-SHA256 verify ok",
			args: args{
				alg:  HmacSha256{},
				sig:  "7lksEgztUSEk34sJ8vGQpE0i+UK+ZexCQ0L8HpHBBJY=",
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "HMAC-SHA256 wrong signature",
			args: args{
				alg:  HmacSha256{},
				sig:  "MTIz",
				data: []byte("xx"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong signature",
		},
		{
			name: "HMAC-SHA256 no private key found",
			args: args{
				alg:    HmacSha256{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "HMAC-SHA512 verify ok",
			args: args{
				alg:  HmacSha512{},
				sig:  "xhrfZlhd8heV7O4w1nPbNRYdWSc2Qg8RuruZ5jDDHbVzSgd4NQOePJWN5xIKz74U/HhlLe138G8VLcH5atTZTg==",
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha512,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "HMAC-SHA512 wrong signature",
			args: args{
				alg:  HmacSha512{},
				sig:  "MTIz",
				data: []byte("xx"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algoHmacSha512,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong signature",
		},
		{
			name: "HMAC-SHA512 no private key found",
			args: args{
				alg:    HmacSha512{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "RSA-SHA256 verify ok",
			args: args{
				alg: RsaSha256{},
				sig: "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8V" +
					"fEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 05 Jan 2014 21:31:40 GMT",
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-SHA256 wrong signature",
			args: args{
				alg:  RsaSha256{},
				sig:  "MTIz",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key3",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error verify signature: crypto/rsa: verification error",
		},
		{
			name: "RSA-SHA256 no public key found",
			args: args{
				alg:    RsaSha256{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no public key found",
		},
		{
			name: "RSA-SHA256 unsupported key type",
			args: args{
				alg:  RsaSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported key type NO PUBLIC KEY",
		},
		{
			name: "RSA-SHA256 error ParsePKIXPublicKey",
			args: args{
				alg:  RsaSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKIXPublicKey: asn1: syntax error: data truncated",
		},
		{
			name: "RSA-SHA256 unknown type of public key",
			args: args{
				alg:  RsaSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo
yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==
-----END PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unknown type of public key",
		},
		{
			name: "RSA-SHA512 verify ok",
			args: args{
				alg: RsaSha512{},
				sig: "j2EgWL0QOEmWjsKXRu1MxfYe2CzjdyNkkqbagIYpBNqBg2kevrQSSIocgfESHHoIgayK+we2SRAB59wVEM3gtQuQ9ef1Bik" +
					"cX54GuqCThSA63kcuGXZzUgQcGnFpy2KO6gV2gl2cCkB8X6ZRY5oFfpiPvFxVY1bg/Y3DXlsKZb0=",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 28 Apr 2020 00:47:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSha512,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSASSA-PSS-SHA256 verify ok",
			args: args{
				alg: RsaSsaPssSha256{},
				sig: "ax+hvuK+r5YdCrjKqKJoVYIYA2XaKTus1jI6VxAXapWKLf0IUwF9c+rDRmoNzr7m4vueZ4WPujAyb5jxwSmCf9gQGE24+JG" +
					"WSz1yIXdLWttFksDXe0jonmTNGotTJZpgK+hBNHlrB+r1aITPK/APhVpwKBXQPwseYhJTmjgIQmg=",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSsaPssSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSASSA-PSS-SHA256 wrong signature",
			args: args{
				alg:  RsaSsaPssSha256{},
				sig:  "MTIz",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSsaPssSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error verify signature: crypto/rsa: verification error",
		},
		{
			name: "RSASSA-PSS-SHA256 no public key found",
			args: args{
				alg:    RsaSsaPssSha256{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no public key found",
		},
		{
			name: "RSASSA-PSS-SHA256 unsupported key type",
			args: args{
				alg:  RsaSsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported key type NO PUBLIC KEY",
		},
		{
			name: "RSASSA-PSS-SHA256 error ParsePKIXPublicKey",
			args: args{
				alg:  RsaSsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKIXPublicKey: asn1: syntax error: data truncated",
		},
		{
			name: "RSASSA-PSS-SHA256 unknown type of public key",
			args: args{
				alg:  RsaSsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo
yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==
-----END PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unknown type of public key",
		},
		{
			name: "RSASSA-PSS-SHA512 verify ok",
			args: args{
				alg: RsaSsaPssSha512{},
				sig: "PFYH4AcklIlNNcrBLWkHGejwDwnK3kLcdMDjjPwZG7MrT76qwqyrl6heeMC6/+B4QEqZf1UuRzGAWJ7mziqh5vanlMfr6E2" +
					"1bhvhsRII2eoqTmvvEANKg4dhnVxYApk/IA9W9wK9t7/p3CctB8CqjMi3hPTj8aNcQcDJNY1DpTcoxuNJK32wHnp/kwuBurL" +
					"nMJBRSc/Zta0lojvlF+eSVLv2dX9Y3tkPvKqUjJy3z4VNYKiynMurbk3oFzFPYCl9JYfqtANk5M70WW+5H165bcmvImTanE5" +
					"0m+Hr6JPRIe1j/SbCGz65pQFsyHDw+Jqma2Kuige3TU9iHMUlzQSZDA==",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey2048,
					PublicKey:  testRsaPublicKey2048,
					Algorithm:  algoRsaSsaPssSha512,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-DUMMY unsupported algorithm type",
			args: args{
				alg:  RsaDummy{},
				sig:  "",
				data: nil,
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algoRsaSsaPssSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported verify algorithm type RSA-DUMMY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, _ := base64.StdEncoding.DecodeString(tt.args.sig)
			err := tt.args.alg.Verify(tt.args.secret, tt.args.data, sig)
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}
