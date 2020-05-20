package httpsignatures

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

const cryptoErrType = "*httpsignatures.CryptoError"
const hashData = "hello world"

const rsaPrivateKey1024 = `-----BEGIN RSA PRIVATE KEY-----
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

const rsaPrivateKey2048 = `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBmTcYuCg3VSpw/5/z9iL5R15E08RBM7N6GT5MeSUK6q2VQyM7c
C6OmdyK0NZH3OoPliBPEk7+OSSmEgVzUiI5HVwC/sPtRqeqByrKi+8DUGNZo8fB4
Rs7+NoMzqw28gIaYuXcLiLtoTWrobxRPNpqwz/nmWMWfJKTRBOERJBhLPEatVQ4o
rBcQjFRXsAS4+6RuvDavJ3t5/iky2JNM6Dv2FomUlCGFjm1386eSSe8peLLx3hjk
+mqkKMSTMqWqdmYAhtPQZpUMdqSodw5SjtuVkBqs/nXt7vHlOp4mHv9fzB8xUN/h
Hin8mnsFz8RWgfIv+hxKwpEht6A4++miB94HAgMBAAECggEAQj9k8VVTZeZ9zihl
PKz7SbZFcroUKyxMYT9QbpFUY9svraOLyRTEcby+PWJfVnCPDukSm/5tUi9wcjzv
JzYSpIHjmz55UIWutUPUcBSE5xP6bFUXultoGVill6TSLVoxTt7zBwYRDdbsPv4H
cdBTVeIn2pFrz8WD8VKuiFIOZVEcYYEJJanARLPVJAZikQ4kZnvxPpmipX4YRyvZ
wJ3HLjn9FtLicf7kR9RR+6bDEV6zbJNlFp61hTTzCai6ShpLZjoeEWG5Ad0pRP+6
ZAAdrm/pz12bzWkl1qZEUssdDLNlRBbBlYijoO8Db2MxghgUMc4tHaYbAhEpntmW
VRshMQKBgQC6hTDMG94nAHXsGTlGYWNUZfMnkjMbhi+2TDDhdJ+g90dHucL8QHb/
bnTtXdWKFU6GFQg2NahE7snvZH/up3wUkIRJods0GIUhZnv91bPypJbFrJsP4bmj
i/EvfWvzkjCfM/p6LsZ4x8QKyw/KGFiSSVeEDgTXvripOWztO94T2QKBgQCMaZgp
nY2tYVvL4OU5ulf4d6F7xg49RcX7JHKwueDRHbk5zYvbttB3K+ewRSKctPEpBkWM
oSusVE29+RE9VNTArhP4lHQXlf23DJPpYfdzO12Gches8aF2L8K4u9+Co2vxQMiC
ls3kVnmsVntsHeE9bwbU/pifS+RDIWROnqC03wKBgFZxReVCgRmoP/6UzhONLQC/
YwqS2jbGYLRm6TyD1Ts/fvyB3hkUM1I8OdqMY1vkdgj0FGMzSPHxjQryk8viOUI6
m+SYK8QgHQsWuR4x/XzVxL6GOTMKFQPz5mpxASfYN8qAx3P626a8RmIOLBooYFwj
u3iLGrl2PZTH9XCZD1o5AoGAbel2oBThw3ezqMt6BA9XL3tN4BqwKMyGZsooMSi/
0FHpHVNGCI55bt/idDwaFPsa0BdFuAitrC8tz+i40v6lr9JUdcCXg6L4wSJKYmU6
k2xEEKsc11cqId7PGVaPZq7QH0Cr9HVh5DzA7+Oep4pYN4PCoFZPWFrK6rWn1Fcd
y5cCgYBW8CXDFEgjkCRgIgjpiJ4kMuBTboDBVRX4nz6j52hkiiDglIG3eSvqr0bj
ujWUiQswHwpF91tUjm6zsZleLt+EjJyJTKVjN9mqJES6U4KcMYs0p0rulmTYnYUD
UV6qwSI7mh5Q0ndPGiRg4ZgUkVI/JiiPuzXJ7MxF4OijXCzFHw==
-----END RSA PRIVATE KEY-----`

const rsaPublicKey1024 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

const rsaPublicKey2048 = `-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBmTcYuCg3VSpw/5/z9iL5R
15E08RBM7N6GT5MeSUK6q2VQyM7cC6OmdyK0NZH3OoPliBPEk7+OSSmEgVzUiI5H
VwC/sPtRqeqByrKi+8DUGNZo8fB4Rs7+NoMzqw28gIaYuXcLiLtoTWrobxRPNpqw
z/nmWMWfJKTRBOERJBhLPEatVQ4orBcQjFRXsAS4+6RuvDavJ3t5/iky2JNM6Dv2
FomUlCGFjm1386eSSe8peLLx3hjk+mqkKMSTMqWqdmYAhtPQZpUMdqSodw5SjtuV
kBqs/nXt7vHlOp4mHv9fzB8xUN/hHin8mnsFz8RWgfIv+hxKwpEht6A4++miB94H
AgMBAAE=
-----END PUBLIC KEY-----`

const algoRsaDummy = "RSA-DUMMY"

// RsaDummy RSA-DUMMY Algorithm
type RsaDummy struct{}

// Algorithm Return algorithm name
func (a RsaDummy) Algorithm() string {
	return algoRsaDummy
}

// Create Create dummy
func (a RsaDummy) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureRsaAlgorithmCreate(algoRsaDummy, sha256.New, crypto.SHA256, secret, data)
}

// Verify Verify dummy
func (a RsaDummy) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureRsaAlgorithmVerify(algoRsaDummy, sha256.New, crypto.SHA256, secret, data, signature)
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
				data: []byte(hashData),
			},
			want:        "5eb63bbbe01eeed093cb22bb8f5acdc3",
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "SHA256 create ok",
			args: args{
				alg:  Sha256{},
				data: []byte(hashData),
			},
			want:        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "SHA512 create ok",
			args: args{
				alg:  Sha512{},
				data: []byte(hashData),
			},
			want: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd8" +
				"30e81f605dcf7dc5542e93ae9cd76f",
			wantErrType: cryptoErrType,
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
				data:   []byte(hashData),
			},
			want: true,
		},
		{
			name: "MD5 wrong hash",
			args: args{
				alg:    Md5{},
				digest: "5eb",
				data:   []byte(hashData),
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: wrong hash",
		},
		{
			name: "Sha256 verify ok",
			args: args{
				alg:    Sha256{},
				digest: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
				data:   []byte(hashData),
			},
			want:        true,
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "Sha256 wrong hash",
			args: args{
				alg:    Sha256{},
				digest: "b94",
				data:   []byte(hashData),
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: wrong hash",
		},
		{
			name: "Sha512 verify ok",
			args: args{
				alg: Sha512{},
				digest: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45" +
					"b0cfd830e81f605dcf7dc5542e93ae9cd76f",
				data: []byte(hashData),
			},
			want:        true,
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "Sha512 wrong hash",
			args: args{
				alg:    Sha512{},
				digest: "309",
				data:   []byte(hashData),
			},
			want:        false,
			wantErrType: cryptoErrType,
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
			name: "RSA-PSS-SHA256 OK",
			arg:  RsaPssSha256{},
			want: "RSA-PSS-SHA256",
		},
		{
			name: "RSA-PSS-SHA512 OK",
			arg:  RsaPssSha512{},
			want: "RSA-PSS-SHA512",
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "RSA-SHA256 create ok",
			args: args{
				alg: RsaSha256{},
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: example.com\n" +
						"date: Sun, 05 Jan 2014 21:31:40 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaSha256,
				},
			},
			want: "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdK" +
				"FYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKCS1PrivateKey: asn1: syntax error: data truncated",
		},
		{
			name: "RSA-SHA512 create ok",
			args: args{
				alg: RsaSha512{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: example.com\n" +
						"date: Sun, 28 Apr 2020 00:47:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaSha512,
				},
			},
			want: "j2EgWL0QOEmWjsKXRu1MxfYe2CzjdyNkkqbagIYpBNqBg2kevrQSSIocgfESHHoIgayK+we2SRAB59wVEM3gtQuQ9ef1BikcX5" +
				"4GuqCThSA63kcuGXZzUgQcGnFpy2KO6gV2gl2cCkB8X6ZRY5oFfpiPvFxVY1bg/Y3DXlsKZb0=",
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-PSS-SHA256 create ok",
			args: args{
				alg: RsaPssSha256{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: example.net\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaPssSha256,
				},
			},
			want:        "",
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-PSS-SHA512 create ok",
			args: args{
				alg: RsaPssSha512{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: example.net\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: rsaPrivateKey2048,
					PublicKey:  rsaPublicKey2048,
					Algorithm:  algoRsaPssSha512,
				},
			},
			want:        "",
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-DUMMY unsupported algorithm type",
			args: args{
				alg:  RsaDummy{},
				data: nil,
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaDummy,
				},
			},
			want:        "",
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: unsupported algorithm type RSA-DUMMY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			// RSA-PSS Algorithm generate always different signature
			if tt.args.alg.Algorithm() == algoRsaPssSha256 {
				if len(sig) != 172 {
					t.Errorf(tt.name+"\ngot = %v, expected length = 172 symbols", got)
				}
				tt.want = sig
			} else if tt.args.alg.Algorithm() == algoRsaPssSha512 {
				if len(sig) != 344 {
					t.Errorf(tt.name+"\ngot = %v, expected length = 344 symbols", got)
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
						"host: example.com\n" +
						"date: Sun, 05 Jan 2014 21:31:40 GMT",
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaSha256,
				},
			},
			want:        true,
			wantErrType: cryptoErrType,
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
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaSha256,
				},
			},
			want:        false,
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
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
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: unknown type of public key",
		},
		{
			name: "RSA-PSS-SHA256 verify ok",
			args: args{
				alg: RsaPssSha256{},
				sig: "o77oM9o0bRYedX5a9+boS/1sX/xJBIdMRV89f2vZdeWRb3FGxdBKLDCZTV9ymvkQLxVdS2mdsxxPTTIQfEg2dahXb8DDCW" +
					"0xQtA2u9/N02P3CSnDXvymDMabVKrSixd2PUHdUZ2ikgqoDcqj2wuSLbVW3fAa0e1lqkTXkxfnyFE=",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: example.net\n" +
						"date: Sun, 28 Apr 2020 00:50:00 GMT",
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaPssSha256,
				},
			},
			want:        true,
			wantErrType: cryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-PSS-SHA256 wrong signature",
			args: args{
				alg:  RsaPssSha256{},
				sig:  "MTIz",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaPssSha256,
				},
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: error verify signature: crypto/rsa: verification error",
		},
		{
			name: "RSA-PSS-SHA256 no public key found",
			args: args{
				alg:    RsaPssSha256{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: no public key found",
		},
		{
			name: "RSA-PSS-SHA256 unsupported key type",
			args: args{
				alg:  RsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: unsupported key type NO PUBLIC KEY",
		},
		{
			name: "RSA-PSS-SHA256 error ParsePKIXPublicKey",
			args: args{
				alg:  RsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKIXPublicKey: asn1: syntax error: data truncated",
		},
		{
			name: "RSA-PSS-SHA256 unknown type of public key",
			args: args{
				alg:  RsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo
yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==
-----END PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: cryptoErrType,
			wantErrMsg:  "CryptoError: unknown type of public key",
		},
		{
			name: "RSA-DUMMY unsupported algorithm type",
			args: args{
				alg:  RsaDummy{},
				sig:  "",
				data: nil,
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: rsaPrivateKey1024,
					PublicKey:  rsaPublicKey1024,
					Algorithm:  algoRsaPssSha256,
				},
			},
			want:        false,
			wantErrType: cryptoErrType,
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
