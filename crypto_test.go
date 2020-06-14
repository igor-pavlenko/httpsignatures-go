package httpsignatures

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

const testCryptoErrType = "*httpsignatures.CryptoError"
const testHashData = "hello world"

type argsVerify struct {
	alg    SignatureHashAlgorithm
	sig    string
	data   []byte
	secret Secret
}

func verify(args argsVerify) (bool, error) {
	sig, _ := base64.StdEncoding.DecodeString(args.sig)
	err := args.alg.Verify(args.secret, args.data, sig)
	return err == nil, err
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
		{
			name: "ECDSA-SHA256 OK",
			arg:  EcdsaSha256{},
			want: "ECDSA-SHA256",
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

func TestSignatureHashHmacAlgorithmCreate(t *testing.T) {
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
					Algorithm:  algHmacSha256,
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
					Algorithm:  algHmacSha512,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			assert(t, sig, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashRsaAlgorithmCreate(t *testing.T) {
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
			name: "RSA-SHA256 create ok",
			args: args{
				alg: RsaSha256{},
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSha256,
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
			wantErrMsg:  "CryptoError: unsupported private key type SSH PRIVATE KEY",
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
			wantErrMsg:  "CryptoError: unsupported private key type RSA PRIVATE KEY",
		},
		{
			name: "RSA-SHA512 create ok",
			args: args{
				alg: RsaSha512{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSha512,
				},
			},
			want: "iz8UWbpy9oK5R2sdD5fIj8VphjkGTeMZ2YKGOiW77yBYS8TB5R/T3Knet4DlnvjAqZrWBDbN75d8/Ttf/bIMoZO0NFr60SBngB" +
				"zya6xnVIQ+0zoidBXpNjlttV2BDc44mrLvemk8Ar5NIiySNvKvKl7UNJxgKfT5UtGKDdry8qU=",
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
		{
			name: "RSA-SHA256 create ok",
			args: args{
				alg: RsaSha256{},
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSha256,
				},
			},
			want: "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdK" +
				"FYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			assert(t, sig, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashRsaSsaPssAlgorithmCreate(t *testing.T) {
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
			name: "RSASSA-PSS-SHA256 create ok",
			args: args{
				alg: RsaSsaPssSha256{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSsaPssSha256,
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
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey2048,
					PublicKey:  testRsaPublicKey2048,
					Algorithm:  algRsaSsaPssSha512,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			// RSASSA-PSS Algorithm generate always different signature
			var length = 0
			switch tt.args.alg.Algorithm() {
			case algRsaSsaPssSha256:
				length = 172
			case algRsaSsaPssSha512:
				length = 344
			}
			if len(sig) < length {
				t.Errorf(tt.name+"\ngot = %v, expected length = %d symbols, but got = %d", sig, length, len(sig))
			}
			tt.want = sig
			assert(t, sig, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashEcdsaAlgorithmCreate(t *testing.T) {
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
			name: "ECDSA-SHA256 create ok",
			args: args{
				alg: EcdsaSha256{},
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testECDSAPrivateKey,
					PublicKey:  testECDSAPublicKey,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "ECDSA-SHA256 no private key found",
			args: args{
				alg:    EcdsaSha256{},
				data:   []byte{},
				secret: Secret{},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
		{
			name: "ECDSA-SHA256 unsupported key type",
			args: args{
				alg:  EcdsaSha256{},
				data: []byte{},
				secret: Secret{
					PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----`,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported private key type RSA PRIVATE KEY",
		},
		{
			name: "ECDSA-SHA256 error ParseECPrivateKey",
			args: args{
				alg:  EcdsaSha256{},
				data: []byte{},
				secret: Secret{
					PrivateKey: `-----BEGIN EC PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
-----END EC PRIVATE KEY-----`,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported private key type EC PRIVATE KEY",
		},
		{
			name: "ECDSA-DUMMY unsupported algorithm type",
			args: args{
				alg:  EcdsaDummy{},
				data: nil,
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testECDSAPrivateKey,
					PublicKey:  testECDSAPublicKey,
					Algorithm:  testEcdsaDummyName,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported algorithm type ECDSA-DUMMY",
		},
		{
			name: "ECDSA-SHA256 unknown private key type",
			args: args{
				alg:  EcdsaSha256{},
				data: []byte{},
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        "",
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unknown private key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.alg.Create(tt.args.secret, tt.args.data)
			sig := base64.StdEncoding.EncodeToString(got)
			// Ecdsa Algorithm generate always different signature
			var length = 150
			if err == nil {
				if len(sig) < length {
					t.Errorf(tt.name+"\ngot = %v, expected length = %d symbols, but got = %d", sig, length, len(sig))
				}
				tt.want = sig
			}
			assert(t, sig, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashHmacAlgorithmVerify(t *testing.T) {
	tests := []struct {
		name        string
		args        argsVerify
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "HMAC-SHA256 verify ok",
			args: argsVerify{
				alg:  HmacSha256{},
				sig:  "7lksEgztUSEk34sJ8vGQpE0i+UK+ZexCQ0L8HpHBBJY=",
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algHmacSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "HMAC-SHA256 wrong signature",
			args: argsVerify{
				alg:  HmacSha256{},
				sig:  "MTIz",
				data: []byte("xx"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algHmacSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong signature",
		},
		{
			name: "HMAC-SHA256 no private key found",
			args: argsVerify{
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
			args: argsVerify{
				alg:  HmacSha512{},
				sig:  "xhrfZlhd8heV7O4w1nPbNRYdWSc2Qg8RuruZ5jDDHbVzSgd4NQOePJWN5xIKz74U/HhlLe138G8VLcH5atTZTg==",
				data: []byte("(request-target): post /foo?param=value&pet=dog"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algHmacSha512,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "HMAC-SHA512 wrong signature",
			args: argsVerify{
				alg:  HmacSha512{},
				sig:  "MTIz",
				data: []byte("xx"),
				secret: Secret{
					PrivateKey: "secret",
					Algorithm:  algHmacSha512,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: wrong signature",
		},
		{
			name: "HMAC-SHA512 no private key found",
			args: argsVerify{
				alg:    HmacSha512{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no private key found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(tt.args)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashRsaAlgorithmVerify(t *testing.T) {
	tests := []struct {
		name        string
		args        argsVerify
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "RSA-SHA256 verify ok",
			args: argsVerify{
				alg: RsaSha256{},
				sig: "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8V" +
					"fEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
				data: []byte(
					"(request-target): post /foo?param=value&pet=dog\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-SHA256 wrong signature",
			args: argsVerify{
				alg:  RsaSha256{},
				sig:  "MTIz",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key3",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error verify signature: crypto/rsa: verification error",
		},
		{
			name: "RSA-SHA256 no public key found",
			args: argsVerify{
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
			args: argsVerify{
				alg:  RsaSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKIXPublicKey: asn1: syntax error: sequence truncated",
		},
		{
			name: "RSA-SHA256 error ParsePKIXPublicKey",
			args: argsVerify{
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
			args: argsVerify{
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
			args: argsVerify{
				alg: RsaSha512{},
				sig: "iz8UWbpy9oK5R2sdD5fIj8VphjkGTeMZ2YKGOiW77yBYS8TB5R/T3Knet4DlnvjAqZrWBDbN75d8/Ttf/bIMoZO0NFr60SB" +
					"ngBzya6xnVIQ+0zoidBXpNjlttV2BDc44mrLvemk8Ar5NIiySNvKvKl7UNJxgKfT5UtGKDdry8qU=",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSha512,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSA-DUMMY unsupported algorithm type",
			args: argsVerify{
				alg:  RsaDummy{},
				sig:  "",
				data: nil,
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSsaPssSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported verify algorithm type RSA-DUMMY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(tt.args)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashRsaSsaPssAlgorithmVerify(t *testing.T) {
	tests := []struct {
		name        string
		args        argsVerify
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "RSASSA-PSS-SHA256 verify ok",
			args: argsVerify{
				alg: RsaSsaPssSha256{},
				sig: "s87lgQ4Uw6+uIeXwREqNwWpYyCZmVUbMFrORiNg90RDFA9RuSHY0ACKNyk6oNKYd88ve0rsA+3ZYPXYl7n81kMC/LfWDOxm" +
					"ZkIKemGG9mYnbU6ArcN6AIxE0POuY60WrgqXdAZeUzW0fIxP4eM/93B4y2vCjBxwNPZoe2YDAPDs=",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSsaPssSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "RSASSA-PSS-SHA256 wrong signature",
			args: argsVerify{
				alg:  RsaSsaPssSha256{},
				sig:  "MTIz",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algRsaSsaPssSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error verify signature: crypto/rsa: verification error",
		},
		{
			name: "RSASSA-PSS-SHA256 no public key found",
			args: argsVerify{
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
			args: argsVerify{
				alg:  RsaSsaPssSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKIXPublicKey: asn1: syntax error: sequence truncated",
		},
		{
			name: "RSASSA-PSS-SHA256 error ParsePKIXPublicKey",
			args: argsVerify{
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
			args: argsVerify{
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
			args: argsVerify{
				alg: RsaSsaPssSha512{},
				sig: "DKqEARe39kCtFwKrMi82soguuwhY1C0wl4VUAFk4EzK3m/OFLMHgnqdJHeIGkJQPRfYsX/Mx78SR9wlt/n1xPu3GR+h8PVR" +
					"NHA9ktsRdcG1BhoX+yZiB7X2ccDzp7D9olf2saii3y38Mp9YajNwBT8lnzIyAEn8Mxyjo0bWGMMo0v1GkhdQVkyOnacB+Gsl" +
					"ADp02tMgXFQi4UwqgXKqKI1tFQ1XUhSk8rJK40H1ieQlrprZIstN3YSZmwb6j/uxZVCBnCPCuRcARWMvWnT2DNZPJPVYEahn" +
					"6X1fxcG2UN/ETk3bT9G1CzIQtw8fz2CigbqtywA5gERFL27RhWbMdJg==",
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey2048,
					PublicKey:  testRsaPublicKey2048,
					Algorithm:  algRsaSsaPssSha512,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(tt.args)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestSignatureHashEcdsaAlgorithmVerify(t *testing.T) {

	const correctSignature = "MIGIAkIAnTM1VJZyCS2Sd+2rlWpy/a7NIce2zHrTw69m1pgk6Z500eSXE4ng5inyV3yvAmjhepzDGsZ0Ip4incq" +
		"6WtUoyrICQgFaYvlJceahh4rTvYdyO8lZhA00EGrLN8pBgx0pMxf1kvjCnLou6R03jB30ZFsOvbL2PSkSUalLXYMh4tunkVMyBg=="

	tests := []struct {
		name        string
		args        argsVerify
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "ECDSA-SHA256 verify ok",
			args: argsVerify{
				alg: EcdsaSha256{},
				sig: correctSignature,
				data: []byte(
					"(request-target): post /foo\n" +
						"host: " + testHostExample + "\n" +
						"date: " + testDateExample,
				),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testECDSAPrivateKey,
					PublicKey:  testECDSAPublicKey,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        true,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "",
		},
		{
			name: "ECDSA-SHA256 wrong signature",
			args: argsVerify{
				alg: EcdsaSha256{},
				sig: "MIGIAkIAnTM1VJZyCS2Sd+2rlWpy/a7NIce2zHrTw69m1pgk6Z500eSXE4ng5inyV3yvAmjhepzDGsZ0Ip4incq6WtUoyr" +
					"ICQgFaYvlJceahh4rTvYdyO8lZhA00EGrLN8pBgx0pMxf1kvjCnLou6R03jB30ZFsOvbL2PSkSUalLXYMh4tunkVMyBg==",
				data: []byte("test"),
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testECDSAPrivateKey,
					PublicKey:  testECDSAPublicKey,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: signature verification error",
		},
		{
			name: "ECDSA-SHA256 no public key found",
			args: argsVerify{
				alg:    EcdsaSha256{},
				sig:    "",
				data:   []byte{},
				secret: Secret{},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: no public key found",
		},
		{
			name: "ECDSA-SHA256 unsupported key type",
			args: argsVerify{
				alg:  EcdsaSha256{},
				data: []byte{},
				secret: Secret{
					PublicKey: `-----BEGIN NO PUBLIC KEY-----
-----END NO PUBLIC KEY-----`,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: error ParsePKIXPublicKey: asn1: syntax error: sequence truncated",
		},
		{
			name: "ECDSA-SHA256 error ParsePKIXPublicKey",
			args: argsVerify{
				alg:  EcdsaSha256{},
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
			name: "ECDSA-SHA256 error wrong public key",
			args: argsVerify{
				alg:  EcdsaSha256{},
				data: []byte{},
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testRsaPrivateKey1024,
					PublicKey:  testRsaPublicKey1024,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unknown type of public key",
		},
		{
			name: "ECDSA-SHA256 error Unmarshal signature",
			args: argsVerify{
				alg:  EcdsaSha256{},
				sig:  "MTIz",
				data: []byte{},
				secret: Secret{
					KeyID:      "key1",
					PrivateKey: testECDSAPrivateKey,
					PublicKey:  testECDSAPublicKey,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg: "CryptoError: error Unmarshal signature: asn1: structure error: tags don't match (16 vs " +
				"{class:0 tag:17 length:50 isCompound:true}) {optional:false explicit:false application:false " +
				"private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false}" +
				" ECDSASignature @2",
		},
		{
			name: "ECDSA-DUMMY unsupported algorithm type",
			args: argsVerify{
				alg:  EcdsaDummy{},
				sig:  correctSignature,
				data: nil,
				secret: Secret{
					KeyID:      "key2",
					PrivateKey: testECDSAPrivateKey,
					PublicKey:  testECDSAPublicKey,
					Algorithm:  algEcdsaSha256,
				},
			},
			want:        false,
			wantErrType: testCryptoErrType,
			wantErrMsg:  "CryptoError: unsupported verify algorithm type ECDSA-DUMMY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(tt.args)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}
