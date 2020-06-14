package httpsignatures

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const testBodyExample = `{"hello": "world"}`
const testFullHostExample = "https://example.com"
const testHostExamplePath = "https://example.com/foo"
const testHostExampleFullPath = "https://example.com/foo?param=value&pet=dog"
const testHostExample = "example.com"
const testDateExample = "Sun, 05 Jan 2014 21:31:40 GMT"
const testContentTypeHeader = "Content-Type"
const testContentTypeJSON = "application/json"

const testRsaPrivateKey1024 = `-----BEGIN RSA PRIVATE KEY-----
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

const testRsaPrivateKey2048 = `-----BEGIN RSA PRIVATE KEY-----
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

const testECDSAPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAitPY7vFYgUY71qlXk8ujTpJqzYz8dkYP/hXxMT6JBsZiqf4vhuZI
VDgkIwCgsUQ5U+x1+25gsY/pOOEJKDBKQ7OgBwYFK4EEACOhgYkDgYYABAFKT4ww
5WDrV2vaOIb5m8OK09wkOqQ8DHlvgKjLznCwM0F54n6nGXyErSeMNWeoag9Is7B9
6QMkXPyfZv4ZUL8MKgFYR9QrgDPXQswDxDQ4OWn06eBw0Tp+3CggnkcbkDhrgEK/
BMxUHKgNNKMfDoisg1AaIKGYjiBQzUju58j0P1LoHQ==
-----END EC PRIVATE KEY-----`

const testRsaPublicKey1024 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

const testRsaPublicKey2048 = `-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBmTcYuCg3VSpw/5/z9iL5R
15E08RBM7N6GT5MeSUK6q2VQyM7cC6OmdyK0NZH3OoPliBPEk7+OSSmEgVzUiI5H
VwC/sPtRqeqByrKi+8DUGNZo8fB4Rs7+NoMzqw28gIaYuXcLiLtoTWrobxRPNpqw
z/nmWMWfJKTRBOERJBhLPEatVQ4orBcQjFRXsAS4+6RuvDavJ3t5/iky2JNM6Dv2
FomUlCGFjm1386eSSe8peLLx3hjk+mqkKMSTMqWqdmYAhtPQZpUMdqSodw5SjtuV
kBqs/nXt7vHlOp4mHv9fzB8xUN/hHin8mnsFz8RWgfIv+hxKwpEht6A4++miB94H
AgMBAAE=
-----END PUBLIC KEY-----`

const testECDSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBSk+MMOVg61dr2jiG+ZvDitPcJDqk
PAx5b4Coy85wsDNBeeJ+pxl8hK0njDVnqGoPSLOwfekDJFz8n2b+GVC/DCoBWEfU
K4Az10LMA8Q0ODlp9OngcNE6ftwoIJ5HG5A4a4BCvwTMVByoDTSjHw6IrINQGiCh
mI4gUM1I7ufI9D9S6B0=
-----END PUBLIC KEY-----`

var (
	testGetDigestRequestFunc = func(b string, h string) *http.Request {
		r, _ := http.NewRequest(http.MethodPost, testFullHostExample, strings.NewReader(b))
		if len(h) > 0 {
			r.Header.Set("Digest", h)
		}
		return r
	}
)

const (
	testAlgName        = "TEST"
	testErrAlgName     = "ERR"
	testRsaDummyName   = "RSA-DUMMY"
	testRsaErrName     = "RSA-ERR"
	testEcdsaDummyName = "ECDSA-DUMMY"
)

type testAlg struct{}

func (a testAlg) Algorithm() string {
	return testAlgName
}

func (a testAlg) Create(data []byte) ([]byte, error) {
	return []byte{}, nil
}

func (a testAlg) Verify(data []byte, digest []byte) error {
	return nil
}

type testErrAlg struct{}

func (a testErrAlg) Algorithm() string {
	return testErrAlgName
}

func (a testErrAlg) Create(data []byte) ([]byte, error) {
	return []byte{}, errors.New("create hash error")
}

func (a testErrAlg) Verify(data []byte, digest []byte) error {
	return errors.New("verify hash error")
}

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

// EcdsaDummy ECDSA-DUMMY Algorithm
type EcdsaDummy struct{}

// Algorithm Return algorithm name
func (a EcdsaDummy) Algorithm() string {
	return testEcdsaDummyName
}

// Create Create dummy
func (a EcdsaDummy) Create(secret Secret, data []byte) ([]byte, error) {
	return signatureEcdsaAlgorithmCreate(testEcdsaDummyName, sha256.New, secret, data)
}

// Verify Verify dummy
func (a EcdsaDummy) Verify(secret Secret, data []byte, signature []byte) error {
	return signatureEcdsaAlgorithmVerify(testEcdsaDummyName, sha256.New, secret, data, signature)
}

// TestRsaErr algorithm with errors
type TestRsaErr struct{}

// Algorithm Return algorithm name
func (a TestRsaErr) Algorithm() string {
	return testRsaErrName
}

// Create Create dummy
func (a TestRsaErr) Create(secret Secret, data []byte) ([]byte, error) {
	return nil, errors.New("create error")
}

// Verify Verify dummy
func (a TestRsaErr) Verify(secret Secret, data []byte, signature []byte) error {
	return errors.New("verify error")
}

var testSecretsStorage = NewSecretsStorage(map[string]Secret{
	"Test": {
		KeyID:      "Test",
		PrivateKey: testRsaPrivateKey1024,
		PublicKey:  testRsaPublicKey1024,
		Algorithm:  "RSA-SHA256",
	},
	"NotSupported": {
		KeyID:     "NotSupported",
		Algorithm: testRsaDummyName,
	},
	"Err": {
		KeyID:     "Err",
		Algorithm: testRsaErrName,
	},
})

func assert(t *testing.T, got interface{}, err error, eType string, name string, want interface{}, wantErrMsg string) {
	if err != nil && reflect.TypeOf(err).String() != eType {
		t.Errorf(name+"\ngot error type %s, expected %s", reflect.TypeOf(err).String(), eType)
	}
	if err != nil && err.Error() != wantErrMsg {
		t.Errorf(name+"\nerror message = `%s`, wantErrMsg = `%s`", err.Error(), wantErrMsg)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(name+"\ngot  = %v,\nwant = %v", got, want)
	}
}
