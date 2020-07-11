package main

import (
	"fmt"
	"github.com/igor-pavlenko/httpsignatures.go"
	"net/http"
	"strings"
)

func main() {
	const sKey = "key1"
	// Don't put keys into code, neither push it in to git repo (this is just for example)
	secrets := map[string]httpsignatures.Secret{
		sKey: {
			KeyID: sKey,
			PublicKey: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`,
			PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`,
			Algorithm: "RSA-SHA256",
		},
	}
	ss := httpsignatures.NewSimpleSecretsStorage(secrets)
	hs := httpsignatures.NewHTTPSignatures(ss)

	r, _ := http.NewRequest(
		"POST",
		"https://example.com/foo?param=value&pet=dog",
		strings.NewReader(`{"hello": "world"}`),
	)
	r.Header.Set("Digest", "SHA-512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==")
	r.Header.Set("Signature", `keyId="key1",algorithm="RSA-SHA256",created=1594222776,headers="(created) digest (request-target)",signature="HobdANH0pDuVm9ag0Zdy06+1wgPttgSqJIiBI0wmgILrJ3IlZ26KuHPGNTZs2N55SFHCpE1gLnmyKJwLF46hmgdElB7zFreYAGmNhukguoIiQ8slZnOjs2GtZ40kHa+7kO5mqT+i5GaRKwBtRiiFe3nEPxEmrugXEwj5j6DEvl8="`)

	err := hs.Verify(r)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature verified")
}
