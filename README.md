# Httpsignatures-go

[![Linter & Tests](https://github.com/igor-pavlenko/httpsignatures-go/workflows/linter%20&%20tests/badge.svg?branch=master)](https://github.com/igor-pavlenko/httpsignatures-go/actions)
[![Codecov](https://codecov.io/gh/igor-pavlenko/httpsignatures.go/branch/master/graph/badge.svg)](https://codecov.io/gh/igor-pavlenko/httpsignatures.go)
[![Go Report Card](https://goreportcard.com/badge/github.com/igor-pavlenko/httpsignatures-go)](https://goreportcard.com/report/github.com/igor-pavlenko/httpsignatures-go)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=igor-pavlenko_httpsignatures.go&metric=alert_status)](https://sonarcloud.io/dashboard?id=igor-pavlenko_httpsignatures.go)

This module is created to provide a simple solution to sign HTTP messages according to the document:

https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00

## Versions compatibility
Since the current standard is still in draft mode and will have a few iterations (versions) before becoming stable, 
the project is going to maintain current and future versions.

To be compatible with ietf.org versioning the project will change only MINOR & PATCH versions, 
until document final release. A MINOR version will be equal to the draft version. A PATCH version will be used for bug 
fixes & improvements and will not break backward compatibility with IETF version.

For example:

The Document version                          | Httpsignatures.go
----------------------------------------------|-------------------
draft-ietf-httpbis-message-signatures-00      | v0.0.1
draft-ietf-httpbis-message-signatures-{MINOR} | v0.{MINOR}.0
Final release                                 | v1.0.0

## Installation
To install the module:

`go get github.com/igor-pavlenko/httpsignatures-go`

To install a specific version, use:

`go get github.com/igor-pavlenko/httpsignatures-go@v0.0.14`

Don't forget: `export GO111MODULE=on`

## Sign
```go
package main

import (
	"fmt"
	"github.com/igor-pavlenko/httpsignatures-go"
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
-----END PUBLIC KEY-----`,
			PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----`,
			Algorithm: "RSA-SHA256",
		},
	}
	ss := httpsignatures.NewSimpleSecretsStorage(secrets)
	hs := httpsignatures.NewHTTPSignatures(ss)
	hs.SetDefaultSignatureHeaders([]string{"(created)", "digest", "(expires)", "(request-target)"})

	r, _ := http.NewRequest(
		"POST",
		"https://example.com/foo?param=value&pet=dog",
		strings.NewReader(`{"hello": "world"}`),
	)
	err := hs.Sign(sKey, r)
	if err != nil {
		panic(err)
	}

	fmt.Println(r.Header.Get("Digest"))
	fmt.Println(r.Header.Get("Signature"))
}
```

## Verify
```go
package main

import (
	"fmt"
	"github.com/igor-pavlenko/httpsignatures-go"
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
-----END PUBLIC KEY-----`,
			PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
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
```

## Settings
### Custom Secrets Storage
If you have a lot of keys, you can get them from any external storage, for example: DB, Files, Vaults etc.
Just implement `Secrets` interface and inject it into `httpsignatures.NewHTTPSignatures()`.
```go
package main

import (
	"fmt"
	"github.com/igor-pavlenko/httpsignatures-go"
	"io/ioutil"
	"os"
	"regexp"
)

// To create your own secrets storage implement the httpsignatures.Secrets interface
// type Secrets interface {
//	   Get(keyID string) (Secret, error)
// }

const alg = "RSA-SHA512"

// SimpleSecretsStorage local static secrets storage
type FileSecretsStorage struct {
	dir     string
	storage map[string]httpsignatures.Secret
}

// Get get secret from local files by KeyID
func (s FileSecretsStorage) Get(keyID string) (httpsignatures.Secret, error) {
	if secret, ok := s.storage[keyID]; ok {
		return secret, nil
	}

	validKeyID, err := regexp.Match(`[a-zA-Z0-9]+`, []byte(keyID))
	if !validKeyID {
		return httpsignatures.Secret{}, &httpsignatures.SecretError{Message: "wrong keyID format allowed: [a-zA-Z0-9]+"}
	}

	publicKeyFile := fmt.Sprintf("%s/%s.pub", s.dir, keyID)
	publicKey, err := s.readFile(publicKeyFile)
	if err != nil {
		return httpsignatures.Secret{}, &httpsignatures.SecretError{Message: "public key file not found", Err: err}
	}

	privateKeyFile := fmt.Sprintf("%s/%s.key", s.dir, keyID)
	privateKey, err := s.readFile(privateKeyFile)
	if err != nil {
		return httpsignatures.Secret{}, &httpsignatures.SecretError{Message: "private key file not found", Err: err}
	}

	fmt.Println(privateKey, publicKey)
	s.storage[keyID] = httpsignatures.Secret{
		KeyID:      keyID,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Algorithm:  alg,
	}
	return s.storage[keyID], nil
}

// Get key from file
func (s FileSecretsStorage) readFile(f string) (string, error) {
	if !s.fileExists(f) {
		return "", &httpsignatures.SecretError{Message: fmt.Sprintf("file '%s' not found", f)}
	}
	key, err := ioutil.ReadFile(f)
	if err != nil {
		return "", &httpsignatures.SecretError{Message: fmt.Sprintf("read file error: '%s'", f), Err: err}
	}

	return string(key), nil
}

// Check if file exists
func (s FileSecretsStorage) fileExists(f string) bool {
	i, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !i.IsDir()
}

// NewSimpleSecretsStorage create new digest
func NewFileSecretsStorage(dir string) httpsignatures.Secrets {
    if len(dir) == 0 {
		return nil
	}
	s := new(FileSecretsStorage)
	s.dir = dir
	s.storage = make(map[string]httpsignatures.Secret)
	return s
}

func main() {
	hs := httpsignatures.NewHTTPSignatures(NewFileSecretsStorage("/tmp"))
	hs.SetDefaultExpiresSeconds(10)
}
```

### AWS Secrets Manager Storage
It's good practice to store private/public keys in secrets storage like AWS Secrets Manager, Vault by HashiCorp, or any other service. So you need to get keys by request.

Some use cases, service used to:
* validate incoming requests from other services (it needs only public keys)
* sign self outgoing requests (signed by itself. So it needs only self private key)
* sign outgoing requests on behalf of other services (it needs all private keys of served services)
* validate other service requests & sign self requests (it needs access to self private keys & only public keys of served services)

#### How to store keys in Secrets Manager
Keys should be stored as binary. Name pattern: "/<ENV>/<Service KeyID>/<PrivateKey|PublicKey|Algorithm>".
Where <ENV> — environment (for example: prod, dev, sandbox, staging etc), <Service KeyID> — service identifier used
as KeyID in requests, <PrivateKey|PublicKey|Algorithm> — key type, can be only PrivateKey, PublicKey, Algorithm.
```
aws secretsmanager create-secret --name "/dev/myServiceID/PrivateKey" \
    --description "Private Key for service with keyID = myServiceID" \
    --secret-binary file://private.key

aws secretsmanager create-secret --name "/dev/myServiceID/PublicKey" \
    --description "Public Key for service with keyID = myServiceID" \
    --secret-binary file://public.pub

# In case services use different signature algorithms, store it also in Secrets Manager
# If you have only one algorithm for all services, set it as a parameter (see below).
aws secretsmanager create-secret --name "/dev/myServiceID/Algorithm" \
    --description "Algorithm for service with keyID = myServiceID" \
    --secret-binary file://algorithm.txt
```

If you have only one algorithm for all services, set it as a parameter and do not store the algorithm name in Secrets Manager:
```go
//...
sm := NewAwsSecretsManagerStorage("prod", secretsManager)
sm.SetAlgorithm("RSA-SHA512")
//...
```

#### Validate incoming requests
To validate incoming requests you need only PublicKey. PrivateKey & Algorithm can be omitted:
```go
//...
sm := NewAwsSecretsManagerStorage("prod", secretsManager)
// Omit Algorithm 
sm.SetAlgorithm("RSA-SHA512")
// To skip private keys for all services, you have to define not empty map with "*" KeyID and set it to false
sm.SetRequiredPrivateKeys(map[string]bool{"*": false})
//...
```

#### Sign self outgoing requests or sign outgoing requests on behalf of other services
To sign outgoing requests you need only PrivateKey. PublicKey & Algorithm can be omitted:
```go
//...
sm := NewAwsSecretsManagerStorage("prod", secretsManager)
// Omit Algorithm 
sm.SetAlgorithm("RSA-SHA512")
// To skip public keys for all services, you have to define not empty map with "*" KeyID and set it to false
sm.SetRequiredPublicKeys(map[string]bool{"*": false})
//...
```

#### Validate other service requests & sign self requests
To sign self outgoing requests you need only PrivateKey. PublicKey & Algorithm can be omitted.
To validate other services incoming requests you need only PublicKeys, PrivateKeys & Algorithms can be omitted:
```go
//...
sm := NewAwsSecretsManagerStorage("prod", secretsManager)
// Omit Algorithm 
sm.SetAlgorithm("RSA-SHA512")
// Set required PrivateKey only for service with keyID = MyselfKeyID (current service).
// You don't need PrivateKeys to validate incoming requests (and you don't have permissions to get PrivateKeys)
sm.SetRequiredPrivateKeys(map[string]bool{"MyselfKeyID": true})
// You don't need self PublicKey, but PublicKeys of other services are required.
sm.SetRequiredPublicKeys(map[string]bool{"MyselfKeyID": false})
//...
```

### Custom Digest hash algorithm
You can set your custom signature hash algorithm by implementing the `DigestHashAlgorithm` interface.
```go
package main

import (
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"github.com/igor-pavlenko/httpsignatures-go"
)

// To create new digest algorithm, implement httpsignatures.DigestHashAlgorithm interface
// type DigestHashAlgorithm interface {
//	 Algorithm() string
//	 Create(data []byte) ([]byte, error)
// 	 Verify(data []byte, digest []byte) error
// }

// Digest algorithm name
const algSha1Name = "sha1"

// algSha1 sha1 Algorithm
type algSha1 struct{}

// Return algorithm name
func (a algSha1) Algorithm() string {
	return algSha1Name
}

// Create hash
func (a algSha1) Create(data []byte) ([]byte, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, &httpsignatures.CryptoError{Message: "error creating hash", Err: err}
	}
	return h.Sum(nil), nil
}

// Verify hash
func (a algSha1) Verify(data []byte, digest []byte) error {
	expected, err := a.Create(data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return &httpsignatures.CryptoError{Message: "wrong hash"}
	}
	return nil
}

func main() {
	hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
	// Add algorithm implementation
	hs.SetDigestAlgorithm(algSha1{})
	// Set `algSha1Name` as default algorithm for digest
	err := hs.SetDefaultDigestAlgorithm(algSha1Name)
	if err != nil {
		fmt.Println(err)
	}
}
```

### Default Digest algorithm
Choose one of supported digest hash algorithms with method `SetDefaultDigestAlgorithm`.
```go
hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
hs.SetDefaultDigestAlgorithm("MD5")
```

### Disable/Enable verify Digest function
If digest header set in signature headers — module will verify it. To disable verification use `SetDefaultVerifyDigest`
method.
```go
hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
hs.SetDefaultVerifyDigest(false)
```

### Custom Signature hash algorithm
You can set your own custom signature hash algorithm by implementing the `SignatureHashAlgorithm` interface.
```go
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"github.com/igor-pavlenko/httpsignatures-go"
)

// To create your own signature hash algorithm, implement httpsignatures.SignatureHashAlgorithm interface
// type SignatureHashAlgorithm interface {
// 	   Algorithm() string
// 	   Create(secret Secret, data []byte) ([]byte, error)
// 	   Verify(secret Secret, data []byte, signature []byte) error
// }

// Digest algorithm name
const algHmacSha1Name = "HMAC-SHA1"

// algHmacSha1 HMAC-SHA1 Algorithm
type algHmacSha1 struct{}

// Return algorithm name
func (a algHmacSha1) Algorithm() string {
	return algHmacSha1Name
}

// Create hash
func (a algHmacSha1) Create(secret httpsignatures.Secret, data []byte) ([]byte, error) {
	if len(secret.PrivateKey) == 0 {
		return nil, &httpsignatures.CryptoError{Message: "no private key found"}
	}
	mac := hmac.New(sha1.New, []byte(secret.PrivateKey))
	_, err := mac.Write(data)
	if err != nil {
		return nil, &httpsignatures.CryptoError{Message: "error creating signature", Err: err}
	}
	return mac.Sum(nil), nil
}

// Verify hash
func (a algHmacSha1) Verify(secret httpsignatures.Secret, data []byte, signature []byte) error {
	expected, err := a.Create(secret, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expected) {
		return &httpsignatures.CryptoError{Message: "wrong signature"}
	}
	return nil
}

func main() {
	hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
	hs.SetSignatureHashAlgorithm(algHmacSha1{})
}
```

### Default expires seconds
By default, signature will expire in 30 seconds. You can set custom value for expiration using 
`SetDefaultExpiresSeconds` method.
```go
hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
hs.SetDefaultExpiresSeconds(60)
```

### Default time gap for expires/created time verification
Default time gap is 10 seconds. To set custom time gap use `SetDefaultTimeGap` method.
```go
hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
hs.SetDefaultTimeGap(100)
````

### Default signature headers
By default, headers used in signature: ["(created)"]. Use `SetDefaultSignatureHeaders` method to set custom headers 
list.
```go
hs := httpsignatures.NewHTTPSignatures(httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{}))
hs.SetDefaultSignatureHeaders([]string{"(request-target)", "(created)", "(expires)", "date", "host", "digest"})
````

## Supported Signature hash algorithms
* RSASSA-PSS with SHA256
* RSASSA-PSS with SHA512
* ECDSA with SHA256
* ECDSA with SHA512
* RSA-SHA256
* RSA-SHA512
* HMAC-SHA256
* HMAC-SHA512
* ED25519

## Supported Digest hash algorithms
* MD5
* SHA256
* SHA512

## Examples
Look at [examples](https://github.com/igor-pavlenko/httpsignatures-go/tree/master/examples) & tests to find out how to work with lib.

## Todo
- [ ] Gin plugin
- [x] [AwsSecretsManagerStorage plugin](https://github.com/igor-pavlenko/httpsignatures-go/tree/master/aws)