# Httpsignatures.go

[![Linter & Tests](https://github.com/igor-pavlenko/httpsignatures.go/workflows/linter%20&%20tests/badge.svg?branch=master)](https://github.com/igor-pavlenko/httpsignatures.go/actions)
[![Codecov](https://codecov.io/gh/igor-pavlenko/httpsignatures.go/branch/master/graph/badge.svg)](https://codecov.io/gh/igor-pavlenko/httpsignatures.go)
[![Go Report Card](https://goreportcard.com/badge/github.com/igor-pavlenko/httpsignatures.go)](https://goreportcard.com/report/github.com/igor-pavlenko/httpsignatures.go)
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

`go get github.com/igor-pavlenko/httpsignatures.go`

To install a specific version, use:

`go get github.com/igor-pavlenko/httpsignatures.go@v0.0.1`

## Sign

## Verify

## Settings

### Custom Secrets Storage

### Custom Digest hash algorithm

### Default Digest algorithm

### Disable/Enable verify Digest function
If digest header set in signature headers — module will verify it. To disable verification use `SetDefaultVerifyDigest`
method.
```go
hs := NewHTTPSignatures(NewSimpleSecretsStorage(map[string]Secret{}))
hs.SetDefaultVerifyDigest(false)
```

### Custom Signature hash algorithm
You can set your custom signature hash algorithm by implementing the `SignatureHashAlgorithm` interface.

### Default expires seconds
By default, signature will expire in 30 seconds. You can set custom value for expiration using `SetDefaultExpiresSeconds`
method.
```go
hs := NewHTTPSignatures(NewSimpleSecretsStorage(map[string]Secret{}))
hs.SetDefaultExpiresSeconds(60)
```

### Default time gap for time expires/created verification
Default time gap is 10 seconds. To set custom time gap use `SetDefaultTimeGap` method.
```go
hs := NewHTTPSignatures(NewSimpleSecretsStorage(map[string]Secret{}))
hs.SetDefaultTimeGap(100)
````

### Default signature headers
By default, headers used in signature: ["(created)"]. Use `SetDefaultSignatureHeaders` method to set custom list
of headers.
```go
hs := NewHTTPSignatures(NewSimpleSecretsStorage(map[string]Secret{}))
hs.SetDefaultSignatureHeaders([]string{"(request-target)", "(created)", "(expires)", "date", "host", "digest"})
````

## Supported Signature hash algorithms
* RSASSA-PSS with SHA256
* RSASSA-PSS with SHA512
* ECDSA with SHA256
* RSA-SHA256
* RSA-SHA512
* HMAC-SHA256
* HMAC-SHA512

## Supported Digest hash algorithms
* MD5
* SHA256
* SHA512

## Todo:
* Gin plugin
* Add signature hash algorithm:
  * https://golang.org/pkg/crypto/ed25519/
