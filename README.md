# Httpsignatures

[![Linter & Tests](https://github.com/igor-pavlenko/httpsignatures.go/workflows/linter%20&%20tests/badge.svg?branch=master)](https://github.com/igor-pavlenko/httpsignatures.go/actions)
[![Codecov](https://codecov.io/gh/igor-pavlenko/httpsignatures.go/branch/master/graph/badge.svg)](https://codecov.io/gh/igor-pavlenko/httpsignatures.go)
[![Go Report Card](https://goreportcard.com/badge/github.com/igor-pavlenko/httpsignatures.go)](https://goreportcard.com/report/github.com/igor-pavlenko/httpsignatures.go)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=igor-pavlenko_httpsignatures.go&metric=alert_status)](https://sonarcloud.io/dashboard?id=igor-pavlenko_httpsignatures.go)

This module is created to provide a simple solution to sign HTTP messages according to document:

https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00

### @todo:
* Tests
* Crypto
  * https://golang.org/pkg/crypto/ecdsa/
  * https://golang.org/pkg/crypto/ed25519/
* Documentation
* Gin plugin