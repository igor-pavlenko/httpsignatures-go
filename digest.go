package httpsignatures

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// DigestError errors during digest verification
type DigestError struct {
	Message string
	Err     error
}

// Error error message
func (e *DigestError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("DigestError: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("DigestError: %s", e.Message)
}

// Digest digest internal struct
type Digest struct {
	parsedDigestHeader DigestHeader
	defaultAlg         string
	alg                map[string]DigestHashAlgorithm
}

// NewDigest create new digest
func NewDigest() *Digest {
	d := new(Digest)
	d.defaultAlg = algoSha512
	d.alg = map[string]DigestHashAlgorithm{
		algoMd5:    Md5{},
		algoSha256: Sha256{},
		algoSha512: Sha512{},
	}
	return d
}

// SetDigestHashAlgorithm set digest options (add new digest hash algorithm)
func (d *Digest) SetDigestHashAlgorithm(a DigestHashAlgorithm) {
	d.alg[strings.ToUpper(a.Algorithm())] = a
}

// SetDefaultDigestHashAlgorithm set digest default algorithm options (default from available)
func (d *Digest) SetDefaultDigestHashAlgorithm(a string) error {
	_, ok := d.alg[strings.ToUpper(a)]
	if !ok {
		return &DigestError{
			fmt.Sprintf("unsupported default digest hash algorithm '%s'", a),
			nil,
		}
	}
	d.defaultAlg = a
	return nil
}

// Verify verify digest header (compare with real request body hash)
func (d *Digest) Verify(r *http.Request) error {
	var err error
	var pErr *ParserError
	var dErr *DigestError

	header := r.Header.Get(digestHeader)
	p := NewParser()
	d.parsedDigestHeader, pErr = p.ParseDigestHeader(header)
	if pErr != nil {
		return pErr
	}

	h, ok := d.alg[strings.ToUpper(d.parsedDigestHeader.algo)]
	if !ok {
		return &DigestError{
			fmt.Sprintf("unsupported digest hash algorithm '%s'", d.parsedDigestHeader.algo),
			nil,
		}
	}

	b, dErr := d.readBody(r)
	if dErr != nil {
		return dErr
	}

	digest, err := base64.StdEncoding.DecodeString(d.parsedDigestHeader.digest)
	if err != nil {
		return &DigestError{
			"error decode digest from base64",
			err,
		}
	}
	err = h.Verify(b, digest)
	if err != nil {
		return &DigestError{
			"wrong digest",
			err,
		}
	}

	return nil
}

// Create create digest hash
func (d *Digest) Create(alg string, r *http.Request) (string, error) {
	// Does it support digest algorithm
	h, ok := d.alg[strings.ToUpper(alg)]
	if !ok {
		return "", &DigestError{
			fmt.Sprintf("unsupported digest hash algorithm '%s'", alg),
			nil,
		}
	}

	// Get body from request
	b, dErr := d.readBody(r)
	if dErr != nil {
		return "", dErr
	}

	// Creat hash
	hash, err := h.Create(b)
	if err != nil {
		return "", &DigestError{
			fmt.Sprintf("error creating digest hash '%s'", alg),
			err,
		}
	}

	return strings.ToUpper(alg) + "=" + base64.StdEncoding.EncodeToString(hash), nil
}

func (d *Digest) readBody(r *http.Request) ([]byte, *DigestError) {
	if r.ContentLength == 0 {
		return nil, &DigestError{"empty body", nil}
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, &DigestError{"error reading body", err}
	}

	err = r.Body.Close()
	if err != nil {
		return nil, &DigestError{"error closing body", err}
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return body, nil
}
