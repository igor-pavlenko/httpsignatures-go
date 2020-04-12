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
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

// Digest digest internal struct
type Digest struct {
	header             string
	parsedDigestHeader ParsedDigestHeader
	alg                map[string]DigestHashAlgorithm
}

// NewDigest create new digest
func NewDigest() *Digest {
	d := new(Digest)
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

// VerifyDigest verify digest header (compare with real request body hash)
func (d *Digest) Verify(r *http.Request) error {
	var err error

	header := r.Header.Get("digest")
	p := NewParser()
	d.parsedDigestHeader, err = p.ParseDigestHeader(header)
	if err != nil {
		return &DigestError{
			"digest parser error",
			err,
		}
	}

	h, ok := d.alg[strings.ToUpper(d.parsedDigestHeader.algo)]
	if ok == false {
		return &DigestError{
			fmt.Sprintf("unsupported digest hash algorithm '%s'", d.parsedDigestHeader.algo),
			nil,
		}
	}

	b, err := d.readBody(r)
	if err != nil {
		return err
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

func (d *Digest) readBody(r *http.Request) ([]byte, error) {
	if r.ContentLength == 0 {
		return []byte{}, &DigestError{"empty body", nil}
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return []byte{}, &DigestError{"error reading body", err}
	}

	err = r.Body.Close()
	if err != nil {
		return []byte{}, &DigestError{"error closing body", err}
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return body, nil
}
