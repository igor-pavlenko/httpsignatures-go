package httpsignatures

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
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
	md5 := Md5{}
	sha256 := Sha256{}
	sha512 := Sha512{}
	d.alg = map[string]DigestHashAlgorithm{
		md5.Algorithm(): md5,
		sha256.Algorithm(): sha256,
		sha512.Algorithm(): sha512,
	}
	return d
}

// SetDigestHashAlgorithm set digest options (add new digest hash algorithm)
func (d *Digest) SetDigestHashAlgorithm(a DigestHashAlgorithm) {
	d.alg[a.Algorithm()] = a
}

// VerifyDigest verify digest header (compare with real request body hash)
func (d *Digest) VerifyDigest(r *http.Request) (bool, error) {
	var err error

	header := r.Header.Get("digest")
	p := NewParser()
	d.parsedDigestHeader, err = p.ParseDigestHeader(header)
	if err != nil {
		return false, &DigestError{
			"digest parser error",
			err,
		}
	}

	h, ok := d.alg[d.parsedDigestHeader.algo]
	if ok == false {
		return false, &DigestError{
			fmt.Sprintf("unsupported digest hash algorithm '%s'", d.parsedDigestHeader.algo),
			nil,
		}
	}

	b, err := d.readBody(r)
	if err != nil {
		return false, err
	}

	digest, err := base64.StdEncoding.DecodeString(d.parsedDigestHeader.digest)
	if err != nil {
		return false, &DigestError{
			"error decode digest from base64",
			err,
		}
	}
	err = h.Verify(b, digest)
	if err != nil {
		return false, &DigestError{
			"wrong digest",
			err,
		}
	}

	return true, nil
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
