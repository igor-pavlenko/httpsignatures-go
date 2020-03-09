package httpsignatures

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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

// DigestHashFn function to calculate digest hash
type DigestHashFn func([]byte) []byte

// DigestOption struct to add new digest option (new digest hash algorithm support)
type DigestOption struct {
	Algorithm string
	Hash      DigestHashFn
}

// Digest digest internal struct
type Digest struct {
	header             string
	parsedDigestHeader ParsedDigestHeader
	hash               map[string]DigestOption
}

// NewDigest create new digest
func NewDigest() *Digest {
	d := new(Digest)
	d.hash = map[string]DigestOption{
		"MD5": {
			"MD5",
			func(b []byte) []byte {
				h := md5.New()
				h.Write(b)
				return h.Sum(nil)
			},
		},
		"SHA-1": {
			"SHA-1",
			func(b []byte) []byte {
				h := sha1.New()
				h.Write(b)
				return h.Sum(nil)
			},
		},
		"SHA-256": {
			"SHA-256",
			func(b []byte) []byte {
				h := sha256.New()
				h.Write(b)
				return h.Sum(nil)
			},
		},
		"SHA-512": {
			"SHA-512",
			func(b []byte) []byte {
				h := sha512.New()
				h.Write(b)
				return h.Sum(nil)
			},
		},
	}
	return d
}

// SetOptions set digest options (add new digest hash algorithm)
func (d *Digest) SetOptions(options []DigestOption) {
	for _, o := range options {
		d.hash[o.Algorithm] = o
	}
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

	h, ok := d.hash[d.parsedDigestHeader.algo]
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

	digest := h.Hash(b)
	digestBase64 := base64.StdEncoding.EncodeToString(digest)
	if digestBase64 != d.parsedDigestHeader.digest {
		return false, &DigestError{
			fmt.Sprintf("%s of body does not match with digest", d.parsedDigestHeader.algo),
			nil,
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
