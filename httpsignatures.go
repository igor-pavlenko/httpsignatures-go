package httpsignatures

import (
	"bytes"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

const (
	signatureHeader     = "Signature"
	authorizationHeader = "Authorization"
	requestTarget       = "(request-target)"
	created             = "(created)"
	expires             = "(expires)"
)

// HttpSignaturesError errors during validating or creating Signature|Authorization
type HttpSignaturesError struct {
	Message string
	Err     error
}

// Error error message
func (e *HttpSignaturesError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

type HttpSignatures struct {
	ss  *SecretsStorage
	d   *Digest
	alg map[string]SignatureHashAlgorithm
}

func NewHttpSignatures(ss *SecretsStorage) *HttpSignatures {
	hs := new(HttpSignatures)
	hs.ss = ss
	hs.d = NewDigest()
	// Predefined algorithms
	RsaSha256 := RsaSha256{}
	HmacSha256 := HmacSha256{}
	HmacSha512 := HmacSha512{}
	hs.alg = map[string]SignatureHashAlgorithm{
		RsaSha256.Algorithm():  RsaSha256,
		HmacSha256.Algorithm(): HmacSha256,
		HmacSha512.Algorithm(): HmacSha512,
	}
	return hs
}

func (hs *HttpSignatures) SetDigestAlgorithm(a DigestHashAlgorithm) {
	hs.d.SetDigestHashAlgorithm(a)
}

func (hs *HttpSignatures) SetSignatureAlgorithm(a SignatureHashAlgorithm) {
	hs.alg[a.Algorithm()] = a
}

func (hs *HttpSignatures) VerifySignature(r *http.Request) (bool, error) {
	h := r.Header.Get(signatureHeader)
	if len(h) == 0 {
		return false, &HttpSignaturesError{"signature header not found", nil}
	}

	p := NewParser()
	ph, err := p.ParseSignatureHeader(h)
	if err != nil {
		return false, &HttpSignaturesError{"parser error", err}
	}

	vs, err := p.VerifySignatureFields()
	if vs == false {
		return false, &HttpSignaturesError{"signature header validation error", err}
	}

	for _, h := range ph.headers {
		if h == "digest" {
			vd, err := hs.d.VerifyDigest(r)
			if vd == false {
				return false, &HttpSignaturesError{"digest validation error", err}
			}
			break
		}
	}

	s, err := hs.buildSignatureString(ph, r)
	if err != nil {
		return false, &HttpSignaturesError{"build signature string error", err}
	}

	if bytes.Compare(s, []byte("")) == 0 {
		return false, &HttpSignaturesError{"empty string to sign", nil}
	}

	return false, nil
}

func (hs *HttpSignatures) VerifyAuthorization(r http.Request) (bool, error) {

	return false, nil
}

func (hs *HttpSignatures) AddAuthorization(s Secret, r http.Request) error {

	return nil
}

func (hs *HttpSignatures) AddSignature(s Secret, r http.Request) error {

	return nil
}

func (hs *HttpSignatures) buildSignatureString(ph ParsedHeader, r *http.Request) ([]byte, error) {
	j := len(ph.headers)
	headers := r.Header.Clone()
	var b bytes.Buffer
	for i, h := range ph.headers {
		switch h {
		case requestTarget:
			// 2.3.1 Note: For the avoidance of doubt, lowercasing only applies to the :method pseudo-header
			// and not to the :path pseudo-header.
			b.WriteString(fmt.Sprintf("%s: %s %s", requestTarget, strings.ToLower(r.Method), r.URL.RequestURI()))
		case created:
			if hs.isAlgoHasPrefix(ph.algorithm) == true && j == 1 {
				// 2.3.2 If the header field name is `(created)` and the `algorithm`  parameter starts with
				// `rsa`, `hmac`, or `ecdsa` an implementation MUST produce an error.
				return nil, &HttpSignaturesError{
					fmt.Sprintf("param '%s' and algorithm '%s'", created, ph.algorithm),
					nil,
				}
			}
			if ph.created == time.Unix(0, 0) {
				return nil, &HttpSignaturesError{
					fmt.Sprintf("param '%s', required in signature, not found", created),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %d", created, ph.created.Unix()))
		case expires:
			if hs.isAlgoHasPrefix(ph.algorithm) == true && j == 1 {
				// 2.3.3 If the header field name is `(expires)` and the `algorithm` parameter starts with
				// `rsa`, `hmac`, or `ecdsa` an implementation MUST produce an error.
				return nil, &HttpSignaturesError{
					fmt.Sprintf("param '%s' and algorithm '%s'", expires, ph.algorithm),
					nil,
				}
			}
			if ph.expires == time.Unix(0, 0) {
				return nil, &HttpSignaturesError{
					fmt.Sprintf("param '%s', required in signature, not found", expires),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %d", expires, ph.expires.Unix()))
		default:
			// 2.3.4 Leading and trailing optional whitespace (OWS) in the header field value MUST be omitted
			// 2.3.4.2 If the header value (after removing leading and trailing whitespace) is a zero-length string,
			// the signature string line correlating with that header will simply be the (lowercased) header name,
			// an ASCII colon `:`, and an ASCII space ` `.
			reqHeader, ok := headers[textproto.CanonicalMIMEHeaderKey(h)]
			if ok == false {
				return nil, &HttpSignaturesError{
					fmt.Sprintf("header '%s', required in signature, not found", h),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %s", strings.ToLower(h), strings.TrimSpace(reqHeader[0])))
		}
		if i < j-1 {
			b.WriteString("\n")
		}
	}

	return b.Bytes(), nil
}

func (hs *HttpSignatures) isAlgoHasPrefix(algo string) bool {
	a := []string{`rsa`, `hmac`, `ecdsa`}
	algo = strings.ToLower(algo)
	for _, v := range a {
		if strings.HasPrefix(algo, v) {
			return true
		}
	}

	return false
}

func (hs *HttpSignatures) signString() (string, error) {
	return "", nil
}
