package httpsignatures

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

const (
	signatureHeader = "Signature"
	requestTarget   = "(request-target)"
	created         = "(created)"
	expires         = "(expires)"
)

// Error errors during validating or creating Signature|Authorization
type Error struct {
	Message string
	Err     error
}

// Error error message
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

// HTTPSignatures struct
type HTTPSignatures struct {
	ss  *SecretsStorage
	d   *Digest
	alg map[string]SignatureHashAlgorithm
}

// NewHTTPSignatures Constructor
func NewHTTPSignatures(ss *SecretsStorage) *HTTPSignatures {
	hs := new(HTTPSignatures)
	hs.ss = ss
	hs.d = NewDigest()
	hs.alg = map[string]SignatureHashAlgorithm{
		algoRsaPssSha256: RsaPssSha256{},
		algoRsaSha256:  RsaSha256{},
		algoRsaSha512:  RsaSha512{},
		algoHmacSha256: HmacSha256{},
		algoHmacSha512: HmacSha512{},
	}
	return hs
}

// SetDigestAlgorithm set custom digest hash algorithm
func (hs *HTTPSignatures) SetDigestAlgorithm(a DigestHashAlgorithm) {
	hs.d.SetDigestHashAlgorithm(a)
}

// SetSignatureAlgorithm set custom signature hash algorithm
func (hs *HTTPSignatures) SetSignatureAlgorithm(a SignatureHashAlgorithm) {
	hs.alg[strings.ToUpper(a.Algorithm())] = a
}

// VerifySignature Verify signature
func (hs *HTTPSignatures) VerifySignature(r *http.Request) error {
	// Check signature header
	h := r.Header.Get(signatureHeader)
	if len(h) == 0 {
		return &Error{"signature header not found", nil}
	}

	// Parse header
	p := NewParser()
	ph, pErr := p.ParseSignatureHeader(h)
	if pErr != nil {
		return pErr
	}

	// Verify required fields in signature header
	pErr = p.VerifySignatureFields()
	if pErr != nil {
		return pErr
	}

	// Check keyID & algorithm
	secret, err := hs.ss.Get(ph.keyID)
	if err != nil {
		return &Error{fmt.Sprintf("keyID '%s' not found", ph.keyID), err}
	}
	if !strings.EqualFold(secret.Algorithm, ph.algorithm) {
		return &Error{
			fmt.Sprintf("wrong algorithm '%s' for keyID '%s'", ph.algorithm, ph.keyID),
			nil,
		}
	}
	alg, ok := hs.alg[strings.ToUpper(secret.Algorithm)]
	if !ok {
		return &Error{
			fmt.Sprintf("algorithm '%s' not supported", ph.algorithm),
			nil,
		}
	}

	// Verify digest
	err = hs.verifyDigest(ph.headers, r)
	if err != nil {
		return err
	}

	// Create signature string
	sigStr, err := hs.buildSignatureString(ph, r)
	if err != nil {
		return &Error{"build signature string error", err}
	}
	if len(sigStr) == 0 {
		return &Error{"empty string for signature", nil}
	}

	// Verify signature
	signatureDecoded, err := base64.StdEncoding.DecodeString(ph.signature)
	if err != nil {
		return &Error{
			"error decode signature from base64",
			err,
		}
	}
	err = alg.Verify(secret, sigStr, signatureDecoded)
	if err != nil {
		return &Error{"wrong signature", err}
	}

	return nil
}

// VerifyAuthorization verify authorization signature
func (hs *HTTPSignatures) VerifyAuthorization(r http.Request) error {

	return nil
}

// AddAuthorization add authorization header
func (hs *HTTPSignatures) AddAuthorization(s Secret, r http.Request) error {

	return nil
}

// AddSignature add signature header
func (hs *HTTPSignatures) AddSignature(s Secret, r http.Request) error {

	return nil
}

func (hs *HTTPSignatures) buildSignatureString(ph ParsedHeader, r *http.Request) ([]byte, error) {
	j := len(ph.headers)
	headers := r.Header.Clone()
	var b bytes.Buffer
	for i, h := range ph.headers {
		switch h {
		case requestTarget:
			b.WriteString(fmt.Sprintf("%s: %s %s", requestTarget, strings.ToLower(r.Method), r.URL.RequestURI()))
		case created:
			if hs.isAlgoHasPrefix(ph.algorithm) && j == 1 {
				return nil, &Error{
					fmt.Sprintf("param '%s' and algorithm '%s'", created, ph.algorithm),
					nil,
				}
			}
			if ph.created == time.Unix(0, 0) {
				return nil, &Error{
					fmt.Sprintf("param '%s', required in signature, not found", created),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %d", created, ph.created.Unix()))
		case expires:
			if hs.isAlgoHasPrefix(ph.algorithm) && j == 1 {
				return nil, &Error{
					fmt.Sprintf("param '%s' and algorithm '%s'", expires, ph.algorithm),
					nil,
				}
			}
			if ph.expires == time.Unix(0, 0) {
				return nil, &Error{
					fmt.Sprintf("param '%s', required in signature, not found", expires),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %d", expires, ph.expires.Unix()))
		default:
			reqHeader, ok := headers[textproto.CanonicalMIMEHeaderKey(h)]
			if !ok {
				return nil, &Error{
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

func (hs *HTTPSignatures) isAlgoHasPrefix(algo string) bool {
	a := []string{`rsa`, `hmac`, `ecdsa`}
	algo = strings.ToLower(algo)
	for _, v := range a {
		if strings.HasPrefix(algo, v) {
			return true
		}
	}

	return false
}

func (hs *HTTPSignatures) verifyDigest(ph []string, r *http.Request) error {
	for _, h := range ph {
		if h == "digest" {
			err := hs.d.Verify(r)
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}
