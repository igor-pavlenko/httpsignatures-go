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
	digestHeader    = "Digest"
	requestTarget   = "(request-target)"
	created         = "(" + paramCreated + ")"
	expires         = "(" + paramExpires + ")"
)

// Default expires param value (seconds)
const defaultExpiresSec = 30

// Default time gap for created, expires validation (+/- seconds)
const defaultTimeGap = 10

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
	ss                  Secrets
	d                   *Digest
	alg                 map[string]SignatureHashAlgorithm
	defaultExpiresSec   uint32
	defaultTimeGap      time.Duration
	defaultHeaders      []string
	defaultVerifyDigest bool
}

// NewHTTPSignatures Constructor
func NewHTTPSignatures(ss Secrets) *HTTPSignatures {
	hs := new(HTTPSignatures)
	hs.ss = ss
	hs.d = NewDigest()
	hs.alg = map[string]SignatureHashAlgorithm{
		algRsaSsaPssSha256: RsaSsaPssSha256{},
		algRsaSsaPssSha512: RsaSsaPssSha512{},
		algEcdsaSha256:     EcdsaSha256{},
		algRsaSha256:       RsaSha256{},
		algRsaSha512:       RsaSha512{},
		algHmacSha256:      HmacSha256{},
		algHmacSha512:      HmacSha512{},
	}
	hs.defaultExpiresSec = defaultExpiresSec
	hs.defaultTimeGap = defaultTimeGap
	hs.defaultHeaders = []string{"(created)"}
	hs.defaultVerifyDigest = true
	return hs
}

// SetDigestAlgorithm set custom digest hash algorithm
func (hs *HTTPSignatures) SetDigestAlgorithm(a DigestHashAlgorithm) {
	hs.d.SetDigestHashAlgorithm(a)
}

// SetDefaultDigestAlgorithm set custom digest hash algorithm
func (hs *HTTPSignatures) SetDefaultDigestAlgorithm(a string) error {
	return hs.d.SetDefaultDigestHashAlgorithm(a)
}

// SetDefaultVerifyDigest set default verify digest or skip verification
func (hs *HTTPSignatures) SetDefaultVerifyDigest(v bool) {
	hs.defaultVerifyDigest = v
}

// SetSignatureHashAlgorithm set custom signature hash algorithm
func (hs *HTTPSignatures) SetSignatureHashAlgorithm(a SignatureHashAlgorithm) {
	hs.alg[strings.ToUpper(a.Algorithm())] = a
}

// SetDefaultExpiresSeconds set default expires seconds (while creating signature).
// If signature never expires just exclude "expires" param from the headers list
func (hs *HTTPSignatures) SetDefaultExpiresSeconds(e uint32) {
	hs.defaultExpiresSec = e
}

// SetDefaultTimeGap set default time gap for (created)/(expires) validation
func (hs *HTTPSignatures) SetDefaultTimeGap(t int64) {
	hs.defaultTimeGap = time.Duration(t)
}

// SetDefaultSignatureHeaders set default list of headers to create signature (Sign method)
func (hs *HTTPSignatures) SetDefaultSignatureHeaders(h []string) {
	hs.defaultHeaders = h
}

// Verify Verify signature
func (hs *HTTPSignatures) Verify(r *http.Request) error {
	// Check signature header
	h := r.Header.Get(signatureHeader)
	if len(h) == 0 {
		return &Error{"signature header not found", nil}
	}

	// Parse header
	p := NewParser()
	sh, pErr := p.ParseSignatureHeader(h)
	if pErr != nil {
		return pErr
	}

	// Verify required fields in signature header
	pErr = p.VerifySignatureFields()
	if pErr != nil {
		return pErr
	}

	// Verify expires (must be lower than now() +/- time gap)
	if hs.inHeaders(expires, sh.headers) {
		now := time.Now()
		max := sh.expires.Add(hs.defaultTimeGap)
		if now.After(max) {
			return &Error{"signature expired", nil}
		}
	}

	// Verify created (can not be in future)
	if hs.inHeaders(created, sh.headers) {
		now := time.Now()
		max := now.Add(hs.defaultTimeGap)
		if sh.created.After(max) {
			return &Error{"signature in future", nil}
		}
	}

	// Verify digest
	if hs.defaultVerifyDigest {
		err := hs.verifyDigest(sh.headers, r)
		if err != nil {
			return err
		}
	}

	// Check keyID & algorithm
	secret, err := hs.ss.Get(sh.keyID)
	if err != nil {
		return &Error{fmt.Sprintf("keyID '%s' not found", sh.keyID), err}
	}
	if !strings.EqualFold(secret.Algorithm, sh.algorithm) {
		return &Error{
			fmt.Sprintf("wrong algorithm '%s' for keyId '%s'", sh.algorithm, sh.keyID),
			nil,
		}
	}
	alg, ok := hs.alg[strings.ToUpper(secret.Algorithm)]
	if !ok {
		return &Error{
			fmt.Sprintf("algorithm '%s' not supported", sh.algorithm),
			nil,
		}
	}

	// Create signature string
	sigStr, err := hs.buildSignatureString(sh, r)
	if err != nil {
		return &Error{"build signature string error", err}
	}
	if len(sigStr) == 0 {
		return &Error{"empty string for signature", nil}
	}

	// Verify signature
	signatureDecoded, err := base64.StdEncoding.DecodeString(sh.signature)
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

// Sign add signature header
func (hs *HTTPSignatures) Sign(secretKeyID string, r *http.Request) error {
	// Get secret
	secret, err := hs.ss.Get(secretKeyID)
	if err != nil {
		return &Error{fmt.Sprintf("keyId '%s' not found", secretKeyID), err}
	}

	// Get hash algorithm
	alg, ok := hs.alg[strings.ToUpper(secret.Algorithm)]
	if !ok {
		return &Error{
			fmt.Sprintf("algorithm '%s' not supported", secret.Algorithm),
			nil,
		}
	}

	// Build signature string
	headers := Headers{
		keyID:     secret.KeyID,
		algorithm: secret.Algorithm,
		created:   time.Now(),
		expires:   time.Time{},
		headers:   hs.defaultHeaders,
	}
	// Expires
	if hs.defaultExpiresSec != 0 {
		headers.expires = time.Now().Add(time.Second * time.Duration(hs.defaultExpiresSec))
	}
	// Create digest & set it to request header
	// Proceed only if digest header not set
	digest := r.Header.Get(digestHeader)
	if len(digest) == 0 {
		d, err := hs.createDigest(headers.headers, r)
		if err != nil {
			return err
		}
		r.Header.Set(digestHeader, d)
	}

	sigStr, err := hs.buildSignatureString(headers, r)
	if err != nil {
		return &Error{"build signature string error", err}
	}

	// Create signature
	s, err := alg.Create(secret, sigStr)
	if err != nil {
		return &Error{"error creating signature", err}
	}
	headers.signature = base64.StdEncoding.EncodeToString(s)

	// Build Signature header
	sigHeader := hs.buildSignatureHeader(headers)
	r.Header.Set(signatureHeader, sigHeader)

	return nil
}

func (hs *HTTPSignatures) buildSignatureString(sh Headers, r *http.Request) ([]byte, error) {
	j := len(sh.headers)
	headers := r.Header.Clone()
	var b bytes.Buffer
	for i, h := range sh.headers {
		switch h {
		case requestTarget:
			b.WriteString(fmt.Sprintf("%s: %s %s", requestTarget, strings.ToLower(r.Method), r.URL.RequestURI()))
		case created:
			if sh.created == time.Unix(0, 0) {
				return nil, &Error{
					fmt.Sprintf("param '%s', required in signature, not found", created),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %d", created, sh.created.Unix()))
		case expires:
			if sh.expires == time.Unix(0, 0) {
				return nil, &Error{
					fmt.Sprintf("param '%s', required in signature, not found", expires),
					nil,
				}
			}
			b.WriteString(fmt.Sprintf("%s: %d", expires, sh.expires.Unix()))
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

func (hs *HTTPSignatures) buildSignatureHeader(h Headers) string {
	header := fmt.Sprintf(`%s="%s",`, paramKeyID, h.keyID)
	header += fmt.Sprintf(`%s="%s",`, paramAlgorithm, h.algorithm)
	if hs.inHeaders(fmt.Sprintf("(%s)", paramCreated), h.headers) {
		header += fmt.Sprintf(`%s=%d,`, paramCreated, h.created.Unix())
	}
	if hs.inHeaders(fmt.Sprintf("(%s)", paramExpires), h.headers) && hs.defaultExpiresSec > 0 {
		header += fmt.Sprintf(`%s=%d,`, paramExpires, h.expires.Unix())
	}
	if len(h.headers) > 0 {
		header += fmt.Sprintf(`%s="%s",`, paramHeaders, strings.Join(h.headers, " "))
	}
	header += fmt.Sprintf(`%s="%s"`, paramSignature, h.signature)

	return header
}

func (hs *HTTPSignatures) verifyDigest(sh []string, r *http.Request) error {
	for _, h := range sh {
		if strings.EqualFold(h, digestHeader) {
			err := hs.d.Verify(r)
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func (hs *HTTPSignatures) createDigest(sh []string, r *http.Request) (string, error) {
	for _, h := range sh {
		if strings.EqualFold(h, digestHeader) {
			d, err := hs.d.Create(hs.d.defaultAlg, r)
			if err != nil {
				return "", err
			}
			return d, nil
		}
	}
	return "", nil
}

func (hs *HTTPSignatures) inHeaders(a string, h []string) bool {
	for _, b := range h {
		if b == a {
			return true
		}
	}
	return false
}
