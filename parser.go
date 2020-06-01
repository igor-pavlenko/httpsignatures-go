package httpsignatures

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ASCII codes
const (
	fromA byte = 'A'
	toZ   byte = 'Z'
	froma byte = 'a'
	toz   byte = 'z'
	equal byte = '='
	quote byte = '"'
	space byte = ' '
	div   byte = ','
	from0 byte = '0'
	to9   byte = '9'
	min   byte = '-'
)

const (
	paramKeyID     = "keyId"
	paramAlgorithm = "algorithm"
	paramCreated   = "created"
	paramExpires   = "expires"
	paramHeaders   = "headers"
	paramSignature = "signature"
)

// Headers Signature headers & params
type Headers struct {
	keyID     string    // REQUIRED
	algorithm string    // RECOMMENDED
	created   time.Time // RECOMMENDED
	expires   time.Time // OPTIONAL (Not implemented: "Subsecond precision is allowed using decimal notation.")
	headers   []string  // OPTIONAL
	signature string    // REQUIRED
}

// DigestHeader Digest header parsed into params (alg & digest)
type DigestHeader struct {
	algo   string
	digest string
}

// ParserError errors during parsing
type ParserError struct {
	Message string
	Err     error
}

// Error error message
func (e *ParserError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("ParserError: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("ParserError: %s", e.Message)
}

// Parser parser internal struct
type Parser struct {
	headers      Headers
	digestHeader DigestHeader
	key          []byte
	value        []byte
	flag         string
	params       map[string]bool
}

// NewParser create new parser
func NewParser() *Parser {
	p := new(Parser)
	p.params = make(map[string]bool)
	return p
}

// ParseSignatureHeader parse Signature header
func (p *Parser) ParseSignatureHeader(header string) (Headers, *ParserError) {
	p.flag = "param"
	return p.parseSignature(header)
}

// ParseDigestHeader parse Digest header
func (p *Parser) ParseDigestHeader(header string) (DigestHeader, *ParserError) {
	p.flag = "algorithm"
	return p.parseDigest(header)
}

func (p *Parser) parseSignature(header string) (Headers, *ParserError) {
	if len(header) == 0 {
		return Headers{}, &ParserError{"empty header", nil}
	}

	var err *ParserError
	r := strings.NewReader(header)
	b := make([]byte, 1)
	for {
		_, rErr := r.Read(b)
		if rErr == io.EOF {
			err = p.handleSignatureEOF()
			if err != nil {
				return Headers{}, err
			}
			break
		}

		cur := b[0]
		switch p.flag {
		case "param":
			err = p.parseKey(cur)
		case "equal":
			err = p.parseEqual(cur)
		case "quote":
			err = p.parseQuote(cur)
		case "stringValue":
			err = p.parseStringValue(cur)
		case "intValue":
			err = p.parseIntValue(cur)
		case "div":
			err = p.parseDiv(cur)
		default:
			err = &ParserError{"unexpected parser stage", nil}

		}
		if err != nil {
			return Headers{}, err
		}
	}

	// 2.1.6 If not specified, implementations MUST operate as if the field were specified with a
	// single value, `(created)`, in the list of HTTP headers.
	if len(p.headers.headers) == 0 {
		p.headers.headers = append(p.headers.headers, "(created)")
	}

	return p.headers, nil
}

func (p *Parser) parseDigest(header string) (DigestHeader, *ParserError) {
	if len(header) == 0 {
		return DigestHeader{}, &ParserError{"empty digest header", nil}
	}

	var err *ParserError
	r := strings.NewReader(header)
	b := make([]byte, 1)
	for {
		_, rErr := r.Read(b)
		if rErr == io.EOF {
			err = p.handleDigestEOF()
			if err != nil {
				return DigestHeader{}, err
			}
			break
		}

		cur := b[0]
		switch p.flag {
		case "algorithm":
			err = p.parseAlgorithm(cur)
		case "stringRawValue":
			err = p.parseStringRawValue(cur)
		default:
			err = &ParserError{"unexpected parser stage", nil}

		}
		if err != nil {
			return DigestHeader{}, err
		}
	}

	return p.digestHeader, nil
}

func (p *Parser) handleSignatureEOF() *ParserError {
	var err *ParserError
	switch p.flag {
	case "param":
		if len(p.key) == 0 {
			err = &ParserError{"unexpected end of header, expected parameter", nil}
		} else {
			err = &ParserError{"unexpected end of header, expected '=' symbol and field value", nil}
		}
	case "equal":
		err = &ParserError{"unexpected end of header, expected field value", nil}
	case "quote":
		err = &ParserError{"unexpected end of header, expected '\"' symbol and field value", nil}
	case "stringValue":
		err = &ParserError{"unexpected end of header, expected '\"' symbol", nil}
	case "intValue":
		err = p.setKeyValue()
	}
	return err
}

func (p *Parser) handleDigestEOF() *ParserError {
	var err *ParserError
	if p.flag == "algorithm" {
		err = &ParserError{"unexpected end of header, expected digest value", nil}
	} else if p.flag == "stringRawValue" {
		err = p.setDigest()
	}
	return err
}

func (p *Parser) parseKey(cur byte) *ParserError {
	if (cur >= fromA && cur <= toZ) || (cur >= froma && cur <= toz) {
		p.key = append(p.key, cur)
	} else if cur == equal {
		t := p.getValueType()
		if t == "string" {
			p.flag = "quote"
		} else if t == "int" {
			p.flag = "intValue"
		}
	} else if cur == space && len(p.key) > 0 {
		p.flag = "equal"
	} else if cur != space {
		return &ParserError{
			fmt.Sprintf("found '%s' — unsupported symbol in key", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseAlgorithm(cur byte) *ParserError {
	if (cur >= fromA && cur <= toZ) ||
		(cur >= froma && cur <= toz) ||
		(cur >= from0 && cur <= to9) || cur == min {
		p.key = append(p.key, cur)
	} else if cur == equal {
		p.flag = "stringRawValue"
	} else {
		return &ParserError{
			fmt.Sprintf("found '%s' — unsupported symbol in algorithm", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseEqual(cur byte) *ParserError {
	if cur == equal {
		t := p.getValueType()
		if t == "string" {
			p.flag = "quote"
		} else if t == "int" {
			p.flag = "intValue"
		}
	} else if cur == space {
		return nil
	} else {
		return &ParserError{
			fmt.Sprintf("found '%s' — unsupported symbol, expected '=' or space symbol", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseQuote(cur byte) *ParserError {
	if cur == quote {
		p.flag = "stringValue"
	} else if cur == space {
		return nil
	} else {
		return &ParserError{
			fmt.Sprintf("found '%s' — unsupported symbol, expected '\"' or space symbol", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseStringValue(cur byte) *ParserError {
	if cur != quote {
		p.value = append(p.value, cur)
	} else if cur == quote {
		p.flag = "div"
		if err := p.setKeyValue(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) parseIntValue(cur byte) *ParserError {
	if cur >= from0 && cur <= to9 {
		p.value = append(p.value, cur)
	} else if cur == space {
		if len(p.value) == 0 {
			return nil
		}
		p.flag = "div"
		if err := p.setKeyValue(); err != nil {
			return err
		}
	} else if cur == div {
		p.flag = "param"
		if err := p.setKeyValue(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) parseStringRawValue(cur byte) *ParserError {
	p.value = append(p.value, cur)
	return nil
}

func (p *Parser) parseDiv(cur byte) *ParserError {
	if cur == div {
		p.flag = "param"
	} else if cur == space {
		return nil
	} else {
		return &ParserError{
			fmt.Sprintf("found '%s' — unsupported symbol, expected ',' or space symbol", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) getValueType() string {
	k := string(p.key)
	if k == "created" || k == "expires" {
		return "int"
	}
	return "string"
}

func (p *Parser) setKeyValue() *ParserError {
	k := string(p.key)

	if len(p.value) == 0 {
		return &ParserError{
			fmt.Sprintf("empty value for key '%s'", k),
			nil,
		}
	}

	if p.params[k] {
		// 2.2 If any of the parameters listed above are erroneously duplicated in the associated header field,
		// then the the signature MUST NOT be processed.
		return &ParserError{
			fmt.Sprintf("duplicate param '%s'", k),
			nil,
		}
	}
	p.params[k] = true

	if k == "keyId" {
		p.headers.keyID = string(p.value)
	} else if k == "algorithm" {
		p.headers.algorithm = string(p.value)
	} else if k == "headers" {
		p.headers.headers = strings.Fields(string(p.value))
	} else if k == "signature" {
		p.headers.signature = string(p.value)
	} else if k == "created" {
		var err error
		if p.headers.created, err = p.intToTime(p.value); err != nil {
			return &ParserError{"wrong 'created' param value", err}
		}
	} else if k == "expires" {
		var err error
		if p.headers.expires, err = p.intToTime(p.value); err != nil {
			return &ParserError{"wrong 'expires' param value", err}
		}
	}

	// 2.2 Any parameter that is not recognized as a parameter, or is not well-formed, MUST be ignored.

	p.key = nil
	p.value = nil

	return nil
}

func (p *Parser) intToTime(v []byte) (time.Time, error) {
	var err error
	var sec int64
	if sec, err = strconv.ParseInt(string(v), 10, 32); err != nil {
		return time.Unix(0, 0), err
	}
	return time.Unix(sec, 0), nil
}

func (p *Parser) setDigest() *ParserError {
	if len(p.value) == 0 {
		return &ParserError{
			"empty digest value",
			nil,
		}
	}

	p.digestHeader.algo = strings.ToUpper(string(p.key))
	p.digestHeader.digest = string(p.value)

	p.key = nil
	p.value = nil

	return nil
}

// VerifySignatureFields verify required fields
func (p *Parser) VerifySignatureFields() *ParserError {
	if p.headers.keyID == "" {
		return &ParserError{
			"keyId is not set in header",
			nil,
		}
	}

	if p.headers.signature == "" {
		return &ParserError{
			"signature is not set in header",
			nil,
		}
	}

	return nil
}
