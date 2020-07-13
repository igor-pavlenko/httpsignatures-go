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
	alg    string
	digest string
}

// ErrParser errors during parsing
type ErrParser struct {
	Message string
	Err     error
}

// ErrHS error message
func (e *ErrParser) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("ErrParser: %s: %s", e.Message, e.Err.Error())
	}
	return fmt.Sprintf("ErrParser: %s", e.Message)
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
func (p *Parser) ParseSignatureHeader(header string) (Headers, *ErrParser) {
	p.flag = "param"
	return p.parseSignature(header)
}

// ParseDigestHeader parse Digest header
func (p *Parser) ParseDigestHeader(header string) (DigestHeader, *ErrParser) {
	p.flag = "algorithm"
	return p.parseDigest(header)
}

func (p *Parser) parseSignature(header string) (Headers, *ErrParser) {
	if len(header) == 0 {
		return Headers{}, &ErrParser{"empty header", nil}
	}

	var err *ErrParser
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
			err = &ErrParser{"unexpected parser stage", nil}

		}
		if err != nil {
			return Headers{}, err
		}
	}

	return p.headers, nil
}

func (p *Parser) parseDigest(header string) (DigestHeader, *ErrParser) {
	if len(header) == 0 {
		return DigestHeader{}, &ErrParser{"empty digest header", nil}
	}

	var err *ErrParser
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
			err = &ErrParser{"unexpected parser stage", nil}

		}
		if err != nil {
			return DigestHeader{}, err
		}
	}

	return p.digestHeader, nil
}

func (p *Parser) handleSignatureEOF() *ErrParser {
	var err *ErrParser
	switch p.flag {
	case "param":
		if len(p.key) == 0 {
			err = &ErrParser{"unexpected end of header, expected parameter", nil}
		} else {
			err = &ErrParser{"unexpected end of header, expected '=' symbol and field value", nil}
		}
	case "equal":
		err = &ErrParser{"unexpected end of header, expected field value", nil}
	case "quote":
		err = &ErrParser{"unexpected end of header, expected '\"' symbol and field value", nil}
	case "stringValue":
		err = &ErrParser{"unexpected end of header, expected '\"' symbol", nil}
	case "intValue":
		err = p.setKeyValue()
	}
	return err
}

func (p *Parser) handleDigestEOF() *ErrParser {
	var err *ErrParser
	if p.flag == "algorithm" {
		err = &ErrParser{"unexpected end of header, expected digest value", nil}
	} else if p.flag == "stringRawValue" {
		err = p.setDigest()
	}
	return err
}

func (p *Parser) parseKey(cur byte) *ErrParser {
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
		return &ErrParser{
			fmt.Sprintf("found '%s' — unsupported symbol in key", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseAlgorithm(cur byte) *ErrParser {
	if (cur >= fromA && cur <= toZ) ||
		(cur >= froma && cur <= toz) ||
		(cur >= from0 && cur <= to9) || cur == min {
		p.key = append(p.key, cur)
	} else if cur == equal {
		p.flag = "stringRawValue"
	} else {
		return &ErrParser{
			fmt.Sprintf("found '%s' — unsupported symbol in algorithm", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseEqual(cur byte) *ErrParser {
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
		return &ErrParser{
			fmt.Sprintf("found '%s' — unsupported symbol, expected '=' or space symbol", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseQuote(cur byte) *ErrParser {
	if cur == quote {
		p.flag = "stringValue"
	} else if cur == space {
		return nil
	} else {
		return &ErrParser{
			fmt.Sprintf("found '%s' — unsupported symbol, expected '\"' or space symbol", string(cur)),
			nil,
		}
	}
	return nil
}

func (p *Parser) parseStringValue(cur byte) *ErrParser {
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

func (p *Parser) parseIntValue(cur byte) *ErrParser {
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

func (p *Parser) parseStringRawValue(cur byte) *ErrParser {
	p.value = append(p.value, cur)
	return nil
}

func (p *Parser) parseDiv(cur byte) *ErrParser {
	if cur == div {
		p.flag = "param"
	} else if cur == space {
		return nil
	} else {
		return &ErrParser{
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

func (p *Parser) setKeyValue() *ErrParser {
	k := string(p.key)

	if len(p.value) == 0 {
		return &ErrParser{
			fmt.Sprintf("empty value for key '%s'", k),
			nil,
		}
	}

	if p.params[k] {
		// 2.2 If any of the parameters listed above are erroneously duplicated in the associated header field,
		// then the the signature MUST NOT be processed.
		return &ErrParser{
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
			return &ErrParser{"wrong 'created' param value", err}
		}
	} else if k == "expires" {
		var err error
		if p.headers.expires, err = p.intToTime(p.value); err != nil {
			return &ErrParser{"wrong 'expires' param value", err}
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
	if sec, err = strconv.ParseInt(string(v), 10, 64); err != nil {
		return time.Unix(0, 0), err
	}
	return time.Unix(sec, 0), nil
}

func (p *Parser) setDigest() *ErrParser {
	if len(p.value) == 0 {
		return &ErrParser{
			"empty digest value",
			nil,
		}
	}

	p.digestHeader.alg = strings.ToUpper(string(p.key))
	p.digestHeader.digest = string(p.value)

	p.key = nil
	p.value = nil

	return nil
}

// VerifySignatureFields verify required fields
func (p *Parser) VerifySignatureFields() *ErrParser {
	if p.headers.keyID == "" {
		return &ErrParser{
			"keyId is not set in header",
			nil,
		}
	}

	if p.headers.signature == "" {
		return &ErrParser{
			"signature is not set in header",
			nil,
		}
	}

	return nil
}
