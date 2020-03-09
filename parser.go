package httpsignatures

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ASCII codes
var fromA byte = 65 // A
var toZ byte = 90   // z
var froma byte = 97 // a
var toz byte = 122  // z
var equal byte = 61 // =
var quote byte = 34 // "
var space byte = 32 // space
var div byte = 44   // ,
var from0 byte = 48 // 0
var to9 byte = 57   // 9
var min byte = 45   // -

// ParsedHeader Authorization or Signature header parsed into params
type ParsedHeader struct {
	keyword   string
	keyID     string
	algorithm string
	created   time.Time
	expires   time.Time // Not implemented: "Subsecond precision is allowed using decimal notation."
	headers   []string
	signature string
}

// ParsedDigestHeader Digest header parsed into params (algo & digest)
type ParsedDigestHeader struct {
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
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

// Parser parser internal struct
type Parser struct {
	header             string
	parsedHeader       ParsedHeader
	parsedDigestHeader ParsedDigestHeader
	keyword            []byte
	key                []byte
	value              []byte
	flag               string
	params             map[string]bool
}

// NewParser create new parser
func NewParser() *Parser {
	p := new(Parser)
	p.params = make(map[string]bool)
	return p
}

// ParseAuthorizationHeader parse Authorization header
func (p *Parser) ParseAuthorizationHeader(header string) (ParsedHeader, error) {
	p.flag = "keyword"
	return p.parseSignature(header)
}

// ParseSignatureHeader parse Signature header
func (p *Parser) ParseSignatureHeader(header string) (ParsedHeader, error) {
	p.flag = "param"
	return p.parseSignature(header)
}

// ParseDigestHeader parse Digest header
func (p *Parser) ParseDigestHeader(header string) (ParsedDigestHeader, error) {
	p.flag = "algorithm"
	return p.parseDigest(header)
}

func (p *Parser) parseSignature(header string) (ParsedHeader, error) {
	if len(header) == 0 {
		return ParsedHeader{}, &ParserError{"empty header", nil}
	}

	r := strings.NewReader(header)
	b := make([]byte, 1)
	for {
		_, err := r.Read(b)
		if err == io.EOF {
			err = p.handleSignatureEOF()
			if err != nil {
				return ParsedHeader{}, err
			}
			break
		}

		cur := b[0]
		switch p.flag {
		case "keyword":
			err = p.parseKeyword(cur)
			break
		case "param":
			err = p.parseKey(cur)
			break
		case "equal":
			err = p.parseEqual(cur)
			break
		case "quote":
			err = p.parseQuote(cur)
			break
		case "stringValue":
			err = p.parseStringValue(cur)
			break
		case "intValue":
			err = p.parseIntValue(cur)
			break
		case "div":
			err = p.parseDiv(cur)
			break
		default:
			err = &ParserError{"unexpected parser stage", nil}

		}
		if err != nil {
			return ParsedHeader{}, err
		}
	}

	return p.parsedHeader, nil
}

func (p *Parser) parseDigest(header string) (ParsedDigestHeader, error) {
	if len(header) == 0 {
		return ParsedDigestHeader{}, &ParserError{"empty digest header", nil}
	}

	r := strings.NewReader(header)
	b := make([]byte, 1)
	for {
		_, err := r.Read(b)
		if err == io.EOF {
			err = p.handleDigestEOF()
			if err != nil {
				return ParsedDigestHeader{}, err
			}
			break
		}

		cur := b[0]
		switch p.flag {
		case "algorithm":
			err = p.parseAlgorithm(cur)
			break
		case "stringRawValue":
			err = p.parseStringRawValue(cur)
			break
		default:
			err = &ParserError{"unexpected parser stage", nil}

		}
		if err != nil {
			return ParsedDigestHeader{}, err
		}
	}

	return p.parsedDigestHeader, nil
}

func (p *Parser) handleSignatureEOF() error {
	var err error
	switch p.flag {
	case "keyword":
		err = p.setKeyword()
		break
	case "param":
		if len(p.key) == 0 {
			err = &ParserError{"unexpected end of header, expected parameter", nil}
		} else {
			err = &ParserError{"unexpected end of header, expected '=' symbol and field value", nil}
		}
		break
	case "equal":
		err = &ParserError{"unexpected end of header, expected field value", nil}
		break
	case "quote":
		err = &ParserError{"unexpected end of header, expected '\"' symbol and field value", nil}
		break
	case "stringValue":
		err = &ParserError{"unexpected end of header, expected '\"' symbol", nil}
		break
	case "intValue":
		err = p.setKeyValue()
		break
	}
	return err
}

func (p *Parser) handleDigestEOF() error {
	var err error
	if p.flag == "algorithm" {
		err = &ParserError{"unexpected end of header, expected digest value", nil}
	} else if p.flag == "stringRawValue" {
		err = p.setDigest()
	}
	return err
}

func (p *Parser) parseKeyword(cur byte) error {
	if (cur >= fromA && cur <= toZ) || (cur >= froma && cur <= toz) {
		p.keyword = append(p.keyword, cur)
	} else if cur == space && len(p.keyword) > 0 {
		p.flag = "param"
		if err := p.setKeyword(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) parseKey(cur byte) error {
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

func (p *Parser) parseAlgorithm(cur byte) error {
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

func (p *Parser) parseEqual(cur byte) error {
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

func (p *Parser) parseQuote(cur byte) error {
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

func (p *Parser) parseStringValue(cur byte) error {
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

func (p *Parser) parseIntValue(cur byte) error {
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

func (p *Parser) parseStringRawValue(cur byte) error {
	p.value = append(p.value, cur)
	return nil
}

func (p *Parser) parseDiv(cur byte) error {
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

func (p *Parser) setKeyword() error {
	if "Signature" != string(p.keyword) {
		return &ParserError{
			"invalid Authorization header, must start from Signature keyword",
			nil,
		}
	}
	p.parsedHeader.keyword = "Signature"
	return nil
}

func (p *Parser) setKeyValue() error {
	k := string(p.key)

	if len(p.value) == 0 {
		return &ParserError{
			fmt.Sprintf("empty value for key '%s'", k),
			nil,
		}
	}

	if p.params[k] == true {
		return &ParserError{
			fmt.Sprintf("duplicate param '%s'", k),
			nil,
		}
	}
	p.params[k] = true

	if k == "keyID" {
		p.parsedHeader.keyID = string(p.value)
	} else if k == "algorithm" {
		p.parsedHeader.algorithm = string(p.value)
	} else if k == "headers" {
		p.parsedHeader.headers = strings.Fields(string(p.value))
	} else if k == "signature" {
		p.parsedHeader.signature = string(p.value)
	} else if k == "created" {
		var err error
		if p.parsedHeader.created, err = p.intToTime(p.value); err != nil {
			return &ParserError{"wrong 'created' param value", err}
		}
	} else if k == "expires" {
		var err error
		if p.parsedHeader.expires, err = p.intToTime(p.value); err != nil {
			return &ParserError{"wrong 'expires' param value", err}
		}
	}

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

func (p *Parser) setDigest() error {
	if len(p.value) == 0 {
		return &ParserError{
			"empty digest value",
			nil,
		}
	}

	p.parsedDigestHeader.algo = strings.ToUpper(string(p.key))
	p.parsedDigestHeader.digest = string(p.value)

	p.key = nil
	p.value = nil

	return nil
}
