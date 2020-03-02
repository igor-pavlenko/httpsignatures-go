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

type ParsedHeader struct {
	keyword   string
	keyId     string
	algorithm string
	created   time.Time
	expires   time.Time // Not implemented: "Subsecod precision is allowed using decimal notation."
	headers   []string
	signature string
}

type parser struct {
	header  string
	result  ParsedHeader
	keyword []byte
	key     []byte
	value   []byte
	flag    string
}

func Create() *parser {
	p := new(parser)
	return p
}

func (p *parser) ParseAuthorization(header string) (ParsedHeader, error) {
	p.flag = "keyword"
	return p.parse(header)
}

func (p *parser) ParseSignature(header string) (ParsedHeader, error) {
	p.flag = "param"
	return p.parse(header)
}

func (p *parser) parse(header string) (ParsedHeader, error) {
	if len(header) == 0 {
		return ParsedHeader{}, fmt.Errorf("empty header")
	}

	r := strings.NewReader(header)
	b := make([]byte, 1)
	for {
		_, err := r.Read(b)
		if err == io.EOF {
			err = nil
			switch p.flag {
			case "keyword":
				err = p.setKeyword()
				break
			case "param":
				if len(p.key) == 0 {
					err = fmt.Errorf("unexpected end of header, expected parameter")
				} else {
					err = fmt.Errorf("unexpected end of header, expected '=' symbol and field value")
				}
				break
			case "equal":
				err = fmt.Errorf("unexpected end of header, expected field value")
				break
			case "quote":
				err = fmt.Errorf("unexpected end of header, expected '\"' symbol and field value")
				break
			case "stringValue":
				err = fmt.Errorf("unexpected end of header, expected '\"' symbol")
				break
			case "intValue":
				err = p.set()
				break
			}
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
			err = fmt.Errorf("unexpected parser stage")
		}
		if err != nil {
			return ParsedHeader{}, err
		}
	}

	return p.result, nil
}

func (p *parser) parseKeyword(cur byte) error {
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

func (p *parser) parseKey(cur byte) error {
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
		return fmt.Errorf("found '%s' — unsupported symbol in key", string(cur))
	}
	return nil
}

func (p *parser) parseEqual(cur byte) error {
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
		return fmt.Errorf("found '%s' — unsupported symbol, expected '=' or space symbol", string(cur))
	}
	return nil
}

func (p *parser) parseQuote(cur byte) error {
	if cur == quote {
		p.flag = "stringValue"
	} else if cur == space {
		return nil
	} else {
		return fmt.Errorf("found '%s' — unsupported symbol, expected '\"' or space symbol", string(cur))
	}
	return nil
}

func (p *parser) parseStringValue(cur byte) error {
	if cur != quote {
		p.value = append(p.value, cur)
	} else if cur == quote {
		p.flag = "div"
		if err := p.set(); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) parseIntValue(cur byte) error {
	if cur >= from0 && cur <= to9 {
		p.value = append(p.value, cur)
	} else if cur == space {
		if len(p.value) == 0 {
			return nil
		}
		p.flag = "div"
		if err := p.set(); err != nil {
			return err
		}
	} else if cur == div {
		p.flag = "param"
		if err := p.set(); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) parseDiv(cur byte) error {
	if cur == div {
		p.flag = "param"
	} else if cur == space {
		return nil
	} else {
		return fmt.Errorf("found '%s' — unsupported symbol, expected ',' or space symbol", string(cur))
	}
	return nil
}

func (p *parser) getValueType() string {
	k := string(p.key)
	if k == "created" || k == "expires" {
		return "int"
	}
	return "string"
}

func (p *parser) setKeyword() error {
	if "Signature" != string(p.keyword) {
		return fmt.Errorf("invalid Authorization header, must start from Signature keyword")
	}
	p.result.keyword = "Signature"
	return nil
}

func (p *parser) set() error {
	k := string(p.key)
	if len(p.value) == 0 {
		return fmt.Errorf("empty value for key '%s'", k)
	}

	if k == "keyId" {
		p.result.keyId = string(p.value)
	} else if k == "algorithm" {
		p.result.algorithm = string(p.value)
	} else if k == "headers" {
		p.result.headers = strings.Fields(string(p.value))
	} else if k == "signature" {
		p.result.signature = string(p.value)
	} else if k == "created" {
		var err error
		var sec int64
		if sec, err = strconv.ParseInt(string(p.value), 10, 32); err != nil {
			return fmt.Errorf("wrong 'created' param value: %v", err)
		}
		p.result.created = time.Unix(sec, 0)
	} else if k == "expires" {
		var err error
		var sec int64
		if sec, err = strconv.ParseInt(string(p.value), 10, 32); err != nil {
			return fmt.Errorf("wrong 'expires' param value: %v", err)
		}
		p.result.expires = time.Unix(sec, 0)
	} else {
		return fmt.Errorf("unknown parameter: '%s'", k)
	}

	p.key = nil
	p.value = nil

	return nil
}
