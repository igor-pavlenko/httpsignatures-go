package httpsignatures

import (
	"fmt"
	"io"
	"strconv"
	"strings"
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
	created   int32
	expires   int32
	headers   []string
	signature string
}

type parser struct {
	header         string
	result         ParsedHeader
	keyword        []byte
	key            []byte
	value          []byte
	keywordNow     bool
	keyNow         bool
	equalNow       bool
	quoteNow       bool
	stringValueNow bool
	intValueNow    bool
	divNow         bool
}

func Create() *parser {
	p := new(parser)
	return p
}

func (p *parser) ParseAuthorization(header string) (ParsedHeader, error) {
	p.keywordNow = true
	return p.parse(header)
}

func (p *parser) ParseSignature(header string) (ParsedHeader, error) {
	p.keyNow = true
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
			if p.keywordNow == true {
				err = p.setKeyword()
			} else if p.keyNow == true {
				if len(p.key) == 0 {
					err = fmt.Errorf("unexpected end of header, expected key param")
				} else {
					err = fmt.Errorf("unexpected end of header, expected '=' symbol and field value")
				}
			} else if p.equalNow == true {
				err = fmt.Errorf("unexpected end of header, expected field value")
			} else if p.quoteNow == true {
				err = fmt.Errorf("unexpected end of header, expected '\"' symbol and field value")
			} else if p.stringValueNow == true {
				err = fmt.Errorf("unexpected end of header, expected '\"' symbol")
			} else if p.intValueNow == true {
				err = p.set()
			}
			if err != nil {
				return ParsedHeader{}, err
			}
			break
		}
		cur := b[0]
		if p.keywordNow == true {
			err = p.parseKeyword(cur)
		} else if p.keyNow == true {
			err = p.parseKey(cur)
		} else if p.equalNow {
			err = p.parseEqual(cur)
		} else if p.quoteNow {
			err = p.parseQuote(cur)
		} else if p.stringValueNow == true {
			err = p.parseStringValue(cur)
		} else if p.intValueNow == true {
			err = p.parseIntValue(cur)
		} else if p.divNow {
			err = p.parseDiv(cur)
		} else {
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
		p.keywordNow = false
		p.keyNow = true
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
		p.keyNow = false
		if p.getValueType() == "string" {
			p.quoteNow = true
		} else {
			p.intValueNow = true
		}
	} else if cur == space && len(p.key) > 0 {
		p.keyNow = false
		p.equalNow = true
	} else if cur != space {
		return fmt.Errorf("found '%s' — unsupported symbol in key", string(cur))
	}
	return nil
}

func (p *parser) parseEqual(cur byte) error {
	if cur == equal {
		p.equalNow = false
		if p.getValueType() == "string" {
			p.quoteNow = true
		} else {
			p.intValueNow = true
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
		p.quoteNow = false
		p.stringValueNow = true
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
		p.stringValueNow = false
		p.divNow = true
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
		p.intValueNow = false
		p.divNow = true
		if err := p.set(); err != nil {
			return err
		}
	} else if cur == div {
		p.intValueNow = false
		p.keyNow = true
		if err := p.set(); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) parseDiv(cur byte) error {
	if cur == div {
		p.divNow = false
		p.keyNow = true
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
		var i int64
		if i, err = strconv.ParseInt(string(p.value), 10, 32); err != nil {
			return fmt.Errorf("wrong 'created' param value: %v", err)
		}
		p.result.created = int32(i)
	} else if k == "expires" {
		var err error
		var i int64
		if i, err = strconv.ParseInt(string(p.value), 10, 32); err != nil {
			return fmt.Errorf("wrong 'expires' param value: %v", err)
		}
		p.result.expires = int32(i)
	} else {
		return fmt.Errorf("unknown key: '%s'", k)
	}

	p.key = nil
	p.value = nil

	return nil
}
