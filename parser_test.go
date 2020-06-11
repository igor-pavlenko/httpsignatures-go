package httpsignatures

import (
	"reflect"
	"testing"
	"time"
)

const testParserErrType = "*httpsignatures.ParserError"
const testValidSignatureHeader = `keyId="Test",algorithm="rsa-sha256",created=1402170695,expires=1402170699,headers="` +
	`(request-target) (created) (expires) host date digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS5` +
	`9iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gW` +
	`xpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="`

var testValidParsedSignatureHeader = Headers{
	keyID:     "Test",
	algorithm: "rsa-sha256",
	created:   time.Unix(1402170695, 0),
	expires:   time.Unix(1402170699, 0),
	headers:   []string{"(request-target)", "(created)", "(expires)", "host", "date", "digest", "content-length"},
	signature: "vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01" +
		"IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE=",
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		want *Parser
	}{
		{
			name: "Successful",
			want: &Parser{
				params: make(map[string]bool),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("create() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParserParseSingleFields(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Empty header",
			args: args{
				header: ``,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: empty header",
		},
		{
			name: "Only spaces",
			args: args{
				header: `  `,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected end of header, expected parameter",
		},
		{
			name: "Only keyId",
			args: args{
				header: `keyId="v1"`,
			},
			want: Headers{
				keyID: "v1",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Only algorithm",
			args: args{
				header: `algorithm="v2"`,
			},
			want: Headers{
				algorithm: "v2",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Only headers",
			args: args{
				header: `headers="(request-target) (created)" `,
			},
			want: Headers{
				headers: []string{"(request-target)", "(created)"},
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Only signature param",
			args: args{
				header: `signature="test" `,
			},
			want: Headers{
				signature: "test",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "All params without spaces",
			args: args{
				header: `keyId="v1",algorithm="v2",created=1402170695,expires=1402170699,headers="v-3 v-4",signature=` +
					`"v5"`,
			},
			want: Headers{
				keyID:     "v1",
				algorithm: "v2",
				created:   time.Unix(1402170695, 0),
				expires:   time.Unix(1402170699, 0),
				headers:   []string{"v-3", "v-4"},
				signature: "v5",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "All params and extra spaces",
			args: args{
				header: `  keyId  ="v1", algorithm  ="v2",created = 1402170695, expires = 1402170699 , headers  =  " ` +
					`v-3 v-4  ", signature="v5"   `,
			},
			want: Headers{
				keyID:     "v1",
				algorithm: "v2",
				created:   time.Unix(1402170695, 0),
				expires:   time.Unix(1402170699, 0),
				headers:   []string{"v-3", "v-4"},
				signature: "v5",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Signature: all params",
			args: args{
				header: `keyId="v1",algorithm="v2",created=1402170695,expires=1402170699,headers="v-3 v-4",signature=` +
					`"v5"`,
			},
			want: Headers{
				keyID:     "v1",
				algorithm: "v2",
				created:   time.Unix(1402170695, 0),
				expires:   time.Unix(1402170699, 0),
				headers:   []string{"v-3", "v-4"},
				signature: "v5",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Unsupported symbol in key",
			args: args{
				header: `keyId-="v1"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: found '-' — unsupported symbol in key",
		},
		{
			name: "Unsupported symbol, expected = symbol",
			args: args{
				header: `keyId :"v1"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: found ':' — unsupported symbol, expected '=' or space symbol",
		},
		{
			name: "Unsupported symbol, expected quote symbol",
			args: args{
				header: `keyId= 'v1'`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: found ''' — unsupported symbol, expected '\"' or space symbol",
		},
		{
			name: "Unknown parameter",
			args: args{
				header: `key="v1"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "unexpected end of header, expected equal symbol",
			args: args{
				header: `keyId`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected end of header, expected '=' symbol and field value",
		},
		{
			name: "Expected field value",
			args: args{
				header: `keyId `,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected end of header, expected field value",
		},
		{
			name: "Expected quote",
			args: args{
				header: `keyId= `,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected end of header, expected '\"' symbol and field value",
		},
		{
			name: "Expected quote at the end",
			args: args{
				header: `keyId="`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected end of header, expected '\"' symbol",
		},
		{
			name: "Empty value",
			args: args{
				header: `keyId=""`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: empty value for key 'keyId'",
		},
		{
			name: "Div symbol expected",
			args: args{
				header: `keyId="v1" algorithm="v2"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: found 'a' — unsupported symbol, expected ',' or space symbol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			p.flag = "param"
			var got, err = p.parseSignature(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseCreatedExpires(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Created only",
			args: args{
				header: `created=1402170695`,
			},
			want: Headers{
				created: time.Unix(1402170695, 0),
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Expires only",
			args: args{
				header: `expires=1402170699`,
			},
			want: Headers{
				expires: time.Unix(1402170699, 0),
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Wrong created INT value",
			args: args{
				header: `created=9223372036854775807`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg: "ParserError: wrong 'created' param value: strconv.ParseInt: parsing \"9223372036854775807\"" +
				": value out of range",
		},
		{
			name: "Wrong created INT value with space at the end",
			args: args{
				header: `created=9223372036854775808 `,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg: "ParserError: wrong 'created' param value: strconv.ParseInt: parsing \"9223372036854775808\"" +
				": value out of range",
		},
		{
			name: "Wrong created INT value with divider",
			args: args{
				header: `created=9223372036854775809,`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg: "ParserError: wrong 'created' param value: strconv.ParseInt: parsing \"9223372036854775809\"" +
				": value out of range",
		},
		{
			name: "Wrong expires INT value",
			args: args{
				header: `expires=9223372036854775807`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg: "ParserError: wrong 'expires' param value: strconv.ParseInt: parsing \"9223372036854775807\"" +
				": value out of range",
		},
		{
			name: "Wrong expires with space at the end",
			args: args{
				header: `expires=9223372036854775808 `,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg: "ParserError: wrong 'expires' param value: strconv.ParseInt: parsing \"9223372036854775808\"" +
				": value out of range",
		},
		{
			name: "Wrong expires with divider",
			args: args{
				header: `expires=9223372036854775809,`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg: "ParserError: wrong 'expires' param value: strconv.ParseInt: parsing \"9223372036854775809\"" +
				": value out of range",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			p.flag = "param"
			var got, err = p.parseSignature(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseSignature(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Signature",
			args: args{
				header: testValidSignatureHeader,
			},
			want:        testValidParsedSignatureHeader,
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			var got, err = p.ParseSignatureHeader(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseSignatureFailed(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Current parser stage not setKeyValue",
			args: args{
				header: `keyId="Test"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected parser stage",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			var got, err = p.parseSignature(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseDigestFailed(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        DigestHeader
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Current parser stage not set",
			args: args{
				header: `MD5=test`,
			},
			want:        DigestHeader{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected parser stage",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			var got, err = p.parseDigest(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseAmbiguousParams(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Ambiguous Parameters",
			args: args{
				header: `keyId="v1",ambiguous="v2",digest="v3"`,
			},
			want: Headers{
				keyID: "v1",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			var got, err = p.ParseSignatureHeader(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseDuplicateParams(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "Duplicate keyId",
			args: args{
				header: `keyId="v1",keyId="v2"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: duplicate param 'keyId'",
		},
		{
			name: "Duplicate algorithm",
			args: args{
				header: `algorithm="v1",algorithm="v2"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: duplicate param 'algorithm'",
		},
		{
			name: "Duplicate created",
			args: args{
				header: `created=1402170695,created=1402170695`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: duplicate param 'created'",
		},
		{
			name: "Duplicate expires",
			args: args{
				header: `expires=1402170699,expires=1402170699`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: duplicate param 'expires'",
		},
		{
			name: "Duplicate headers",
			args: args{
				header: `headers="v1",headers="v2"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: duplicate param 'headers'",
		},
		{
			name: "Duplicate signature",
			args: args{
				header: `signature="v1",signature="v2"`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: duplicate param 'signature'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			p.flag = "param"
			got, err := p.parseSignature(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestNotSpecifiedHeadersParams(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        Headers
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "No headers",
			args: args{
				header: `keyId="v1"`,
			},
			want: Headers{
				keyID: "v1",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "Empty headers",
			args: args{
				header: `keyId="v1",headers=""`,
			},
			want:        Headers{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: empty value for key 'headers'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			var got, err = p.ParseSignatureHeader(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestParserParseDigestHeader(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        DigestHeader
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "MD5 Digest",
			args: args{
				header: `MD5=ZDk5NTk4ODgxNjM3MDc5MDQ2MTgzNDQwMzExMThiZWI=`,
			},
			want: DigestHeader{
				alg:    "MD5",
				digest: "ZDk5NTk4ODgxNjM3MDc5MDQ2MTgzNDQwMzExMThiZWI=",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "SHA-1 Digest",
			args: args{
				header: `SHA-1=ZDNiMDlhYmUzMGNmZTJlZGZmNGVlOWUwYTE0MWM5M2JmNWIzYWY4Nw==`,
			},
			want: DigestHeader{
				alg:    "SHA-1",
				digest: "ZDNiMDlhYmUzMGNmZTJlZGZmNGVlOWUwYTE0MWM5M2JmNWIzYWY4Nw==",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name: "SHA-256 Digest",
			args: args{
				header: `SHA-256=NWY4ZjA0ZjZhM2E4OTJhYWFiYmRkYjZjZjI3Mzg5NDQ5Mzc3Mzk2MGQ0YTMyNWIxMDVmZWU0NmVlZjQzMDRm` +
					`MQ==`,
			},
			want: DigestHeader{
				alg:    "SHA-256",
				digest: "NWY4ZjA0ZjZhM2E4OTJhYWFiYmRkYjZjZjI3Mzg5NDQ5Mzc3Mzk2MGQ0YTMyNWIxMDVmZWU0NmVlZjQzMDRmMQ==",
			},
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
		{
			name:        "Empty Digest header",
			args:        args{},
			want:        DigestHeader{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: empty digest header",
		},
		{
			name: "Empty Digest value",
			args: args{
				header: `md5`,
			},
			want:        DigestHeader{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: unexpected end of header, expected digest value",
		},
		{
			name: "Unsupported digest algorithm symbol",
			args: args{
				header: `md 5=`,
			},
			want:        DigestHeader{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: found ' ' — unsupported symbol in algorithm",
		},
		{
			name: "Empty digest value",
			args: args{
				header: `MD5=`,
			},
			want:        DigestHeader{},
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: empty digest value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			var got, err = p.ParseDigestHeader(tt.args.header)
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}

func TestVerifySignatureFields(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name        string
		args        args
		want        bool
		wantErrType string
		wantErrMsg  string
	}{
		{
			name: "No keyId",
			args: args{
				header: `algorithm="v1",headers="v-2",signature="v3"`,
			},
			want:        false,
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: keyId is not set in header",
		},
		{
			name: "No signature",
			args: args{
				header: `keyId="v1",headers="v-2"`,
			},
			want:        false,
			wantErrType: testParserErrType,
			wantErrMsg:  "ParserError: signature is not set in header",
		},
		{
			name: "OK",
			args: args{
				header: testValidSignatureHeader,
			},
			want:        true,
			wantErrType: testParserErrType,
			wantErrMsg:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, _ = p.ParseSignatureHeader(tt.args.header)
			err := p.VerifySignatureFields()
			got := err == nil
			assert(t, got, err, tt.wantErrType, tt.name, tt.want, tt.wantErrMsg)
		})
	}
}
