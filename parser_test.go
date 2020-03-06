package httpsignatures

import (
	"reflect"
	"testing"
	"time"
)

type args struct {
	header        string
	authorization bool
}

type testCase struct {
	name       string
	args       args
	want       ParsedHeader
	wantErr    bool
	wantErrMsg string
}

const validHeader = `keyID="Test",algorithm="rsa-sha256",created=1402170695,expires=1402170699,headers="(request-target) (created) (expires) host date digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="`
const validAuthHeader = `Signature ` + validHeader

var validParsedHeader = ParsedHeader{
	keyID:     "Test",
	algorithm: "rsa-sha256",
	created:   time.Unix(1402170695, 0),
	expires:   time.Unix(1402170699, 0),
	headers:   []string{"(request-target)", "(created)", "(expires)", "host", "date", "digest", "content-length"},
	signature: "vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE=",
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
			if got := New(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("create() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParserParse(t *testing.T) {
	tests := []testCase{
		{
			name: "Authorization: Empty header",
			args: args{
				header:        ``,
				authorization: true,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "empty header",
		},
		{
			name: "Authorization: Only Signature keyword",
			args: args{
				header:        `Signature`,
				authorization: true,
			},
			want: ParsedHeader{
				keyword: "Signature",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Only Signature keyword with space",
			args: args{
				header:        `Signature  `,
				authorization: true,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "unexpected end of header, expected parameter",
		},
		{
			name: "Authorization: Wrong in keyword",
			args: args{
				header:        `Auth`,
				authorization: true,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "invalid Authorization header, must start from Signature keyword",
		},
		{
			name: "Authorization: Wrong in keyword with space char",
			args: args{
				header:        `Auth `,
				authorization: true,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "invalid Authorization header, must start from Signature keyword",
		},
		{
			name: "Authorization: Signature and keyID",
			args: args{
				header:        `Signature keyID="v1"`,
				authorization: true,
			},
			want: ParsedHeader{
				keyword: "Signature",
				keyID:   "v1",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and algorithm",
			args: args{
				header:        `Signature algorithm="v2"`,
				authorization: true,
			},
			want: ParsedHeader{
				keyword:   "Signature",
				algorithm: "v2",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and created",
			args: args{
				header:        `Signature created=1402170695`,
				authorization: true,
			},
			want: ParsedHeader{
				keyword: "Signature",
				created: time.Unix(1402170695, 0),
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and expires",
			args: args{
				header:        `Signature expires=1402170699`,
				authorization: true,
			},
			want: ParsedHeader{
				keyword: "Signature",
				expires: time.Unix(1402170699, 0),
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and headers",
			args: args{
				header:        `Signature headers="(request-target) (created)" `,
				authorization: true,
			},
			want: ParsedHeader{
				keyword: "Signature",
				headers: []string{"(request-target)", "(created)"},
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and signature param",
			args: args{
				header:        `Signature signature="test" `,
				authorization: true,
			},
			want: ParsedHeader{
				keyword:   "Signature",
				signature: "test",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and all params",
			args: args{
				header:        `Signature keyID="v1",algorithm="v2",created=1402170695,expires=1402170699,headers="v-3 v-4",signature="v5"`,
				authorization: true,
			},
			want: ParsedHeader{
				keyword:   "Signature",
				keyID:     "v1",
				algorithm: "v2",
				created:   time.Unix(1402170695, 0),
				expires:   time.Unix(1402170699, 0),
				headers:   []string{"v-3", "v-4"},
				signature: "v5",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Authorization: Signature and all params and extra spaces",
			args: args{
				header:        `Signature   keyID  ="v1", algorithm  ="v2",created = 1402170695, expires = 1402170699 , headers  =  "  v-3 v-4  ", signature="v5"   `,
				authorization: true,
			},
			want: ParsedHeader{
				keyword:   "Signature",
				keyID:     "v1",
				algorithm: "v2",
				created:   time.Unix(1402170695, 0),
				expires:   time.Unix(1402170699, 0),
				headers:   []string{"v-3", "v-4"},
				signature: "v5",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Signature: all params",
			args: args{
				header:        `keyID="v1",algorithm="v2",created=1402170695,expires=1402170699,headers="v-3 v-4",signature="v5"`,
				authorization: false,
			},
			want: ParsedHeader{
				keyID:     "v1",
				algorithm: "v2",
				created:   time.Unix(1402170695, 0),
				expires:   time.Unix(1402170699, 0),
				headers:   []string{"v-3", "v-4"},
				signature: "v5",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Signature: real example",
			args: args{
				header:        validHeader,
				authorization: false,
			},
			want: validParsedHeader,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Unsupported symbol in key",
			args: args{
				header: `keyID-="v1"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "found '-' — unsupported symbol in key",
		},
		{
			name: "Unsupported symbol, expected = symbol",
			args: args{
				header: `keyID :"v1"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "found ':' — unsupported symbol, expected '=' or space symbol",
		},
		{
			name: "Unsupported symbol, expected quote symbol",
			args: args{
				header: `keyID= 'v1'`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "found ''' — unsupported symbol, expected '\"' or space symbol",
		},
		{
			name: "Unknown parameter",
			args: args{
				header: `key="v1"`,
			},
			want:       ParsedHeader{},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "unexpected end of header, expected equal symbol",
			args: args{
				header: `keyID`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "unexpected end of header, expected '=' symbol and field value",
		},
		{
			name: "Expected field value",
			args: args{
				header: `keyID `,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "unexpected end of header, expected field value",
		},
		{
			name: "Expected quote",
			args: args{
				header: `keyID= `,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "unexpected end of header, expected '\"' symbol and field value",
		},
		{
			name: "Expected quote at the end",
			args: args{
				header: `keyID="`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "unexpected end of header, expected '\"' symbol",
		},
		{
			name: "Empty value",
			args: args{
				header: `keyID=""`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "empty value for key 'keyID'",
		},
		{
			name: "Div symbol expected",
			args: args{
				header: `keyID="v1" algorithm="v2"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "found 'a' — unsupported symbol, expected ',' or space symbol",
		},
		{
			name: "Wrong created INT value",
			args: args{
				header: `created=9223372036854775807`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "wrong 'created' param value: strconv.ParseInt: parsing \"9223372036854775807\": value out of range",
		},
		{
			name: "Wrong created INT value with space at the end",
			args: args{
				header: `created=9223372036854775808 `,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "wrong 'created' param value: strconv.ParseInt: parsing \"9223372036854775808\": value out of range",
		},
		{
			name: "Wrong created INT value with divider",
			args: args{
				header: `created=9223372036854775809,`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "wrong 'created' param value: strconv.ParseInt: parsing \"9223372036854775809\": value out of range",
		},
		{
			name: "Wrong expires INT value",
			args: args{
				header: `expires=9223372036854775807`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "wrong 'expires' param value: strconv.ParseInt: parsing \"9223372036854775807\": value out of range",
		},
		{
			name: "Wrong expires with space at the end",
			args: args{
				header: `expires=9223372036854775808 `,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "wrong 'expires' param value: strconv.ParseInt: parsing \"9223372036854775808\": value out of range",
		},
		{
			name: "Wrong expires with divider",
			args: args{
				header: `expires=9223372036854775809,`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "wrong 'expires' param value: strconv.ParseInt: parsing \"9223372036854775809\": value out of range",
		},
		{
			name: "Ambiguous Parameters",
			args: args{
				header: `keyID="v1",ambiguous="v2",sig="v3"`,
			},
			want: ParsedHeader{
				keyID: "v1",
			},
			wantErr:    false,
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			if true == tt.args.authorization {
				p.flag = "keyword"
			} else {
				p.flag = "param"
			}
			var got, err = p.parse(tt.args.header)
			assert(t, tt, got, err)
		})
	}
}

func TestParserParseAuthorization(t *testing.T) {
	var validAuthParsedHeader = validParsedHeader
	validAuthParsedHeader.keyword = "Signature"
	tests := []testCase{
		{
			name: "Authorization",
			args: args{
				header:        validAuthHeader,
				authorization: true,
			},
			want: validAuthParsedHeader,
			wantErr:    false,
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var got, err = p.ParseAuthorization(tt.args.header)
			assert(t, tt, got, err)
		})
	}
}

func TestParserParseSignature(t *testing.T) {
	tests := []testCase{
		{
			name: "Signature",
			args: args{
				header: validHeader,
			},
			want: validParsedHeader,
			wantErr:    false,
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var got, err = p.ParseSignature(tt.args.header)
			assert(t, tt, got, err)
		})
	}
}

func TestParserParseFailed(t *testing.T) {
	tests := []testCase{
		{
			name: "Current parser stage not set",
			args: args{
				header: `keyID="Test"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "unexpected parser stage",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var got, err = p.parse(tt.args.header)
			assert(t, tt, got, err)
		})
	}
}

func TestParserParseDuplicateParams(t *testing.T) {
	tests := []testCase{
		{
			name: "Duplicate keyID",
			args: args{
				header: `keyID="v1",keyID="v2"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "duplicate param 'keyID'",
		},
		{
			name: "Duplicate algorithm",
			args: args{
				header: `algorithm="v1",algorithm="v2"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "duplicate param 'algorithm'",
		},
		{
			name: "Duplicate created",
			args: args{
				header: `created=1402170695,created=1402170695`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "duplicate param 'created'",
		},
		{
			name: "Duplicate expires",
			args: args{
				header: `expires=1402170699,expires=1402170699`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "duplicate param 'expires'",
		},
		{
			name: "Duplicate headers",
			args: args{
				header: `headers="v1",headers="v2"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "duplicate param 'headers'",
		},
		{
			name: "Duplicate signature",
			args: args{
				header: `signature="v1",signature="v2"`,
			},
			want:       ParsedHeader{},
			wantErr:    true,
			wantErrMsg: "duplicate param 'signature'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			p.flag = "param"
			got, err := p.parse(tt.args.header)
			assert(t, tt, got, err)
		})
	}
}

func assert(t *testing.T, tt testCase, got interface{}, err error) {
	if e, ok := err.(*ParserError); err != nil && ok == false {
		t.Errorf("unexpected error type %v", e)
	}
	if err != nil && err.Error() != tt.wantErrMsg {
		t.Errorf("error message = `%s`, wantErrMsg = `%s`", err.Error(), tt.wantErrMsg)
	}
	if (err != nil) != tt.wantErr {
		t.Errorf("parse() error = `%v`, wantErr %v", err, tt.wantErr)
	}
	if !reflect.DeepEqual(got, tt.want) {
		t.Errorf("parse() got = %v,\nwant %v", got, tt.want)
	}
}
