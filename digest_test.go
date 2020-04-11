package httpsignatures

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const digestBodyExample = `{"hello": "world"}`
const digestHostExample = "https://example.com"

var getDigestRequestFunc = func(b string, h string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(b))
	r.Header.Set("Digest", h)
	return r
}

func TestVerifyDigest(t *testing.T) {
	type args struct {
		r *http.Request
		o DigestHashAlgorithm
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Valid MD5 digest",
			args: args{
				r: getDigestRequestFunc(digestBodyExample, "MD5=Sd/dVLAcvNLSq16eXua5uQ=="),
			},
			want: true,
		},
		{
			name: "Valid SHA-256 digest",
			args: args{
				r: getDigestRequestFunc(digestBodyExample, "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="),
			},
			want: true,
		},
		{
			name: "Valid SHA-512 digest",
			args: args{
				r: getDigestRequestFunc(digestBodyExample, "SHA-512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew=="),
			},
			want: true,
		},
		{
			name: "Invalid MD5 digest",
			args: args{
				r: getDigestRequestFunc(digestBodyExample, "MD5=123456"),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "error decode digest from base64: illegal base64 data at input byte 4",
		},
		{
			name: "Invalid digest header",
			args: args{
				r: getDigestRequestFunc(digestBodyExample, "SHA-512="),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "digest parser error: empty digest value",
		},
		{
			name: "Unsupported digest hash algorithm",
			args: args{
				r: getDigestRequestFunc(digestBodyExample, "SHA-0=test"),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "unsupported digest hash algorithm 'SHA-0'",
		},
		{
			name: "Empty body",
			args: args{
				r: getDigestRequestFunc("", "MD5=xxx"),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "empty body",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDigest()
			got, err := d.VerifyDigest(tt.args.r)
			assertDigest(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}


func assertDigest(t *testing.T, got interface{}, err error, name string, want interface{}, wantErr bool, wantErrMsg string) {
	if e, ok := err.(*DigestError); err != nil && ok == false {
		t.Errorf(name+"\nunexpected error type %v", e)
	}
	if err != nil && err.Error() != wantErrMsg {
		t.Errorf(name+"\nerror message = `%s`, wantErrMsg = `%s`", err.Error(), wantErrMsg)
	}
	if (err != nil) != wantErr {
		t.Errorf(name+"\nerror = `%v`, wantErr %v", err, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(name+"\ngot  = %v,\nwant = %v", got, want)
	}
}
