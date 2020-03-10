package httpsignatures

import (
	"crypto/sha256"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const digestBodyExample = `{"hello": "world"}`
const digestHostExample = "https://example.com"

var getRequestFunc = func(b string, h string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(b))
	r.Header.Set("Digest", h)
	return r
}

func TestVerifyDigest(t *testing.T) {
	type args struct {
		r *http.Request
		o DigestOption
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
				r: getRequestFunc(digestBodyExample, "MD5=Sd/dVLAcvNLSq16eXua5uQ=="),
			},
			want:       true,
		},
		{
			name: "Valid SHA-1 digest",
			args: args{
				r: getRequestFunc(digestBodyExample, "SHA-1=07CavjDP4u3/TungoUHJO/Wzr4c="),
			},
			want:       true,
		},
		{
			name: "Valid SHA-256 digest",
			args: args{
				r: getRequestFunc(digestBodyExample, "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="),
			},
			want:       true,
		},
		{
			name: "Valid SHA-512 digest",
			args: args{
				r: getRequestFunc(digestBodyExample, "SHA-512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew=="),
			},
			want:       true,
		},
		{
			name: "Invalid MD5 digest",
			args: args{
				r: getRequestFunc(digestBodyExample, "MD5=123456"),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "MD5 of body does not match with digest",
		},
		{
			name: "Invalid digest header",
			args: args{
				r: getRequestFunc(digestBodyExample, "SHA-512="),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "digest parser error: empty digest value",
		},
		{
			name: "Unsupported digest hash algorithm",
			args: args{
				r: getRequestFunc(digestBodyExample, "SHA-0=test"),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "unsupported digest hash algorithm 'SHA-0'",
		},
		{
			name: "Empty body",
			args: args{
				r: getRequestFunc("", "MD5=xxx"),
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


func TestVerifyDigestCustomAlgorithm(t *testing.T) {
	type args struct {
		r *http.Request
		o DigestOption
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Custom hash algorithm",
			args: args{
				r: getRequestFunc(digestBodyExample, "SHA-256-SALT=Io9cYUVmytq+9dkc8zPPG22x1tJgxIGAtc+6ntuDgLE="),
				o: DigestOption{
					Algorithm: "SHA-256-SALT",
					Hash: func(b []byte) []byte {
						salt := []byte("salt")
						b = append(b, salt[:]...)
						h := sha256.New()
						h.Write(b)
						return h.Sum(nil)
					},
				},
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDigest()
			d.SetOptions([]DigestOption{tt.args.o})
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
