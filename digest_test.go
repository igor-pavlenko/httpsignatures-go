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
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "MD5=Sd/dVLAcvNLSq16eXua5uQ==")
					return r
				})(),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Valid SHA-1 digest",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "SHA-1=07CavjDP4u3/TungoUHJO/Wzr4c=")
					return r
				})(),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Valid SHA-256 digest",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
					return r
				})(),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Valid SHA-512 digest",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "SHA-512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==")
					return r
				})(),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Invalid MD5 digest",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "MD5=123456")
					return r
				})(),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "MD5 of body does not match with digest",
		},
		{
			name: "Invalid digest header",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "SHA-512=")
					return r
				})(),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "digest parser error: empty digest value",
		},
		{
			name: "Unsupported digest hash algorithm",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "SHA-0=test")
					return r
				})(),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "unsupported digest hash algorithm 'SHA-0'",
		},
		{
			name: "Empty body",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, nil)
					r.Header.Set("Digest", "MD5=Sd/dVLAcvNLSq16eXua5uQ==")
					return r
				})(),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "empty body",
		},
		{
			name: "Custom hash algorithm",
			args: args{
				r: (func() *http.Request {
					r, _ := http.NewRequest(http.MethodPost, digestHostExample, strings.NewReader(digestBodyExample))
					r.Header.Set("Digest", "SHA-256-SALT=Io9cYUVmytq+9dkc8zPPG22x1tJgxIGAtc+6ntuDgLE=")
					return r
				})(),
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
			if tt.args.o.Algorithm != "" {
				d.SetOptions([]DigestOption{tt.args.o})
			}
			got, err := d.VerifyDigest(tt.args.r)
			if e, ok := err.(*DigestError); err != nil && ok == false {
				t.Errorf(tt.name+"\nunexpected error type %v", e)
			}
			if err != nil && err.Error() != tt.wantErrMsg {
				t.Errorf(tt.name+"\nerror message = `%s`, wantErrMsg = `%s`", err.Error(), tt.wantErrMsg)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf(tt.name+"\nerror = `%v`, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf(tt.name+"\ngot  = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}
