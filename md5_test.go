package httpsignatures

import (
	"encoding/hex"
	"testing"
)

func TestMd5Algorithm(t *testing.T) {
	a := Md5{}
	got := a.Algorithm()
	want := "MD5"
	if got != want {
		t.Errorf("got = %s\nwant = %s", got, want)
	}
}

func TestMd5Create(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name       string
		args       args
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "MD5 create ok",
			args: args{
				data: []byte(`hello world`),
			},
			want:       "5eb63bbbe01eeed093cb22bb8f5acdc3",
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Md5{}
			got, err := a.Create(tt.args.data)
			digest := hex.EncodeToString(got)
			assertCrypto(t, digest, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func TestMd5Verify(t *testing.T) {
	type args struct {
		digest string
		data   []byte
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "MD5 verify ok",
			args: args{
				digest: "5eb63bbbe01eeed093cb22bb8f5acdc3",
				data:   []byte("hello world"),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "MD5 wrong hash",
			args: args{
				digest: "xxx",
				data:   []byte("xx"),
			},
			want:       false,
			wantErr:    true,
			wantErrMsg: "wrong hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Md5{}
			b, _ := hex.DecodeString(tt.args.digest)
			err := a.Verify(tt.args.data, b)
			got := err == nil
			assertCrypto(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}
