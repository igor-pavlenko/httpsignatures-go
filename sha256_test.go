package httpsignatures

import (
	"encoding/hex"
	"testing"
)

func TestSha256Algorithm(t *testing.T) {
	a := Sha256{}
	got := a.Algorithm()
	want := "SHA-256"
	if got != want {
		t.Errorf("got = %s\nwant = %s", got, want)
	}
}

func TestSha256Create(t *testing.T) {
	type args struct {
		data   []byte
	}
	tests := []struct {
		name       string
		args       args
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Sha256 create ok",
			args: args{
				data: []byte(`hello world`),
			},
			want:       "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Sha256{}
			got, err := a.Create(tt.args.data)
			digest := hex.EncodeToString(got)
			assertCrypto(t, digest, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func TestSha256Verify(t *testing.T) {
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
			name: "Sha256 verify ok",
			args: args{
				digest: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
				data:   []byte("hello world"),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Sha256 wrong hash",
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
			a := Sha256{}
			b, _ := hex.DecodeString(tt.args.digest)
			err := a.Verify(tt.args.data, b)
			got := err == nil
			assertCrypto(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}
