package httpsignatures

import (
	"encoding/hex"
	"testing"
)

func TestSha512Algorithm(t *testing.T) {
	a := Sha512{}
	got := a.Algorithm()
	want := "SHA-512"
	if got != want {
		t.Errorf("got = %s\nwant = %s", got, want)
	}
}

func TestSha512Create(t *testing.T) {
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
			name: "Sha512 create ok",
			args: args{
				data: []byte(`hello world`),
			},
			want:       "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Sha512{}
			got, err := a.Create(tt.args.data)
			digest := hex.EncodeToString(got)
			assertCrypto(t, digest, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}

func TestSha512Verify(t *testing.T) {
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
			name: "Sha512 verify ok",
			args: args{
				digest: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
				data:   []byte("hello world"),
			},
			want:       true,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "Sha512 wrong hash",
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
			a := Sha512{}
			b, _ := hex.DecodeString(tt.args.digest)
			err := a.Verify(tt.args.data, b)
			got := err == nil
			assertCrypto(t, got, err, tt.name, tt.want, tt.wantErr, tt.wantErrMsg)
		})
	}
}
