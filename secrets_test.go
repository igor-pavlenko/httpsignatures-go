package httpsignatures

import (
	"errors"
	"testing"
)

func TestSecretsError(t *testing.T) {
	err := errors.New("test err")
	e := SecretError{"secret err", err}

	wantErrMsg := "SecretError: secret err: test err"

	if e.Error() != wantErrMsg {
		t.Errorf("error message = `%s`, wantErrMsg = `%s`", e.Error(), wantErrMsg)
	}
}
