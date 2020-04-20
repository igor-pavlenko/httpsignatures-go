package httpsignatures

import (
	"reflect"
	"testing"
)

func assert(t *testing.T, got interface{}, err error, eType string, name string, want interface{}, wantErrMsg string) {
	if err != nil && reflect.TypeOf(err).String() != eType {
		t.Errorf(name+"\ngot error type %s, expected %s", reflect.TypeOf(err).String(), eType)
	}
	if err != nil && err.Error() != wantErrMsg {
		t.Errorf(name+"\nerror message = `%s`, wantErrMsg = `%s`", err.Error(), wantErrMsg)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(name+"\ngot  = %v,\nwant = %v", got, want)
	}
}
