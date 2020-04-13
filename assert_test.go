package httpsignatures

import (
	"reflect"
	"testing"
)

func assert(t *testing.T, got interface{}, err error, eType string, name string, want interface{}, wantErr bool, wantErrMsg string) {
	if err != nil && reflect.TypeOf(err).String() != eType {
		t.Errorf(name+"\nunexpected error type %s", reflect.TypeOf(err).String())
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
