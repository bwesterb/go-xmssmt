package xmssmt

import (
	"reflect"
	"testing"
)

func TestBinaryUnmarshalingNamedParams(t *testing.T) {
	for _, name := range ListNames() {
		params := ParamsFromName(name)
		if params == nil {
			t.Fatalf("ParamsFromName(%s) is nil", name)
		}
		buf, err := params.MarshalBinary()
		if err != nil {
			t.Fatalf("ParamsFromName(%s).MarshalBinary(): %v ", name, err)
		}
		var params2 Params
		err = params2.UnmarshalBinary(buf)
		if err != nil {
			t.Fatalf("%s: UnmarshalBinary(): %v ", name, err)
		}
		name2, _ := params2.LookupNameAndOid()
		if name2 != name {
			t.Fatalf("%s unmarshaled improperly to %s", name, name2)
		}
	}
}

func testBinaryUnmarshalingCustomParams(params *Params, t *testing.T) {
	buf, err := params.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v ", err)
	}
	var params2 Params
	err = params2.UnmarshalBinary(buf)
	if err != nil {
		t.Fatalf("UnmarshalBinary(): %v ", err)
	}
	if !reflect.DeepEqual(*params, params2) {
		t.Fatalf("Unmarshaling failed")
	}
}

func TestBinaryUnmarshalingCustomParams(t *testing.T) {
	for _, name := range ListNames() {
		params := ParamsFromName(name)
		if params == nil {
			t.Fatalf("ParamsFromName(%s) is nil", name)
		}
		params.WotsW = 4
		testBinaryUnmarshalingCustomParams(params, t)
		params.WotsW = 256
		testBinaryUnmarshalingCustomParams(params, t)
	}
}

func TestParamsString(t *testing.T) {
	for _, name := range ListNames() {
		params := ParamsFromName(name)
		if params == nil {
			t.Fatalf("ParamsFromName(%s) is nil", name)
		}
		name2 := params.String()
		if name != name2 {
			t.Fatalf("ParamsFromName(%s) = %s", name, name2)
		}
	}
}

func TestParseParams(t *testing.T) {
	for _, name := range ListNames() {
		params := ParamsFromName(name)
		params2, err := parseParamsFromName(name)
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", name, err)
		}
		if *params != *params2 {
			t.Fatalf("Parsed %s as %v instead of %v", name, params2, params)
		}
	}
}
