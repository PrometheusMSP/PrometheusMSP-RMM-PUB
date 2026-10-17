package store

import (
	"bytes"
	"encoding/json"
	"testing"
)

type testEvent struct {
	Message string            `json:"message"`
	Extra   map[string]string `json:"extra"`
}

func TestMarshalEventForJSONBReplacesNulls(t *testing.T) {
	original := testEvent{
		Message: "a\x00b",
		Extra:   map[string]string{"provider": "x\x00y"},
	}
	raw, err := marshalEventForJSONB(original)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`\u0000`)) {
		t.Fatalf("unrepresentable JSON NUL escape remained: %s", raw)
	}
	var decoded testEvent
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Message != "a\ufffdb" || decoded.Extra["provider"] != "x\ufffdy" {
		t.Fatalf("unexpected normalized event: %#v", decoded)
	}
}

func TestMarshalEventForJSONBPreservesLiteralBackslashU(t *testing.T) {
	original := testEvent{Message: `literal \u0000 must remain literal`}
	raw, err := marshalEventForJSONB(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded testEvent
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Message != original.Message {
		t.Fatalf("literal backslash-u text was changed: %q", decoded.Message)
	}
}

func TestMarshalEventForJSONBPreservesQuotes(t *testing.T) {
	original := testEvent{Message: `Windows service said "hello"`}
	raw, err := marshalEventForJSONB(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded testEvent
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Message != original.Message {
		t.Fatalf("escaped quote handling changed the text: %q", decoded.Message)
	}
}