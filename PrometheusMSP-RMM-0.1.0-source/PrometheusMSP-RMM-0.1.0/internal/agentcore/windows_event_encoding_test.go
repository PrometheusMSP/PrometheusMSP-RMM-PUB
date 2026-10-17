package agentcore

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func encodeUTF16EventText(text string, order binary.ByteOrder, bom bool) []byte {
	units := utf16.Encode([]rune(text))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		order.PutUint16(raw[i*2:], unit)
	}
	if !bom {
		return raw
	}
	if order == binary.LittleEndian {
		return append([]byte{0xff, 0xfe}, raw...)
	}
	return append([]byte{0xfe, 0xff}, raw...)
}

func TestDecodeWindowsEventOutputUTF16LEWithBOM(t *testing.T) {
	want := "Event ID: 42\nMessage: r\u00e9sum\u00e9 \U0001f600"
	raw := encodeUTF16EventText(want, binary.LittleEndian, true)
	if got := decodeWindowsEventOutput(raw); got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestDecodeWindowsEventOutputUTF16LEWithoutBOM(t *testing.T) {
	want := "Event ID: 42\nMessage: Service started"
	raw := encodeUTF16EventText(want, binary.LittleEndian, false)
	if got := decodeWindowsEventOutput(raw); got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestDecodeWindowsEventOutputUTF16BEWithBOM(t *testing.T) {
	want := "Event ID: 42\nMessage: Started"
	raw := encodeUTF16EventText(want, binary.BigEndian, true)
	if got := decodeWindowsEventOutput(raw); got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestDecodeWindowsEventOutputUTF8(t *testing.T) {
	want := "Service start: r\u00e9sum\u00e9"
	raw := append([]byte{0xef, 0xbb, 0xbf}, []byte(want)...)
	if got := decodeWindowsEventOutput(raw); got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestDecodeWindowsEventOutputRemovesNUL(t *testing.T) {
	got := decodeWindowsEventOutput([]byte("a\x00b"))
	if strings.ContainsRune(got, '\x00') {
		t.Fatalf("decoded text still contains NUL: %q", got)
	}
	if !bytes.Equal([]byte(got), []byte("a\ufffdb")) {
		t.Fatalf("got %q; want replacement rune", got)
	}
}