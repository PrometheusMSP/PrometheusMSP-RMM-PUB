package agentcore

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// decodeWindowsEventOutput converts wevtutil's raw stdout to usable UTF-8.
// wevtutil may emit UTF-16 with or without a BOM; Go's exec.Output does not
// automatically decode the Windows process output.
func decodeWindowsEventOutput(raw []byte) string {
	switch {
	case bytes.HasPrefix(raw, []byte{0xff, 0xfe}):
		return sanitizeWindowsEventText(decodeUTF16EventText(raw[2:], binary.LittleEndian))
	case bytes.HasPrefix(raw, []byte{0xfe, 0xff}):
		return sanitizeWindowsEventText(decodeUTF16EventText(raw[2:], binary.BigEndian))
	case bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}):
		return sanitizeWindowsEventText(string(raw[3:]))
	}

	if byteOrder := detectUTF16EventByteOrder(raw); byteOrder != nil {
		return sanitizeWindowsEventText(decodeUTF16EventText(raw, byteOrder))
	}
	return sanitizeWindowsEventText(string(raw))
}

func detectUTF16EventByteOrder(raw []byte) binary.ByteOrder {
	pairs := len(raw) / 2
	if pairs > 256 {
		pairs = 256
	}
	if pairs < 4 {
		return nil
	}
	var oddZeros, evenZeros int
	for i := 0; i < pairs; i++ {
		if raw[i*2] == 0 {
			evenZeros++
		}
		if raw[i*2+1] == 0 {
			oddZeros++
		}
	}
	if oddZeros >= pairs/4 && oddZeros > 2*evenZeros {
		return binary.LittleEndian
	}
	if evenZeros >= pairs/4 && evenZeros > 2*oddZeros {
		return binary.BigEndian
	}
	return nil
}

func decodeUTF16EventText(raw []byte, order binary.ByteOrder) string {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = order.Uint16(raw[i*2:])
	}
	text := string(utf16.Decode(units))
	if len(raw)%2 != 0 {
		text += "\ufffd"
	}
	return text
}

func sanitizeWindowsEventText(s string) string {
	// NUL is not supported by PostgreSQL jsonb even after JSON escaping.
	s = strings.ReplaceAll(s, "\x00", "\ufffd")
	return strings.ToValidUTF8(s, "\ufffd")
}