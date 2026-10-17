package store

import "encoding/json"

// marshalEventForJSONB ensures PostgreSQL jsonb never receives the \u0000
// escape, which it rejects with SQLSTATE 22P05. Older Windows agent spool
// files may contain this escape due to incorrectly decoded UTF-16 output.
// Keep literal backslash-u text intact; replace only actual JSON NUL escapes.
func marshalEventForJSONB(event any) ([]byte, error) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return replaceJSONNullEscapes(encoded), nil
}

func replaceJSONNullEscapes(encoded []byte) []byte {
	output := make([]byte, 0, len(encoded))
	insideString := false
	for i := 0; i < len(encoded); i++ {
		current := encoded[i]
		if !insideString {
			if current == '"' {
				insideString = true
			}
			output = append(output, current)
			continue
		}
		if current == '"' {
			insideString = false
			output = append(output, current)
			continue
		}
		if current != '\\' {
			output = append(output, current)
			continue
		}
		if i+5 < len(encoded) &&
			encoded[i+1] == 'u' &&
			encoded[i+2] == '0' && encoded[i+3] == '0' &&
			encoded[i+4] == '0' && encoded[i+5] == '0' {
			output = append(output, []byte(`\ufffd`)...)
			i += 5
			continue
		}
		// An escaped quote or escaped backslash is part of the string data.
		// Skip both bytes so its second byte is not treated as syntax.
		output = append(output, current)
		if i+1 < len(encoded) {
			output = append(output, encoded[i+1])
			i++
		}
	}
	return output
}