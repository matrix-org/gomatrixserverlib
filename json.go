package matrixfederation

import (
	"encoding/binary"
	"encoding/json"
	"sort"
	"unicode/utf8"
)

// CanonicalJSON re-encodes the JSON in a cannonical encoding. The encoding is
// the shortest possible encoding using integer values with sorted object keys.
func CanonicalJSON(input []byte) ([]byte, error) {
	sorted, err := SortJSON(input, make([]byte, 0, len(input)))
	if err != nil {
		return nil, err
	}
	return CompactJSON(sorted, make([]byte, 0, len(sorted))), nil
}

// SortJSON reencodes the JSON with the object keys sorted by lexicographically
// by codepoint. The input must be valid JSON.
func SortJSON(input, output []byte) ([]byte, error) {
	// Skip to the first character that isn't whitespace.
	var decoded interface{}
	if err := json.Unmarshal(input, &decoded); err != nil {
		return nil, err
	}
	return sortJSONValue(decoded, output)
}

func sortJSONValue(input interface{}, output []byte) ([]byte, error) {
	switch value := input.(type) {
	case []interface{}:
		// If the JSON is an array then we need to sort the keys of its children.
		return sortJSONArray(value, output)
	case map[string]interface{}:
		// If the JSON is an object then we need to sort its keys and the keys of its children.
		return sortJSONObject(value, output)
	default:
		// Otherwise the JSON is a value and can be encoded without any further sorting.
		bytes, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return append(output, bytes...), nil
	}
}

func sortJSONArray(input []interface{}, output []byte) ([]byte, error) {
	var err error
	sep := byte('[')
	for _, value := range input {
		output = append(output, sep)
		sep = ','
		if output, err = sortJSONValue(value, output); err != nil {
			return nil, err
		}
	}
	if sep == '[' {
		// If sep is still '[' then the array was empty and we never wrote the
		// initial '[', so we write it now along with the closing ']'.
		output = append(output, '[', ']')
	} else {
		// Otherwise we end the array by writing a single ']'
		output = append(output, ']')
	}
	return output, nil
}

func sortJSONObject(input map[string]interface{}, output []byte) ([]byte, error) {
	var err error
	keys := make([]string, len(input))
	var j int
	for key := range input {
		keys[j] = key
		j++
	}
	sort.Strings(keys)
	sep := byte('{')
	for _, key := range keys {
		output = append(output, sep)
		sep = ','
		var encoded []byte
		if encoded, err = json.Marshal(key); err != nil {
			return nil, err
		}
		output = append(output, encoded...)
		output = append(output, ':')
		if output, err = sortJSONValue(input[key], output); err != nil {
			return nil, err
		}
	}
	if sep == '{' {
		// If sep is still '{' then the object was empty and we never wrote the
		// initial '{', so we write it now along with the closing '}'.
		output = append(output, '{', '}')
	} else {
		// Otherwise we end the object by writing a single '}'
		output = append(output, '}')
	}
	return output, nil
}

// CompactJSON makes the encoded JSON as small as possible by removing
// whitespace and unneeded unicode escapes
func CompactJSON(input, output []byte) []byte {
	var i int
	for i < len(input) {
		c := input[i]
		i++
		if c <= ' ' {
			// Skip over whitespace.
			continue
		}
		output = append(output, c)
		if c == '"' {
			for i < len(input) {
				c = input[i]
				i++
				if c == '\\' {
					escape := input[i]
					i++
					if escape == 'u' {
						output, i = compactUnicodeEscape(input, output, i)
					} else {
						if escape == '/' {
							output = append(output, escape)
						} else {
							output = append(output, c, escape)
						}
					}
				} else {
					output = append(output, c)
				}
				if c == '"' {
					break
				}
			}
		}
	}
	return output
}

func compactUnicodeEscape(input, output []byte, index int) ([]byte, int) {
	const (
		ESCAPES = "uuuuuuuubtnufruuuuuuuuuuuuuuuuuu"
		HEX     = "0123456789ABCDEF"
	)
	if len(input)-index < 4 {
		return output, len(input)
	}
	c := readHexDigits(input[index:])
	index += 4
	if c < ' ' {
		escape := ESCAPES[c]
		output = append(output, '\\', escape)
		if escape == 'u' {
			output = append(output, '0', '0', byte('0'+(c>>4)), HEX[c&0xF])
		}
	} else if c == '\\' || c == '"' {
		output = append(output, '\\', byte(c))
	} else if c < 0xD800 || c >= 0xE000 {
		var buffer [4]byte
		n := utf8.EncodeRune(buffer[:], rune(c))
		output = append(output, buffer[:n]...)
	} else {
		if len(input)-index < 6 {
			return output, len(input)
		}
		surrogate := readHexDigits(input[index+2:])
		index += 6
		codepoint := 0x10000 + (((c & 0x3FF) << 10) | (surrogate & 0x3FF))
		var buffer [4]byte
		n := utf8.EncodeRune(buffer[:], rune(codepoint))
		output = append(output, buffer[:n]...)
	}
	return output, index
}

func readHexDigits(input []byte) uint32 {
	hex := binary.BigEndian.Uint32(input)
	// substract '0'
	hex -= 0x30303030
	// strip the higher bits, maps 'a' => 'A'
	hex &= 0x1F1F1F1F
	mask := hex & 0x10101010
	// subtract 'A' - 10 - '9' - 9 = 7 from the letters.
	hex -= mask >> 1
	hex += mask >> 4
	// collect the nibbles
	hex |= hex >> 4
	hex &= 0xFF00FF
	hex |= hex >> 8
	return hex & 0xFFFF
}
