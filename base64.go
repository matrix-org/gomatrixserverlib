package matrixfederation

import (
	"encoding/base64"
	"encoding/json"
)

// A Base64String are some bytes encoded using base64 in JSON.
type Base64String []byte

// MarshalJSON encodes the bytes as base64 and then encodes the base64 as a JSON string.
func (b64 Base64String) MarshalJSON() ([]byte, error) {
	// This could be made more efficient by using base64.RawStdEncoding.Encode
	// to write the base64 directly to the JSON. We don't need to JSON escape
	// any of the characters used in base64.
	return json.Marshal(base64.RawStdEncoding.EncodeToString(b64))
}

// UnmarshalJSON decodes a JSON string and then decodes the resulting base64.
func (b64 *Base64String) UnmarshalJSON(raw []byte) (err error) {
	// We could add a fast path that used base64.RawStdEncoding.Decode
	// directly on the raw JSON if the JSON didn't contain any escapes.
	var str string
	err = json.Unmarshal(raw, &str)
	if err != nil {
		return
	}
	*b64, err = base64.RawStdEncoding.DecodeString(str)
	return
}
