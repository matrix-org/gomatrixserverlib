/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package spec

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// A Base64Bytes is a string of bytes (not base64 encoded) that are
// base64 encoded when used in JSON.
//
// The bytes encoded using base64 when marshalled as JSON.
// When the bytes are unmarshalled from JSON they are decoded from base64.
//
// When scanning directly from a database, a string column will be
// decoded from base64 automatically whereas a bytes column will be
// copied as-is.
type Base64Bytes []byte

// Encode encodes the bytes as base64
func (b64 Base64Bytes) Encode() string {
	return base64.RawStdEncoding.EncodeToString(b64)
}

// Decode decodes the given input into this Base64Bytes
func (b64 *Base64Bytes) Decode(str string) error {
	// We must check whether the string was encoded in a URL-safe way in order
	// to use the appropriate encoding.
	var err error
	if strings.ContainsAny(str, "-_") {
		*b64, err = base64.RawURLEncoding.DecodeString(str)
	} else {
		*b64, err = base64.RawStdEncoding.DecodeString(str)
	}
	return err
}

// Implements sql.Scanner
func (b64 *Base64Bytes) Scan(src interface{}) error {
	switch v := src.(type) {
	case string:
		return b64.Decode(v)
	case []byte:
		*b64 = append(Base64Bytes{}, v...)
		return nil
	case RawJSON:
		return b64.UnmarshalJSON(v)
	default:
		return fmt.Errorf("unsupported source type")
	}
}

// Implements sql.Valuer
func (b64 Base64Bytes) Value() (driver.Value, error) {
	return b64.Encode(), nil
}

// MarshalJSON encodes the bytes as base64 and then encodes the base64 as a JSON string.
// This takes a value receiver so that maps and slices of Base64Bytes encode correctly.
func (b64 Base64Bytes) MarshalJSON() ([]byte, error) {
	// This could be made more efficient by using base64.RawStdEncoding.Encode
	// to write the base64 directly to the JSON. We don't need to JSON escape
	// any of the characters used in base64.
	return json.Marshal(b64.Encode())
}

// MarshalYAML implements yaml.Marshaller
// It just encodes the bytes as base64, which is a valid YAML string
func (b64 Base64Bytes) MarshalYAML() (interface{}, error) {
	return b64.Encode(), nil
}

// UnmarshalJSON decodes a JSON string and then decodes the resulting base64.
// This takes a pointer receiver because it needs to write the result of decoding.
func (b64 *Base64Bytes) UnmarshalJSON(raw []byte) (err error) {
	// We could add a fast path that used base64.RawStdEncoding.Decode
	// directly on the raw JSON if the JSON didn't contain any escapes.
	var str string
	if err = json.Unmarshal(raw, &str); err != nil {
		return
	}
	err = b64.Decode(str)
	return
}

// UnmarshalYAML implements yaml.Unmarshaller
// it unmarshals the input as a yaml string and then base64-decodes the result
func (b64 *Base64Bytes) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var str string
	if err = unmarshal(&str); err != nil {
		return
	}
	err = b64.Decode(str)
	return
}
