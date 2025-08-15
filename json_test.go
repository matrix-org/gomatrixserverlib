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

package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestJSONIntegerRanges(t *testing.T) {
	// This value is in range so it should be fine with both room versions
	input := `{"foo": 9007199254740991, "bar": {"baz": 9007199254740991}}`
	if _, err := EnforcedCanonicalJSON([]byte(input), RoomVersionV1); err != nil {
		// Room version 1 allows this value
		t.Errorf("should be valid")
	}
	if _, err := EnforcedCanonicalJSON([]byte(input), RoomVersionV6); err != nil {
		// Room version 6 allows this value
		t.Errorf("should be valid")
	}

	// This time the value is out of range, which was OK before room version 6,
	// but now isn't OK
	input = `{"foo": 9007199254740991, "bar": {"baz": 9007199254740991, "qux": {"another": [9007199254740998]}}}`
	if _, err := EnforcedCanonicalJSON([]byte(input), RoomVersionV1); err != nil {
		// Room version 1 allows this value
		t.Errorf("should be valid")
	}
	if _, err := EnforcedCanonicalJSON([]byte(input), RoomVersionV6); err == nil {
		// Room version 6 shouldn't allow this value
		t.Errorf("should be invalid")
	}
}

func TestJSONFloats(t *testing.T) {
	// This value is in range so it should be fine with both room versions
	input := `{"foo": 1.1}`
	if _, err := EnforcedCanonicalJSON([]byte(input), RoomVersionV1); err != nil {
		// Room version 1 allows this value
		t.Errorf("should be valid")
	}
	if _, err := EnforcedCanonicalJSON([]byte(input), RoomVersionV6); err == nil {
		// Room version 6 forbids this value
		t.Errorf("should be invalid")
	}
}

func testSortJSON(t *testing.T, input, want string) {
	got := SortJSON([]byte(input), nil)

	// Squash out the whitespace before comparing the JSON in case SortJSON had inserted whitespace.
	if string(CompactJSON(got, nil)) != want {
		t.Errorf("SortJSON(%q): want %q got %q", input, want, got)
	}
}

func TestSortJSON(t *testing.T) {
	testSortJSON(t, `[{"b":"two","a":1}]`, `[{"a":1,"b":"two"}]`)
	testSortJSON(t, `{"B":{"4":4,"3":3},"A":{"1":1,"2":2}}`,
		`{"A":{"1":1,"2":2},"B":{"3":3,"4":4}}`)
	testSortJSON(t, `[true,false,null]`, `[true,false,null]`)
	testSortJSON(t, `[9007199254740991]`, `[9007199254740991]`)
	testSortJSON(t, "\t\n[9007199254740991]", `[9007199254740991]`)
}

func testCompactJSON(t *testing.T, input, want string) {
	bytes := CompactJSON([]byte(input), nil)
	got := string(bytes)
	if got != want {
		t.Errorf("CompactJSON(%q):\n want: %q\n got: %q\n bytes: % X", input, want, got, bytes)
	}
}

func TestCompactJSON(t *testing.T) {
	testCompactJSON(t, "{ }", "{}")

	input := `["\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007"]`
	want := input
	testCompactJSON(t, input, want)

	input = `["\u0008\u0009\u000A\u000B\u000C\u000D\u000E\u000F"]`
	want = `["\b\t\n\u000b\f\r\u000e\u000f"]`
	testCompactJSON(t, input, want)

	input = `["\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017"]`
	want = input
	testCompactJSON(t, input, want)

	input = `["\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F"]`
	want = `["\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"]`
	testCompactJSON(t, input, want)

	testCompactJSON(t, `["\u0061\u005C\u0042\u0022"]`, `["a\\B\""]`)
	testCompactJSON(t, `["\u0120"]`, "[\"\u0120\"]")
	testCompactJSON(t, `["\u0FFF"]`, "[\"\u0FFF\"]")
	testCompactJSON(t, `["\u0FFf"]`, "[\"\u0FFF\"]")
	testCompactJSON(t, `["\u1820"]`, "[\"\u1820\"]")
	testCompactJSON(t, `["\uFFFF"]`, "[\"\uFFFF\"]")
	testCompactJSON(t, `["\uD842\uDC20"]`, "[\"\U00020820\"]")
	testCompactJSON(t, `["\uDBFF\uDFFF"]`, "[\"\U0010FFFF\"]")

	// Unpaired UTF-16 surrogate pair
	testCompactJSON(t, `["\uDEAD"]`, "[\"\"]")

	testCompactJSON(t, `["\\"]`, "[\"\\\\\"]")
	testCompactJSON(t, `"`, "\"")
	testCompactJSON(t, `["\b"]`, "[\"\\b\"]")
	testCompactJSON(t, `["\f"]`, "[\"\\f\"]")
	testCompactJSON(t, `["\n"]`, "[\"\\n\"]")
	testCompactJSON(t, `["\r"]`, "[\"\\r\"]")
	testCompactJSON(t, `["\t"]`, "[\"\\t\"]")

	testCompactJSON(t, `"\u000a"`, "\"\\n\"")
	testCompactJSON(t, `"\u000A"`, "\"\\n\"")
	testCompactJSON(t, `"\u0022"`, "\"\\\"\"")
	testCompactJSON(t, `"\u005c"`, "\"\\\\\"")

	testCompactJSON(t, `["\"\\\/"]`, `["\"\\/"]`)
	testCompactJSON(t, `["\/"]`, `["/"]`)
}

func TestVerifyCanonical(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		valid bool
	}{
		//{
		//	name:    "escaped unicode",
		//	input:   []byte(`{"\u00F1":0}`),
		//	valid: false,
		//},
		//{
		//	name:    "long form unicode",
		//	input:   []byte(`{"\u0009":0}`),
		//	valid: false,
		//},
		//{
		//	name:    "escaped unicode surrogate pair",
		//	input:   []byte(`{"\ud83d\udc08":0}`),
		//	valid: false,
		//},
		{
			name:  "negative zero",
			input: []byte(`{"a":-0}`),
			valid: false,
		},
		{
			name:  "number out of bounds upper",
			input: []byte(`{"a":9007199254740992}`),
			valid: false,
		},
		{
			name:  "number out of bounds lower",
			input: []byte(`{"a":-9007199254740992}`),
			valid: false,
		},
		{
			name:  "exponential notation number",
			input: []byte(`{"a":1e5}`),
			valid: false,
		},
		{
			name:  "fractional number",
			input: []byte(`{"a":1.5}`),
			valid: false,
		},
		//{
		//	name:    "unsorted keys",
		//	input:   []byte(`{"b":0,"a":1}`),
		//	valid: false,
		//},
		//{
		//	name:    "unsorted keys in array",
		//	input:   []byte(`{"a":[{"b":0,"a":1},{"b":0,"a":1}]}`),
		//	valid: false,
		//},
		//{
		//	name:    "unnecessary whitespace",
		//	input:   []byte(`{"a": 0}`),
		//	valid: false,
		//},
		//{
		//	name:    "unpaired UTF-16 surrogate",
		//	input:   []byte(`{"a":"\uDEAD"}`),
		//	valid: false,
		//},
		//{
		//	name:    "failure combo",
		//	input:   []byte(`{ "\u00F1": -0, "2": 0, "1": 9007199254740991, "3":1e5, "4": [{"2": 0, "1": 0},{"2": 0, "1": 0}] }`),
		//	valid: false,
		//},
		{
			name:  "canonical JSON",
			input: []byte(`{"1":9007199254740991,"2":0,"3":-9007199254740991,"4":[{"1":0,"2":0},{"1":0,"2":0}],"ñ":0}`),
			valid: true,
		},
		//{
		//	name:      "duplicate keys",
		//	input:     []byte(`{"a":0,"a":1}`),
		//	valid:   false,
		//},
		//{
		//	name:      "nested duplicate keys",
		//	input:     []byte(`{"a":[{"a":0,"a":1}]}`),
		//	valid:   false,
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EnforcedCanonicalJSON(tt.input, RoomVersionV11)

			if !tt.valid && err == nil {
				t.Fatalf("JSON passes canonical check when it shouldn't. \n Original: %s (% X)", tt.input, tt.input)
			}
			if tt.valid && err != nil {
				t.Fatalf("JSON doesn't pass canonical check when it should. \n Original: %s (% X)", tt.input, tt.input)
			}
		})
	}
}

func TestCanonicalConversion(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		canonical []byte
	}{
		{
			name:      "escaped unicode",
			input:     []byte(`{"\u00F1":0}`),
			canonical: []byte(`{"ñ":0}`),
		},
		{
			name:      "escaped unicode surrogate pair",
			input:     []byte(`{"\ud83d\udc08":0}`),
			canonical: []byte(`{"🐈":0}`),
		},
		{
			name:      "negative zero",
			input:     []byte(`{"a":-0}`),
			canonical: []byte(`{"a":0}`),
		},
		//{
		//	name:      "exponential notation number",
		//	input:     []byte(`{"a":1e5}`),
		//	canonical: []byte(`{"a":100000}`),
		//},
		{
			name:      "unsorted keys",
			input:     []byte(`{"b":0,"a":1}`),
			canonical: []byte(`{"a":1,"b":0}`),
		},
		{
			name:      "unsorted keys in array",
			input:     []byte(`{"a":[{"b":0,"a":1},{"b":0,"a":1}]}`),
			canonical: []byte(`{"a":[{"a":1,"b":0},{"a":1,"b":0}]}`),
		},
		{
			name:      "unnecessary whitespace",
			input:     []byte(`{"a": 0}`),
			canonical: []byte(`{"a":0}`),
		},
		{
			name:      "conversion combo",
			input:     []byte(`{ "\u00F1": -0, "2": 0, "1": 9007199254740991, "4": [{"2": 0, "1": 0},{"2": 0, "1": 0}] }`),
			canonical: []byte(`{"1":9007199254740991,"2":0,"4":[{"1":0,"2":0},{"1":0,"2":0}],"ñ":0}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gmslCanonical, err := CanonicalJSON(tt.input)
			if err != nil {
				t.Fatalf("Failed parsing json: %s", err.Error())
			}

			if !bytes.Equal(tt.canonical, gmslCanonical) {
				t.Fatalf("GMSL canonical JSON is not canonical. \n      Original: %s (% X) \nGMSL Canonical: %s (% X) \n Expected Form: %s (% X)", tt.input, tt.input, gmslCanonical, gmslCanonical, tt.canonical, tt.canonical)
			}
		})
	}
}

func TestCompactUnicodeEscapeWithUTF16Surrogate(t *testing.T) {
	input := []byte(`\ud83d\udc08`)
	output, n := compactUnicodeEscape(input[2:], nil, 0)
	if n != 10 {
		t.Fatalf("should have consumed 10 bytes but consumed only %d bytes", n)
	}
	if string(output) != "🐈" {
		t.Fatalf("expected a cat emoji")
	}
}

func TestCompactUnicodeEscapeWithBadUTF16Surrogate(t *testing.T) {
	input := []byte(`\ud83d\zdc08`)
	output, n := compactUnicodeEscape(input[2:], nil, 0)
	if n != 4 {
		t.Fatalf("should have consumed 4 bytes but consumed %d bytes", n)
	}
	if string(output) != "" {
		t.Fatalf("expected output to be empty")
	}

	input = []byte(`\ud83d udc08`)
	output, n = compactUnicodeEscape(input[2:], nil, 0)
	if n != 4 {
		t.Fatalf("should have consumed 4 bytes but consumed %d bytes", n)
	}
	if string(output) != "" {
		t.Fatalf("expected output to be empty")
	}
}

func testReadHex(t *testing.T, input string, want rune) {
	got := readHexDigits([]byte(input))
	if want != got {
		t.Errorf("readHexDigits(%q): want 0x%x got 0x%x", input, want, got)
	}
}

func TestReadHex(t *testing.T) {
	testReadHex(t, "0123", 0x0123)
	testReadHex(t, "4567", 0x4567)
	testReadHex(t, "89AB", 0x89AB)
	testReadHex(t, "CDEF", 0xCDEF)
	testReadHex(t, "89ab", 0x89AB)
	testReadHex(t, "cdef", 0xCDEF)
}

func TestEventJSON(t *testing.T) {
	resp := struct {
		Events EventJSONs
	}{}
	jsonValue := []byte(`{"events":[{"foo":"bar"}, {"baz":"quuz"}]}`)
	if err := json.Unmarshal(jsonValue, &resp); err != nil {
		t.Fatalf("failed to unmarshal: %s", err)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(resp.Events))
	}
	if !reflect.DeepEqual([]byte(resp.Events[0]), []byte(`{"foo":"bar"}`)) {
		t.Fatalf("first event wrong, got %s", string(resp.Events[0]))
	}
	if !reflect.DeepEqual([]byte(resp.Events[1]), []byte(`{"baz":"quuz"}`)) {
		t.Fatalf("first event wrong, got %s", string(resp.Events[1]))
	}
}
