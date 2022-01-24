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
	"encoding/json"
	"testing"
)

func BenchmarkLevelJSONValueInt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		var value []levelJSONValue
		_ = json.Unmarshal([]byte(`[1, 2, 3]`), &value)
	}
}

func BenchmarkLevelJSONValueFloat(b *testing.B) {
	for n := 0; n < b.N; n++ {
		var value []levelJSONValue
		_ = json.Unmarshal([]byte(`[1.1, 1.2, 1.3]`), &value)
	}
}

func BenchmarkLevelJSONValueString(b *testing.B) {
	for n := 0; n < b.N; n++ {
		var value []levelJSONValue
		_ = json.Unmarshal([]byte(`["1", "2", "3"]`), &value)
	}
}

func TestLevelJSONValueValid(t *testing.T) {
	var values []levelJSONValue
	input := `[0,"1",2.0]`
	if err := json.Unmarshal([]byte(input), &values); err != nil {
		t.Fatal("Unexpected error unmarshalling ", input, ": ", err)
	}
	for i, got := range values {
		want := i
		if !got.exists {
			t.Fatalf("Wanted entry %d to exist", want)
		}
		if int64(want) != got.value {
			t.Fatalf("Wanted %d got %q", want, got.value)
		}
	}
}

func TestLevelJSONValueInvalid(t *testing.T) {
	var values []levelJSONValue
	inputs := []string{
		`[{}]`, `[[]]`, `["not a number"]`, `["0.0"]`,
	}

	for _, input := range inputs {
		if err := json.Unmarshal([]byte(input), &values); err == nil {
			t.Fatalf("Unexpected success when unmarshalling %q", input)
		}
	}
}

func TestStrictPowerLevelContent(t *testing.T) {
	eventJSON := `{"content":{"ban":50,"events":{"m.room.avatar":50,"m.room.canonical_alias":50,"m.room.encryption":100,"m.room.history_visibility":100,"m.room.name":50,"m.room.power_levels":100,"m.room.server_acl":100,"m.room.tombstone":100},"events_default":0,"historical":100,"invite":0,"kick":50,"redact":50,"state_default":50,"users":{"@neilalexander:matrix.org":"100"},"users_default":0},"origin_server_ts":1643017369993,"sender":"@neilalexander:matrix.org","state_key":"","type":"m.room.power_levels","unsigned":{"age":592},"event_id":"$2CT2RSF8B4XJyysh7i6Zdw0oYSs53JkIhTMrapIVYnw","room_id":"!CeUyQRqMxuBnjcxiIr:matrix.org"}`
	goodEvent, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV7)
	if err != nil {
		t.Fatal(err)
	}
	badEvent, err := NewEventFromTrustedJSON([]byte(eventJSON), false, "org.matrix.msc3667")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := goodEvent.PowerLevels(); err != nil {
		t.Fatalf("good content should not have errored but did: %s", err)
	}
	if _, err := badEvent.PowerLevels(); err == nil {
		t.Fatal("bad content should have errored but didn't")
	}
}
