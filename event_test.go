/* Copyright 2017 New Vector Ltd
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func benchmarkParse(b *testing.B, eventJSON string) {
	// run the Unparse function b.N times
	for n := 0; n < b.N; n++ {
		if _, err := NewEventFromUntrustedJSON([]byte(eventJSON), RoomVersionV1); err != nil {
			b.Error("Failed to parse event")
		}
	}
}

// Benchmark a more complicated event, in this case a power levels event.

func BenchmarkParseLargerEvent(b *testing.B) {
	benchmarkParse(b, `{"auth_events":[["$Stdin0028C5qBjz5:localhost",{"sha256":"PvTyW+Mfb0aCajkIlBk1XlQE+1uVco3to8C2+/1J7iQ"}],["$klXtjBwwDQIGglax:localhost",{"sha256":"hLoiSkcGLZJr5wkIDA8+bujNJPsYX1SOCCXIErHEcgM"}]],"content":{"ban":50,"events":{"m.room.avatar":50,"m.room.canonical_alias":50,"m.room.history_visibility":100,"m.room.name":50,"m.room.power_levels":100},"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users":{"@test:localhost":100},"users_default":0},"depth":3,"event_id":"$7gPR7SLdkfDsMvJL:localhost","hashes":{"sha256":"/kQnrzO5vhbnwyGvKso4CVMRyyryiyanq6t27mt5kSw"},"origin":"localhost","origin_server_ts":1510854446548,"prev_events":[["$klXtjBwwDQIGglax:localhost",{"sha256":"hLoiSkcGLZJr5wkIDA8+bujNJPsYX1SOCCXIErHEcgM"}]],"prev_state":[],"room_id":"!pUjJbIC8V32G0FLt:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"NOxjrcci7AIRhcTVmJ6nrsslLsaOJzB0iusDZ6cOFrv2OXkDY7mrBM3cQQS3DhGWltEtu3OC0nsvkfeYtwr9DQ"}},"state_key":"","type":"m.room.power_levels"}`)
}

// Lets now test parsing a smaller name event, first one that is valid, then wrong hash, and then the redacted one

func BenchmarkParseSmallerEvent(b *testing.B) {
	benchmarkParse(b, `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`)
}

func BenchmarkParseSmallerEventFailedHash(b *testing.B) {
	benchmarkParse(b, `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test4"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`)
}

func BenchmarkParseSmallerEventRedacted(b *testing.B) {
	benchmarkParse(b, `{"event_id":"$yvN1b43rlmcOs5fY:localhost","sender":"@test:localhost","room_id":"!19Mp0U9hjajeIiw1:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"content":{},"type":"m.room.name","state_key":"","depth":7,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"origin":"localhost","origin_server_ts":1510854416361}`)
}

func TestAddUnsignedField(t *testing.T) {
	initialEventJSON := `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`
	expectedEventJSON := `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name","unsigned":{"foo":"bar","x":1}}`

	event, err := NewEventFromTrustedJSON([]byte(initialEventJSON), false, RoomVersionV1)
	if err != nil {
		t.Error(err)
	}

	err = event.SetUnsignedField("foo", "bar")
	if err != nil {
		t.Error("Failed to insert foo")
	}

	err = event.SetUnsignedField("x", 1)
	if err != nil {
		t.Error("Failed to insert x")
	}

	if expectedEventJSON != string(event.JSON()) {
		t.Fatalf("Serialized event does not match expected: %s != %s", string(event.JSON()), initialEventJSON)
	}
}

// TestRedact makes sure Redact works as expected.
func TestRedact(t *testing.T) {
	// v1 event
	nameEvent := ` {"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`
	event, err := NewEventFromTrustedJSON([]byte(nameEvent), false, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}
	event = event.Redact()
	if !reflect.DeepEqual([]byte(`{}`), event.Content()) {
		t.Fatalf("content not redacted: %s", string(event.Content()))
	}

	// v5 event
	nameEvent = `{"auth_events":["$x4MKEPRSF6OGlo0qpnsP3BfSmYX5HhVlykOsQH3ECyg","$BcEcbZnlFLB5rxSNSZNBn6fO3jU_TKAJ79wfKyCQLiU"],"content":{"name":"test123"},"depth":2,"hashes":{"sha256":"5S025c0BhumelvCXMXWlislPnDYJn18mm9XMClL1OZ8"},"origin":"localhost","origin_server_ts":0,"prev_events":["$BcEcbZnlFLB5rxSNSZNBn6fO3jU_TKAJ79wfKyCQLiU"],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"VHCB/tai3S2nBpvYWnOlJfjt2KcxsgBJ1W6xDYUMOxGehDOd+lI2wy5ZBZydy1xFdIBzuERn9t9aiFThIHHcCA"}},"state_key":"","type":"m.room.name"}`
	event, err = NewEventFromTrustedJSON([]byte(nameEvent), false, RoomVersionV5)
	if err != nil {
		t.Fatal(err)
	}
	event = event.Redact()
	if !reflect.DeepEqual([]byte(`{}`), event.Content()) {
		t.Fatalf("content not redacted: %s", string(event.Content()))
	}
}

func TestEventMembership(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}]],"content":{"membership":"join"},"depth":1,"event_id":"$9fmIxbx4IX8w1JVo:localhost","hashes":{"sha256":"mXgoJxvMyI8ZTdhUMYwWzi0F3M50tiAQkmk0F08tQl4"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"ndobFGFV9i2XExPHfYVI4rd10Vw6GKtmdz2Wv0WSFohtm/FqFNUnDYVTsY/qZ1vkuEjHqgb5nscKD/i7TyURBw"}},"state_key":"@userid:localhost","type":"m.room.member"}`
	event, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.Membership()
	if err != nil {
		t.Fatal(err)
	}
	want := "join"
	if got != want {
		t.Errorf("membership: got %s want %s", got, want)
	}
}

func TestEventJoinRule(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"join_rule":"public"},"depth":2,"event_id":"$5hL9YWgJCtDzjlAQ:localhost","hashes":{"sha256":"CetHe0Na5HKphg5iYmLThfwQyM19w3PMCrve3Bwv8rw"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"dxwQWiH6ppF+VVFQ8IEAWeB30hrYiZWLsWNTrE1B0/vUWMp+qLhU+My65XhmE5XreHvgY3fOh4Le6OYUcxNTAw"}},"state_key":"","type":"m.room.join_rules"}`
	event, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.JoinRule()
	if err != nil {
		t.Fatal(err)
	}
	want := "public"
	if got != want {
		t.Errorf("join rule: got %s want %s", got, want)
	}
}

func TestEventHistoryVisibility(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"history_visibility":"shared"},"depth":3,"event_id":"$QAhQsLNIMdumtpOi:localhost","hashes":{"sha256":"tssm21TZjY36w9ND9h50h5zL0vqJgz5U432l45WWGaI"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$5hL9YWgJCtDzjlAQ:localhost",{"sha256":"UztZf0/CBZ8UoCHuYdrxlfyUZ5nf5h8aKZkg5GVhWI0"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"FwBwMZnGjkZFt8aiWQODSmLmy1cxVZGOFkeu3JEUVEI5r4/2BMcwdYw6+am7ov4VfDRJ/ehp9wv3Bo93XLEJCQ"}},"state_key":"","type":"m.room.history_visibility"}`
	event, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.HistoryVisibility()
	if err != nil {
		t.Fatal(err)
	}
	want := "shared"
	if got != want {
		t.Errorf("history visibility: got %s want %s", got, want)
	}
}

func TestEventPowerLevels(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"ban":50,"events":null,"events_default":0,"invite":50,"kick":50,"redact":50,"state_default":50,"users":null,"users_default":0,"notifications":{"room":50}},"depth":4,"event_id":"$1570trwyGMovM5uU:localhost","hashes":{"sha256":"QvWo2OZufVTMUkPcYQinGVeeHEODWY6RUMaHRxdT31Y"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$QAhQsLNIMdumtpOi:localhost",{"sha256":"RqoKwu8u8qL+wDoka23xvd7t9UoOXLRQse/bK3o9qLE"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"0oPZsvPkbNNVwRrLAP+fEyxFRAIUh0Zn7NPH3LybNC8lMz0GyPtN1bKlTVQYMwZBTXCV795s+CEgoIX+M5gkAQ"}},"state_key":"","type":"m.room.power_levels"}`
	event, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.PowerLevels()
	if err != nil {
		t.Fatal(err)
	}
	var want PowerLevelContent
	want.Defaults()
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("power levels: got %+v want %+v", got, want)
	}
}

func TestHeaderedEventToNewEventFromUntrustedJSON(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"ban":50,"events":null,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users":null,"users_default":0},"depth":4,"event_id":"$1570trwyGMovM5uU:localhost","hashes":{"sha256":"QvWo2OZufVTMUkPcYQinGVeeHEODWY6RUMaHRxdT31Y"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$QAhQsLNIMdumtpOi:localhost",{"sha256":"RqoKwu8u8qL+wDoka23xvd7t9UoOXLRQse/bK3o9qLE"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"0oPZsvPkbNNVwRrLAP+fEyxFRAIUh0Zn7NPH3LybNC8lMz0GyPtN1bKlTVQYMwZBTXCV795s+CEgoIX+M5gkAQ"}},"state_key":"","type":"m.room.power_levels"}`
	event, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(event.Headered(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewEventFromUntrustedJSON(j, RoomVersionV1)
	if !errors.Is(err, UnexpectedHeaderedEvent{}) {
		t.Fatal("expected an UnexpectedHeaderedEvent error but got:", err)
	}
}

func TestSplitID(t *testing.T) {
	t.Run("To short id",
		func(t *testing.T) {
			_, _, err := SplitID('@', "")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"\"", "To short id")
		})
	t.Run("Mismatch Sigil",
		func(t *testing.T) {
			_, _, err := SplitID('@', "#1234abcd:test")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"#1234abcd:test\" doesn't start with '@'", "Mismatch Sigil incorrect error")
		})
}

func difference(slice1 []rune, slice2 []rune) []rune {
	diffStr := []rune{}
	m := map[rune]int{}

	for _, s1Val := range slice1 {
		m[s1Val] = 1
	}
	for _, s2Val := range slice2 {
		m[s2Val] = m[s2Val] + 1
	}

	for mKey, mVal := range m {
		if mVal == 1 {
			diffStr = append(diffStr, mKey)
		}
	}

	return diffStr
}
func TestSplitUserID(t *testing.T) {
	testFunction := SplitUserID
	supportedSigils := GetUserSigils()
	t.Run("To short id",
		func(t *testing.T) {
			_, _, err := testFunction("")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"\"", "To short id")
		})
	t.Run("Mismatch Sigil",
		func(t *testing.T) {
			notUserSigil := difference(GetSupportedSigils(), supportedSigils)
			for _, sigil := range notUserSigil {
				_, _, err := testFunction(string(sigil) + "1234abcd:test")
				assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \""+string(sigil)+"1234abcd:test\" doesn't start with valid sigil '"+string(sigil)+"'", "Mismatch Sigil incorrect error")
			}
		})
	t.Run("Matching Sigil",
		func(t *testing.T) {
			for _, sigil := range supportedSigils {
				localpart, domain, err := testFunction(string(sigil) + "1234abcd:test")
				if err != nil {
					t.Fatal(err)
				}
				if sigil == UserIDSigil {
					assert.Equal(t, "1234abcd", localpart, "The localpart should parse for sigil"+string(sigil))
					assert.Equal(t, ServerName("test"), domain, "The domain should parse for sigil"+string(sigil))

				} else {
					assert.Equal(t, "234abcd:test", localpart, "The localpart should parse for sigil"+string(sigil))
					assert.Equal(t, ServerName(""), domain, "The domain should parse for sigil"+string(sigil))

				}
			}
		})
}

func TestSplitRoomID(t *testing.T) {
	testFunction := SplitRoomID
	supportedSigils := GetRoomSigils()
	t.Run("To short id",
		func(t *testing.T) {
			_, _, err := testFunction("")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"\"", "To short id")
		})
	t.Run("Mismatch Sigil",
		func(t *testing.T) {
			notRoomSigil := difference(GetSupportedSigils(), supportedSigils)
			for _, sigil := range notRoomSigil {
				_, _, err := testFunction(string(sigil) + "1234abcd:test")
				assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \""+string(sigil)+"1234abcd:test\" doesn't start with valid sigil '"+string(sigil)+"'", "Mismatch Sigil incorrect error")
			}
		})
	t.Run("Matching Sigil",
		func(t *testing.T) {
			for _, sigil := range supportedSigils {
				localpart, domain, err := testFunction(string(sigil) + "1234abcd:test")
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, "1234abcd", localpart, "The localpart should parse for sigil"+string(sigil))
				assert.Equal(t, ServerName("test"), domain, "The domain should parse for sigil"+string(sigil))
			}
		})
}

func TestSplitGroupID(t *testing.T) {
	testFunction := SplitGroupID
	supportedSigils := []rune{GroupIDSigil}
	t.Run("To short id",
		func(t *testing.T) {
			_, _, err := testFunction("")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"\"", "To short id")
		})
	t.Run("Mismatch Sigil",
		func(t *testing.T) {
			notGroupSigil := difference(GetSupportedSigils(), supportedSigils)
			for _, sigil := range notGroupSigil {
				_, _, err := testFunction(string(sigil) + "1234abcd:test")
				assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \""+string(sigil)+"1234abcd:test\" doesn't start with valid sigil '"+string(sigil)+"'", "Mismatch Sigil incorrect error")
			}
		})
	t.Run("Matching Sigil",
		func(t *testing.T) {
			for _, sigil := range supportedSigils {
				localpart, domain, err := testFunction(string(sigil) + "1234abcd:test")
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, "1234abcd", localpart, "The localpart should parse for sigil"+string(sigil))
				assert.Equal(t, ServerName("test"), domain, "The domain should parse for sigil"+string(sigil))
			}
		})
}

func TestSplitEventID(t *testing.T) {
	testFunction := SplitEventID
	supportedSigils := []rune{EventIDSigil}
	t.Run("To short id",
		func(t *testing.T) {
			_, _, err := testFunction("")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"\"", "To short id")
		})
	t.Run("Mismatch Sigil",
		func(t *testing.T) {
			notGroupSigil := difference(GetSupportedSigils(), supportedSigils)
			for _, sigil := range notGroupSigil {
				_, _, err := testFunction(string(sigil) + "1234abcd:test")
				assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \""+string(sigil)+"1234abcd:test\" doesn't start with valid sigil '"+string(sigil)+"'", "Mismatch Sigil incorrect error")
			}
		})
	t.Run("Matching Sigil",
		func(t *testing.T) {
			for _, sigil := range supportedSigils {
				localpart, domain, err := testFunction(string(sigil) + "1234abcd:test")
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, "1234abcd", localpart, "The localpart should parse for sigil"+string(sigil))
				assert.Equal(t, ServerName("test"), domain, "The domain should parse for sigil"+string(sigil))
			}
		})
}

func TestSplitIDWithSigil(t *testing.T) {
	t.Run("Too short id",
		func(t *testing.T) {
			_, _, err := splitIDWithSigil("")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"\"", "Too short id")
		})
	t.Run("Invalid Sigil",
		func(t *testing.T) {
			_, _, err := splitIDWithSigil("%1234abcd:test")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid sigil '%'", "Invalid Sigil incorrect error")
		})

	t.Run("No ServerName",
		func(t *testing.T) {
			_, _, err := splitIDWithSigil("@1234abcd_test")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"@1234abcd_test\" missing ':'", "No ServerName incorrect error")
		})

	t.Run("UserID",
		func(t *testing.T) {
			localpart, domain, err := splitIDWithSigil("@1234abcd:test")
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, "1234abcd", localpart, "The localpart should parse")
			assert.Equal(t, ServerName("test"), domain, "The domain should parse")
		})
	t.Run("UserID - Missing :",
		func(t *testing.T) {
			_, _, err := splitIDWithSigil("@1234Abcdtest")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"@1234Abcdtest\" missing ':'", "No : in UserID")

		})
	t.Run("UserID - Invalid",
		func(t *testing.T) {
			_, _, err := splitIDWithSigil("@1234Abcd:test")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid local ID \"1234Abcd\"", "Error should be: %v, got: %v", "gomatrixserverlib: invalid local ID \"1234Abcd\"", err)

		})

	t.Run("UserID - UPK",
		func(t *testing.T) {
			pubKey, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			encodedKey := base64.URLEncoding.EncodeToString(pubKey)
			localpart, domain, err := splitIDWithSigil("~1" + encodedKey)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, encodedKey, localpart, "The localpart should parse")
			assert.Equal(t, ServerName(""), domain, "The domain should parse")
		})

	t.Run("UserID - Unsupported UPK version",
		func(t *testing.T) {
			pubKey, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			encodedKey := base64.URLEncoding.EncodeToString(pubKey)
			_, _, err = splitIDWithSigil("~2" + encodedKey)
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid UPK version '2'", "Only version 1 supported at this time")
		})

	t.Run("GroupID",
		func(t *testing.T) {
			localpart, domain, err := splitIDWithSigil("+group/=_-.123:my.domain")
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, "group/=_-.123", localpart, "The localpart should parse")
			assert.Equal(t, ServerName("my.domain"), domain, "The domain should parse")
		})
	t.Run("GroupID - Missing :",
		func(t *testing.T) {
			_, _, err := splitIDWithSigil("+group/=_-.123my.domain")
			assert.EqualErrorf(t, err, "gomatrixserverlib: invalid ID \"+group/=_-.123my.domain\" missing ':'", "No : in UserID")

		})

	t.Run("RoomAlias",

		func(t *testing.T) {
			localpart, domain, err := splitIDWithSigil("#channel:test")
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, "channel", localpart, "The localpart should parse")
			assert.Equal(t, ServerName("test"), domain, "The domain should parse")
		})
}
