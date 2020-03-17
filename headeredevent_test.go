package gomatrixserverlib

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalMarshalHeaderedEvent(t *testing.T) {
	output := HeaderedEvent{}
	input := `{"_room_version":"1","auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`

	if err := json.Unmarshal([]byte(input), &output); err != nil {
		t.Fatal(err)
	}

	headered := output.Event.Headered(RoomVersionV1)

	if j, err := json.Marshal(headered); err == nil {
		if string(j) != input {
			t.Logf("got: %s", string(j))
			t.Logf("expected: %s", input)
			t.Fatalf("round-trip unmarshal and marshal produced different results")
		}
	} else {
		t.Fatalf("failed to unmarshal: %v", err)
	}
}
