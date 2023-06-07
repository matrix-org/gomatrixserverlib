package gomatrixserverlib

import (
	"testing"
)

func TestEventIDForRoomVersionV1(t *testing.T) {
	initialEventJSON := `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`
	expectedEventID := "$yvN1b43rlmcOs5fY:localhost"

	event, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON([]byte(initialEventJSON), false)
	if err != nil {
		t.Error(err)
	}

	if event.EventID() != expectedEventID {
		t.Fatalf("event ID '%s' does not match expected '%s'", event.EventID(), expectedEventID)
	}
}

func TestEventIDForRoomVersionV3(t *testing.T) {
	initialEventJSON := `{"auth_events": [], "prev_events": [], "type": "m.room.create", "room_id": "!uXDCzlYgCTHtiWCkEx:jki.re", "sender": "@erikj:jki.re", "content": {"room_version": "5", "predecessor": {"room_id": "!gdRMqOrTFdOCYHNwOo:half-shot.uk", "event_id": "$LP7ROBc4b+cMc1UE9haIz8q5AK2AIW4eJ90FfKLvyZI"}, "creator": "@erikj:jki.re"}, "depth": 1, "prev_state": [], "state_key": "", "origin": "jki.re", "origin_server_ts": 1560284621137, "hashes": {"sha256": "IX6zuNiJpJPNf70BLleL3HSCpjKeq9Uhu7uUpyDjBmc"}, "signatures": {"jki.re": {"ed25519:auto": "O4IyFfF2PPtGp5uaDm8t57dZbdh8vc8Q64LgCwvzYRVItAMI0uisfiAFaxkVT7MRpzh6N2QNN5NMRXZKmgPYDA"}}, "unsigned": {"age": 1321650}}`
	expectedEventID := "$RrGxF28UrHLmoASHndYb9Jb/1SFww2ptmtur9INS438"

	event, err := MustGetRoomVersion(RoomVersionV3).NewEventFromTrustedJSON([]byte(initialEventJSON), false)
	if err != nil {
		t.Error(err)
	}

	if event.EventID() != expectedEventID {
		t.Fatalf("event ID '%s' does not match expected '%s'", event.EventID(), expectedEventID)
	}
}

func TestEventIDForRoomVersionV4(t *testing.T) {
	initialEventJSON := `{"auth_events": [], "prev_events": [], "type": "m.room.create", "room_id": "!uXDCzlYgCTHtiWCkEx:jki.re", "sender": "@erikj:jki.re", "content": {"room_version": "5", "predecessor": {"room_id": "!gdRMqOrTFdOCYHNwOo:half-shot.uk", "event_id": "$LP7ROBc4b+cMc1UE9haIz8q5AK2AIW4eJ90FfKLvyZI"}, "creator": "@erikj:jki.re"}, "depth": 1, "prev_state": [], "state_key": "", "origin": "jki.re", "origin_server_ts": 1560284621137, "hashes": {"sha256": "IX6zuNiJpJPNf70BLleL3HSCpjKeq9Uhu7uUpyDjBmc"}, "signatures": {"jki.re": {"ed25519:auto": "O4IyFfF2PPtGp5uaDm8t57dZbdh8vc8Q64LgCwvzYRVItAMI0uisfiAFaxkVT7MRpzh6N2QNN5NMRXZKmgPYDA"}}, "unsigned": {"age": 1321650}}`
	expectedEventID := "$RrGxF28UrHLmoASHndYb9Jb_1SFww2ptmtur9INS438"

	event, err := MustGetRoomVersion(RoomVersionV4).NewEventFromTrustedJSON([]byte(initialEventJSON), false)
	if err != nil {
		t.Error(err)
	}

	if event.EventID() != expectedEventID {
		t.Fatalf("event ID '%s' does not match expected '%s'", event.EventID(), expectedEventID)
	}
}
