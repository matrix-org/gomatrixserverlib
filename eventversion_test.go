package gomatrixserverlib

import (
	"testing"
)

func TestEventIDForRoomVersionV1(t *testing.T) {
	initialEventJSON := `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`
	expectedEventID := "$yvN1b43rlmcOs5fY:localhost"

	event, err := NewEventFromTrustedJSON([]byte(initialEventJSON), false, RoomVersionV1)
	if err != nil {
		t.Error(err)
	}

	if event.EventID() != expectedEventID {
		t.Fatalf("event ID '%s' does not match expected '%s'", event.EventID(), expectedEventID)
	}
}

func TestEventIDForRoomVersionV5(t *testing.T) {
	initialEventJSON := `{"auth_events": ["$OKPes_DblGAyobzyE1URoHA2-3CIpX3uvjQYrZ5hejo", "$RrGxF28UrHLmoASHndYb9Jb_1SFww2ptmtur9INS438", "$5jwb0LeojBscEuVzdk-YBeuhiSa6ob6ygWA8EmXwfzg", "$eoyXjfFijYvWm3JZ5NQfPzrhiboPdvutpROmD9dYelg"], "content": {"avatar_url": "mxc://matrix.vgorcum.com/ZRlwJNjWFesIsuEjRevGtxkB", "displayname": "Mathijs", "membership": "join"}, "depth": 36, "hashes": {"sha256": "AAvLiR0HgSgxRfmRn+zy3nC4FK0pHo8YCd4yB2uwMM8"}, "origin": "matrix.vgorcum.com", "origin_server_ts": 1560285821015, "prev_events": ["$eoyXjfFijYvWm3JZ5NQfPzrhiboPdvutpROmD9dYelg"], "prev_state": [], "room_id": "!uXDCzlYgCTHtiWCkEx:jki.re", "sender": "@mathijs:matrix.vgorcum.com", "state_key": "@mathijs:matrix.vgorcum.com", "type": "m.room.member", "signatures": {"half-shot.uk": {"ed25519:a_fBAF": "H01dNRn4xNjxmJ+X/JDSPmryfBpmu5Ktacbmrnu32b32Skb+qwjBEee5o6DAUno3n/U6KCkI8JVRd7DxI/ZsBg"}, "matrix.vgorcum.com": {"ed25519:a_SAeW": "Wu8xCepoJ87RaO2H6DgRZK/go8j16ZbqbVbHfSvJF6zeykb6W1YyYLm6MXJcSQYgyhz/4KMdPLXxRImw2TWFCA"}}, "unsigned": {"age": 42, "replaces_state": "$eoyXjfFijYvWm3JZ5NQfPzrhiboPdvutpROmD9dYelg", "prev_content": {"avatar_url": "mxc://matrix.vgorcum.com/ZRlwJNjWFesIsuEjRevGtxkB", "displayname": "Mathijs", "membership": "invite"}, "prev_sender": "@Half-Shot:half-shot.uk"}}`
	expectedEventID := "$tTPjEB-7HV7dpw4dbSAcW-zF9fgCmcBOvsS9X8DFEy4"

	event, err := NewEventFromUntrustedJSON([]byte(initialEventJSON), RoomVersionV5)
	if err != nil {
		t.Error(err)
	}

	if event.EventID() != expectedEventID {
		t.Fatalf("event ID '%s' does not match expected '%s'", event.EventID(), expectedEventID)
	}
}