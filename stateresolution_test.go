package gomatrixserverlib

import (
	"reflect"
	"testing"
)

const (
	sha1OfEventID1A = "\xe5\x89,\xa2\x1cF<&\xf3\rf}\xde\xa5\xef;\xddK\xaaS"
	sha1OfEventID2A = "\xa4\xe4\x10\x1b}\x1a\xf9`\x94\x10\xa3\x84+\xae\x06\x8d\x16A\xfc>"
	sha1OfEventID3B = "\xca\xe8\xde\xb6\xa3\xb6\xee\x01\xc4\xbc\xd0/\x1b\x1c2\x0c\xd3\xa4\xe9\xcb"
)

func TestConflictEventSorter(t *testing.T) {
	input := []PDU{
		&eventV1{roomVersion: RoomVersionV1, EventIDRaw: "@1:a", eventFields: eventFields{Depth: 1}},
		&eventV1{roomVersion: RoomVersionV1, EventIDRaw: "@2:a", eventFields: eventFields{Depth: 2}},
		&eventV1{roomVersion: RoomVersionV1, EventIDRaw: "@3:b", eventFields: eventFields{Depth: 2}},
	}

	got := sortConflictedEventsByDepthAndSHA1(input)
	want := []conflictedEvent{
		{depth: 1, event: input[0]},
		{depth: 2, event: input[2]},
		{depth: 2, event: input[1]},
	}
	copy(want[0].eventIDSHA1[:], sha1OfEventID1A)
	copy(want[1].eventIDSHA1[:], sha1OfEventID3B)
	copy(want[2].eventIDSHA1[:], sha1OfEventID2A)
	if len(want) != len(got) {
		t.Fatalf("Different length: wanted %d, got %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("Different element at index %d: wanted %#v got %#v", i, want[i], got[i])
		}
	}
}

func TestStateResV1(t *testing.T) {
	conf116, _ := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON([]byte(`{"auth_events":[["$eyo4dwZEqjpgVvJQ:localhost:8800",{"sha256":"A+0F+nB0uufU2qZQeKNFMWyuZR/hMVBopfa93uwSB6c"}],["$EvaMCNF3S7LKX3PQ:localhost:8800",{"sha256":"rzZwZu6p+tfFUqZwK/vPcA/JK+FQsnR3S6GqZicyitc"}],["$MK1CUtcLrHv2ZYC1:localhost:8800",{"sha256":"wtpl5Oe7hMbl0PNI7bgO3aDzuSgkN/mMtNVSM8SYuts"}]],"content":{"ban":50,"events":{"m.room.avatar":50,"m.room.canonical_alias":50,"m.room.encryption":100,"m.room.history_visibility":100,"m.room.name":50,"m.room.power_levels":100,"m.room.server_acl":100,"m.room.tombstone":100},"events_default":0,"invite":50,"kick":50,"notifications":{"room":50},"redact":50,"state_default":50,"users":{"@__ANON__-13:localhost:45449":100,"@anon-20230118_153539-14:localhost:8800":100},"users_default":0},"depth":7,"event_id":"$2WAhEQoN2m8IHGeP:localhost:8800","hashes":{"sha256":"jXcgXG/2hJwfb3yDOF/QC5+kX/01FvqECy1zBRfqH/A"},"origin":"localhost:8800","origin_server_ts":1674056179306,"prev_events":[["$V0JEF92cEpkBiCDK:localhost:8800",{"sha256":"p/jgBrovg5lDzBAPNfhjMcbTf9jhus7ByC+GJWKQqNE"}]],"prev_state":[],"room_id":"!BH4klhnOGdvbapqB:localhost:8800","sender":"@anon-20230118_153539-14:localhost:8800","signatures":{"localhost:8800":{"ed25519:B1BmCw":"7vfrHd0YWJFhSLYwhO9T46uWqnqffYwaEW0bXglhKCjBm81wpvrUuHi0WZcJd0g7uLb/qeDIcGFAG0sYVizzAQ"}},"state_key":"","type":"m.room.power_levels"}`), false)
	conf120, _ := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON([]byte(`{"auth_events":[["$eyo4dwZEqjpgVvJQ:localhost:8800",{"sha256":"RHMTf0156SG4DPDeljEIYh66UkrxD2Ixw8vaB5/JSAk"}],["$2WAhEQoN2m8IHGeP:localhost:8800",{"sha256":"jXcgXG/2hJwfb3yDOF/QC5+kX/01FvqECy1zBRfqH/A"}],["$0:localhost:45449",{"sha256":"Bua9COzZbyl6RKS6g/1ByvSZG+ujjkSBtuh4mL825+I"}]],"depth":10,"signatures":{"localhost:45449":{"ed25519:1":"J9HxQfFnLAigHaVt79onVVxUfB6IA2TCxYxecTCxoSBKmwCAgLgBK604jwDz1ZCqoL2f+vSD4LD9rmKMuA/KBg"}},"type":"m.room.power_levels","state_key":"","event_id":"$4:localhost:45449","origin_server_ts":1674056180186,"sender":"@__ANON__-13:localhost:45449","content":{"users":{"@__ANON__-13:localhost:45449":100}},"room_id":"!BH4klhnOGdvbapqB:localhost:8800","hashes":{"sha256":"1DpYQoOEQVYD3lj8wQyn+9EbgsS1yBU4bQLCBmDsHu8"},"prev_events":[["$1:localhost:45449",{"sha256":"IA945vRB+MyCHIoalcxOdfMUidTwVA2MIDj9kfcp1Bk"}]]}`), false)
	conflicted := []PDU{conf116, conf120}

	a1, _ := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON([]byte(`{"auth_events":[],"content":{"creator":"@anon-20230118_153539-14:localhost:8800","room_version":"1"},"depth":1,"event_id":"$eyo4dwZEqjpgVvJQ:localhost:8800","hashes":{"sha256":"RHMTf0156SG4DPDeljEIYh66UkrxD2Ixw8vaB5/JSAk"},"origin":"localhost:8800","origin_server_ts":1674056177787,"prev_events":[],"prev_state":[],"room_id":"!BH4klhnOGdvbapqB:localhost:8800","sender":"@anon-20230118_153539-14:localhost:8800","signatures":{"localhost:8800":{"ed25519:B1BmCw":"87/SoFEvLpqnjQd/elMUuGLFr4ptqjZkex8h6CCUEgswSw09BthCLuOcEYf9/7e7AkUaBILRggHb0uQE3lfgDg"}},"state_key":"","type":"m.room.create"}`), false)
	a2, _ := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON([]byte(`{"auth_events":[["$eyo4dwZEqjpgVvJQ:localhost:8800",{"sha256":"A+0F+nB0uufU2qZQeKNFMWyuZR/hMVBopfa93uwSB6c"}],["$fPkoAVAjJxEvNHYE:localhost:8800",{"sha256":"FQwLvjhGdgxKmo3yg1Hw2oiDH4AmdRrpUnTaseoqR50"}],["$2WAhEQoN2m8IHGeP:localhost:8800",{"sha256":"hGt+ZgKmq6nQxs1Q/EpiUjl4ql5xZMl1FuuiHdyx9XM"}]],"content":{"membership":"join"},"depth":8,"event_id":"$0:localhost:45449","hashes":{"sha256":"Bua9COzZbyl6RKS6g/1ByvSZG+ujjkSBtuh4mL825+I"},"origin_server_ts":1674056179589,"prev_events":[["$2WAhEQoN2m8IHGeP:localhost:8800",{"sha256":"hGt+ZgKmq6nQxs1Q/EpiUjl4ql5xZMl1FuuiHdyx9XM"}]],"room_id":"!BH4klhnOGdvbapqB:localhost:8800","sender":"@__ANON__-13:localhost:45449","signatures":{"localhost:45449":{"ed25519:1":"FAFUhMgAMdAl9oeo8+zOYjHH2ijZwXh49rcPZ1KKjnZnhRPWoN5b02hH9hOFAIx9oHHYZwNpMULEyuVTnbOeDA"},"localhost:8800":{"ed25519:B1BmCw":"pXEvvpHwY7Qt6h6UuQMLpm1zMtgABspQUr7DTf/ds1xL8So7qUBNGCurSxw+/z7rcVjvznZJmvCMeOH83DyHAQ"}},"state_key":"@__ANON__-13:localhost:45449","type":"m.room.member"}`), false)
	a3, _ := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON([]byte(`{"auth_events":[["$eyo4dwZEqjpgVvJQ:localhost:8800",{"sha256":"A+0F+nB0uufU2qZQeKNFMWyuZR/hMVBopfa93uwSB6c"}]],"content":{"displayname":"anon-20230118_153539-14","membership":"join"},"depth":2,"event_id":"$MK1CUtcLrHv2ZYC1:localhost:8800","hashes":{"sha256":"AsccsRhj4M2vRDuBw96Em1SF5WmFpmMAa+wD5KFRZq8"},"origin":"localhost:8800","origin_server_ts":1674056177787,"prev_events":[["$eyo4dwZEqjpgVvJQ:localhost:8800",{"sha256":"A+0F+nB0uufU2qZQeKNFMWyuZR/hMVBopfa93uwSB6c"}]],"prev_state":[],"room_id":"!BH4klhnOGdvbapqB:localhost:8800","sender":"@anon-20230118_153539-14:localhost:8800","signatures":{"localhost:8800":{"ed25519:B1BmCw":"15ZvcsGKh8YOS32HtitWyCUBQSwtNc3SnLkHvSeumz/tkqaui0d/Zee2Hi7uv+cG2S4ta/tTNTQoiibd3h+NCw"}},"state_key":"@anon-20230118_153539-14:localhost:8800","type":"m.room.member"}`), false)

	authEvents := []PDU{a1, a2, a3}

	resolved, err := ResolveConflicts(RoomVersionV1, conflicted, authEvents, UserIDForSenderTest, isRejectedTest)
	if err != nil {
		t.Fatalf("failed to resolve conflicts: %s", err)
	}
	if len(resolved) == 0 {
		t.Fatalf("expected events to be resolved, got none back?")
	}
	if !reflect.DeepEqual(resolved[0], conf116) {
		t.Fatalf("Wrong resolved event:\nexpected: %s\ngot: %s", string(conf116.JSON()), string(resolved[0].JSON()))
	}
}
