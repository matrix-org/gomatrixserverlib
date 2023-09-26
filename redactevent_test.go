package gomatrixserverlib

import (
	"bytes"
	"testing"
)

func TestRedactionAlgorithmV4(t *testing.T) {
	// Specifically, the version 4 redaction algorithm used in room
	// version 9 is ensuring that the `join_authorised_via_users_server`
	// key doesn't get redacted.

	input := []byte(`{"content":{"avatar_url":"mxc://something/somewhere","displayname":"Someone","join_authorised_via_users_server":"@someoneelse:somewhere.org","membership":"join"},"origin_server_ts":1633108629915,"sender":"@someone:somewhere.org","state_key":"@someone:somewhere.org","type":"m.room.member","unsigned":{"age":539338},"room_id":"!someroom:matrix.org"}`)
	expectedv8 := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{"membership":"join"},"type":"m.room.member","state_key":"@someone:somewhere.org","origin_server_ts":1633108629915}`))
	expectedv9 := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{"membership":"join","join_authorised_via_users_server":"@someoneelse:somewhere.org"},"type":"m.room.member","state_key":"@someone:somewhere.org","origin_server_ts":1633108629915}`))

	redactedv8, err := MustGetRoomVersion(RoomVersionV8).RedactEventJSON(input)
	if err != nil {
		t.Fatal(err)
	}

	redactedv9, err := MustGetRoomVersion(RoomVersionV9).RedactEventJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	redactedv8 = CanonicalJSONAssumeValid(redactedv8)
	redactedv9 = CanonicalJSONAssumeValid(redactedv9)

	if !bytes.Equal(redactedv8, expectedv8) {
		t.Fatalf("room version 8 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv8), string(redactedv8))
	}

	if !bytes.Equal(redactedv9, expectedv9) {
		t.Fatalf("room version 9 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv9), string(redactedv9))
	}

	redactedv8withv9, err := MustGetRoomVersion(RoomVersionV9).RedactEventJSON(expectedv8)
	if err != nil {
		t.Fatal(err)
	}
	redactedv8withv9 = CanonicalJSONAssumeValid(redactedv8withv9)
	if !bytes.Equal(redactedv8withv9, expectedv8) {
		t.Fatalf("room version 8 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv8), string(redactedv8withv9))
	}
}

func TestRedactionAlgorithmV5(t *testing.T) {
	// Specifically, the version 5 redaction algorithm used in room
	// version 11 is ensuring that:
	//   - `m.room.create` keeps all `content` fields
	//   - `m.room.redaction` keeps `redacts` `content` field
	//   - `m.room.power_levels` keeps `invite` `content` field
	//   - top level `origin`, `membership`, and `prev_state` aren't protected from redaction

	input := []byte(`{"content":{"placeholder":"value"},"origin_server_ts":1633108629915,"sender":"@someone:somewhere.org","state_key":"@someone:somewhere.org","type":"m.room.create","unsigned":{"age":539338},"room_id":"!someroom:matrix.org","origin":"matrix.org","membership":"join","prev_state":""}`)
	expectedv10 := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{},"type":"m.room.create","state_key":"@someone:somewhere.org","prev_state":"","origin":"matrix.org","origin_server_ts":1633108629915,"membership":"join"}`))
	expectedv11 := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{"placeholder":"value"},"type":"m.room.create","state_key":"@someone:somewhere.org","origin_server_ts":1633108629915}`))
	expectedv10withv11 := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{},"type":"m.room.create","state_key":"@someone:somewhere.org","origin_server_ts":1633108629915}`))

	redactedv10, err := MustGetRoomVersion(RoomVersionV10).RedactEventJSON(input)
	if err != nil {
		t.Fatal(err)
	}

	redactedv11, err := MustGetRoomVersion(RoomVersionV11).RedactEventJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	redactedv10 = CanonicalJSONAssumeValid(redactedv10)
	redactedv11 = CanonicalJSONAssumeValid(redactedv11)

	if !bytes.Equal(redactedv10, expectedv10) {
		t.Fatalf("room version 10 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv10), string(redactedv10))
	}

	if !bytes.Equal(redactedv11, expectedv11) {
		t.Fatalf("room version 11 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv11), string(redactedv11))
	}

	redactedv10withv11, err := MustGetRoomVersion(RoomVersionV11).RedactEventJSON(expectedv10)
	if err != nil {
		t.Fatal(err)
	}
	redactedv10withv11 = CanonicalJSONAssumeValid(redactedv10withv11)
	if !bytes.Equal(redactedv10withv11, expectedv10withv11) {
		t.Fatalf("room version 11 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv10withv11), string(redactedv10withv11))
	}

	powerLevelsInput := []byte(`{"content":{"invite":"","placeholder":"value"},"origin_server_ts":1633108629915,"sender":"@someone:somewhere.org","state_key":"@someone:somewhere.org","type":"m.room.power_levels","unsigned":{"age":539338},"room_id":"!someroom:matrix.org","origin":"matrix.org","membership":"join","prev_state":""}`)
	expectedv11PLs := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{"invite":""},"type":"m.room.power_levels","state_key":"@someone:somewhere.org","origin_server_ts":1633108629915}`))

	redactedv11PLs, err := MustGetRoomVersion(RoomVersionV11).RedactEventJSON(powerLevelsInput)
	if err != nil {
		t.Fatal(err)
	}
	redactedv11PLs = CanonicalJSONAssumeValid(redactedv11PLs)
	if !bytes.Equal(redactedv11PLs, expectedv11PLs) {
		t.Fatalf("room version 11 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv11PLs), string(redactedv11PLs))
	}

	readactionInput := []byte(`{"content":{"redacts":"","placeholder":"value"},"origin_server_ts":1633108629915,"sender":"@someone:somewhere.org","state_key":"@someone:somewhere.org","type":"m.room.redaction","unsigned":{"age":539338},"room_id":"!someroom:matrix.org","origin":"matrix.org","membership":"join","prev_state":""}`)
	expectedv11Redaction := CanonicalJSONAssumeValid([]byte(`{"sender":"@someone:somewhere.org","room_id":"!someroom:matrix.org","content":{"redacts":""},"type":"m.room.redaction","state_key":"@someone:somewhere.org","origin_server_ts":1633108629915}`))

	redactedv11Redaction, err := MustGetRoomVersion(RoomVersionV11).RedactEventJSON(readactionInput)
	if err != nil {
		t.Fatal(err)
	}
	redactedv11Redaction = CanonicalJSONAssumeValid(redactedv11Redaction)
	if !bytes.Equal(redactedv11Redaction, expectedv11Redaction) {
		t.Fatalf("room version 11 redaction produced unexpected result\nexpected: %s\ngot: %s", string(expectedv11Redaction), string(redactedv11Redaction))
	}
}
