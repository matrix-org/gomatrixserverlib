package fclient

import (
	"encoding/json"
	"testing"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
)

func TestMarshalInviteV3Request(t *testing.T) {
	expected := `{"room_version":"org.matrix.msc4014","invite_room_state":[],"event":{"sender":"@test:localhost","room_id":"!19Mp0U9hjajeIiw1:localhost","type":"m.room.name","state_key":"","prev_events":["upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"],"auth_events":["abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY","X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko","k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"],"depth":7,"signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"content":{"name":"test3"}}}`

	senderID := "@test:localhost"
	roomID := "!19Mp0U9hjajeIiw1:localhost"
	eventType := "m.room.name"
	stateKey := ""
	prevEvents := []string{"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}
	authEvents := []string{"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY", "X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko", "k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}
	depth := int64(7)
	signatures := spec.RawJSON(`{"localhost": {"ed25519:u9kP": "5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}}`)
	content := spec.RawJSON(`{"name":"test3"}`)

	output := gomatrixserverlib.ProtoEvent{
		SenderID:   senderID,
		RoomID:     roomID,
		Type:       eventType,
		StateKey:   &stateKey,
		PrevEvents: prevEvents,
		AuthEvents: authEvents,
		Depth:      depth,
		Signature:  signatures,
		Content:    content,
	}

	inviteReq, err := NewInviteV3Request(output, gomatrixserverlib.RoomVersionPseudoIDs, []gomatrixserverlib.InviteStrippedState{})
	if err != nil {
		t.Fatal(err)
	}

	j, err := json.Marshal(inviteReq)
	if err != nil {
		t.Fatal(err)
	}

	if string(j) != expected {
		t.Fatalf("\nresult: %q\nwanted: %q", string(j), expected)
	}

	var newRequest InviteV3Request
	err = json.Unmarshal(j, &newRequest)
	if err != nil {
		t.Fatal(err)
	}

	if newRequest.RoomVersion() != gomatrixserverlib.RoomVersionPseudoIDs {
		t.Fatalf("unmatched room version. expected: %v, got: %v", gomatrixserverlib.RoomVersionPseudoIDs, newRequest.RoomVersion())
	}
	if len(newRequest.InviteRoomState()) != 0 {
		t.Fatalf("invite room state should not have any events")
	}
	if newRequest.Event().SenderID != senderID {
		t.Fatalf("unmatched senderID. expected: %v, got: %v", newRequest.Event().SenderID, senderID)

	}
	if newRequest.Event().RoomID != roomID {
		t.Fatalf("unmatched roomID. expected: %v, got: %v", newRequest.Event().RoomID, roomID)
	}
	if newRequest.Event().Type != eventType {
		t.Fatalf("unmatched type. expected: %v, got: %v", newRequest.Event().Type, eventType)

	}
	if *newRequest.Event().StateKey != stateKey {
		t.Fatalf("unmatched state key. expected: %v, got: %v", *newRequest.Event().StateKey, stateKey)
	}
	if newRequest.Event().Depth != depth {
		t.Fatalf("unmatched depth. expected: %v, got: %v", newRequest.Event().Depth, depth)
	}
}
