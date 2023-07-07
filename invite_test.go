// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

const TestInviteV2ExampleEvent = `{"_room_version":"1","auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`

func TestEmptyUnsignedFieldIsSetForPDU(t *testing.T) {
	output, err := NewEventFromHeaderedJSON([]byte(TestInviteV2ExampleEvent), false)
	if err != nil {
		t.Fatal(err)
	}

	inviteState := []InviteStrippedState{}

	err = setUnsignedFieldForInvite(output, inviteState)
	if err != nil {
		t.Fatal(err)
	}

	inviteStateJSON, err := json.Marshal(map[string]interface{}{"invite_room_state": struct{}{}})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output.Unsigned(), inviteStateJSON) {
		t.Fatalf("Expected: %v, Got: %v", string(inviteStateJSON[:]), string(output.Unsigned()[:]))
	}
}

func TestEmptyUnsignedFieldIsSetForProtoEvent(t *testing.T) {
	senderID := "@test:localhost"
	roomID := "!19Mp0U9hjajeIiw1:localhost"
	eventType := "m.room.name"
	stateKey := ""
	prevEvents := []string{"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}
	authEvents := []string{"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY", "X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko", "k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}
	depth := int64(7)
	signatures := spec.RawJSON(`{"localhost": {"ed25519:u9kP": "5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}}`)
	content := spec.RawJSON(`{"name":"test3"}`)

	output := ProtoEvent{
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

	inviteState := []InviteStrippedState{}

	err := setUnsignedFieldForProtoInvite(&output, inviteState)
	if err != nil {
		t.Fatal(err)
	}

	inviteStateJSON, err := json.Marshal(map[string]interface{}{"invite_room_state": struct{}{}})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output.Unsigned, inviteStateJSON) {
		t.Fatalf("Expected: %v, Got: %v", string(inviteStateJSON[:]), string(output.Unsigned[:]))
	}
}
