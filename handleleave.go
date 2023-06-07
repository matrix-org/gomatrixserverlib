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
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

type HandleMakeLeaveResponse struct {
	LeaveTemplateEvent ProtoEvent
	RoomVersion        RoomVersion
}

type HandleMakeLeaveInput struct {
	UserID            spec.UserID          // The user wanting to leave the room
	SenderID          spec.SenderID        // The senderID of the user wanting to leave the room
	RoomID            spec.RoomID          // The room the user wants to leave
	RoomVersion       RoomVersion          // The room version for the room being left
	RequestOrigin     spec.ServerName      // The server that sent the /make_leave federation request
	LocalServerName   spec.ServerName      // The name of this local server
	LocalServerInRoom bool                 // Whether this local server has a user currently joined to the room
	UserIDQuerier     spec.UserIDForSender // Provides userIDs given a senderID

	// Returns a fully built version of the proto event and a list of state events required to auth this event
	BuildEventTemplate func(*ProtoEvent) (PDU, []PDU, error)
}

func HandleMakeLeave(input HandleMakeLeaveInput) (*HandleMakeLeaveResponse, error) {

	if input.UserID.Domain() != input.RequestOrigin {
		return nil, spec.Forbidden(fmt.Sprintf("The leave must be sent by the server of the user. Origin %s != %s",
			input.RequestOrigin, input.UserID.Domain()))
	}

	// Check if we think we are still joined to the room
	if !input.LocalServerInRoom {
		return nil, spec.NotFound(fmt.Sprintf("Local server not currently joined to room: %s", input.RoomID.String()))
	}

	// Try building an event for the server
	rawSenderID := string(input.SenderID)
	proto := ProtoEvent{
		SenderID: string(input.SenderID),
		RoomID:   input.RoomID.String(),
		Type:     spec.MRoomMember,
		StateKey: &rawSenderID,
	}
	content := MemberContent{
		Membership: spec.Leave,
	}

	if err := proto.SetContent(content); err != nil {
		return nil, spec.InternalServerError{Err: "builder.SetContent failed"}
	}

	event, stateEvents, templateErr := input.BuildEventTemplate(&proto)
	if templateErr != nil {
		return nil, templateErr
	}
	if event == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event"}
	}
	if stateEvents == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event state"}
	}
	if event.Type() != spec.MRoomMember {
		return nil, spec.InternalServerError{Err: fmt.Sprintf("expected leave event from template builder. got: %s", event.Type())}
	}

	provider := NewAuthEvents(stateEvents)
	if err := Allowed(event, &provider, input.UserIDQuerier); err != nil {
		return nil, spec.Forbidden(err.Error())
	}

	// This ensures we send EventReferences for room version v1 and v2. We need to do this, since we're
	// returning the proto event, which isn't modified when running `Build`.
	switch event.Version() {
	case RoomVersionV1, RoomVersionV2:
		proto.PrevEvents = toEventReference(event.PrevEventIDs())
		proto.AuthEvents = toEventReference(event.AuthEventIDs())
	}

	makeLeaveResponse := HandleMakeLeaveResponse{
		LeaveTemplateEvent: proto,
		RoomVersion:        input.RoomVersion,
	}
	return &makeLeaveResponse, nil
}
