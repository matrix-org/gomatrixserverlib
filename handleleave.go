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
	"context"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
)

type HandleMakeLeaveResponse struct {
	LeaveTemplateEvent ProtoEvent
	RoomVersion        RoomVersion
}

type HandleMakeLeaveInput struct {
	UserID            spec.UserID     // The user wanting to leave the room
	RoomID            spec.RoomID     // The room the user wants to leave
	RoomVersion       RoomVersion     // The room version for the room being left
	RequestOrigin     spec.ServerName // The server that sent the /make_leave federation request
	LocalServerName   spec.ServerName // The name of this local server
	LocalServerInRoom bool            // Whether this local server has a user currently joined to the room

	// Returns a fully built version of the proto event and a list of state events required to auth this event
	BuildEventTemplate func(*ProtoEvent) (PDU, []PDU, error)
}

// HandleMakeLeave handles requests to `/make_leave`
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
	rawUserID := input.UserID.String()
	proto := ProtoEvent{
		Sender:   input.UserID.String(),
		RoomID:   input.RoomID.String(),
		Type:     spec.MRoomMember,
		StateKey: &rawUserID,
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
	if err := Allowed(event, &provider); err != nil {
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

type CurrentStateQuerier interface {
	CurrentStateEvent(ctx context.Context, roomID spec.RoomID, eventType string, stateKey string) (PDU, error)
}

// HandleSendLeave handles requests to `/send_leave
// Returns the parsed event and an error.
func HandleSendLeave(ctx context.Context,
	requestContent []byte,
	origin spec.ServerName,
	roomVersion RoomVersion,
	eventID, roomID string,
	querier CurrentStateQuerier,
	verifier JSONVerifier,
) (PDU, error) {

	rID, err := spec.NewRoomID(roomID)
	if err != nil {
		return nil, err
	}

	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil, spec.UnsupportedRoomVersion(fmt.Sprintf("QueryRoomVersionForRoom returned unknown version: %s", roomVersion))
	}

	// Decode the event JSON from the request.
	event, err := verImpl.NewEventFromUntrustedJSON(requestContent)
	switch err.(type) {
	case BadJSONError:
		return nil, spec.BadJSON(err.Error())
	case nil:
	default:
		return nil, spec.NotJSON("The request body could not be decoded into valid JSON. " + err.Error())
	}

	// Check that the room ID is correct.
	if (event.RoomID()) != roomID {
		return nil, spec.BadJSON("The room ID in the request path must match the room ID in the leave event JSON")
	}

	// Check that the event ID is correct.
	if event.EventID() != eventID {
		return nil, spec.BadJSON("The event ID in the request path must match the event ID in the leave event JSON")

	}

	// Sanity check that we really received a state event
	if event.StateKey() == nil || event.StateKeyEquals("") {
		return nil, spec.BadJSON("No state key was provided in the leave event.")
	}
	if !event.StateKeyEquals(event.Sender()) {
		return nil, spec.BadJSON("Event state key must match the event sender.")
	}

	leavingUser, err := spec.NewUserID(*event.StateKey(), true)
	if err != nil {
		return nil, spec.Forbidden("The leaving user ID is invalid")
	}

	// Check that the sender belongs to the server that is sending us
	// the request. By this point we've already asserted that the sender
	// and the state key are equal so we don't need to check both.
	sender, err := spec.NewUserID(event.Sender(), true)
	if err != nil {
		return nil, spec.Forbidden("The sender of the join is invalid")
	}
	if sender.Domain() != origin {
		return nil, spec.Forbidden("The sender does not match the server that originated the request")
	}

	stateEvent, err := querier.CurrentStateEvent(ctx, *rID, spec.MRoomMember, leavingUser.String())
	if err != nil {
		return nil, err
	}
	// we weren't joined at all
	if stateEvent == nil {
		return nil, nil
	}
	// We are/were joined/invited/banned or something
	if mem, merr := stateEvent.Membership(); merr == nil && mem == spec.Leave {
		return nil, nil
	}
	// we already processed this event
	if event.EventID() == stateEvent.EventID() {
		return nil, nil
	}

	// Check that the event is signed by the server sending the request.
	redacted, err := verImpl.RedactEventJSON(event.JSON())
	if err != nil {
		util.GetLogger(ctx).WithError(err).Errorf("unable to redact event")
		return nil, spec.BadJSON("The event JSON could not be redacted")
	}
	verifyRequests := []VerifyJSONRequest{{
		ServerName:             sender.Domain(),
		Message:                redacted,
		AtTS:                   event.OriginServerTS(),
		StrictValidityChecking: true,
	}}
	verifyResults, err := verifier.VerifyJSONs(ctx, verifyRequests)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("keys.VerifyJSONs failed")
		return nil, spec.InternalServerError{}
	}
	if verifyResults[0].Error != nil {
		return nil, spec.Forbidden("The leave must be signed by the server it originated on")
	}

	// check membership is set to leave
	mem, err := event.Membership()
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("event.Membership failed")
		return nil, spec.BadJSON("missing content.membership key")
	}
	if mem != spec.Leave {
		return nil, spec.BadJSON("The membership in the event content must be set to leave")
	}

	return event, nil
}
