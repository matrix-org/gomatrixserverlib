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
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
)

type HandleInviteInput struct {
	RoomID        spec.RoomID           // The room that the user is being invited to join
	RoomVersion   RoomVersion           // The version of the invited to room
	InvitedUser   spec.UserID           // The user being invited to join the room
	InviteEvent   PDU                   // The original invite event
	StrippedState []InviteStrippedState // A small set of state events that can be used to identify the room

	KeyID      KeyID              // Used to sign the original invite event
	PrivateKey ed25519.PrivateKey // Used to sign the original invite event
	Verifier   JSONVerifier       // Used to verify the original invite event

	RoomQuerier       RoomQuerier       // Provides information about the room
	MembershipQuerier MembershipQuerier // Provides information about the room's membership
	StateQuerier      StateQuerier      // Provides access to state events
}

// HandleInvite - Ensures the incoming invite request is valid and signs the event
// to return back to the remote server.
// On success returns a fully formed & signed Invite Event
func HandleInvite(ctx context.Context, input HandleInviteInput) (PDU, error) {
	if input.RoomQuerier == nil || input.MembershipQuerier == nil || input.StateQuerier == nil {
		panic("Missing valid Querier")
	}
	if input.Verifier == nil {
		panic("Missing valid JSONVerifier")
	}

	if ctx == nil {
		panic("Missing valid Context")
	}

	// Check that we can accept invites for this room version.
	verImpl, err := GetRoomVersion(input.RoomVersion)
	if err != nil {
		return nil, spec.UnsupportedRoomVersion(
			fmt.Sprintf("Room version %q is not supported by this server.", input.RoomVersion),
		)
	}

	// Check that the room ID is correct.
	if input.InviteEvent.RoomID() != input.RoomID.String() {
		return nil, spec.BadJSON("The room ID in the request path must match the room ID in the invite event JSON")
	}

	// Check that the event is signed by the server sending the request.
	redacted, err := verImpl.RedactEventJSON(input.InviteEvent.JSON())
	if err != nil {
		return nil, spec.BadJSON("The event JSON could not be redacted")
	}

	sender, err := spec.NewUserID(input.InviteEvent.Sender(), true)
	if err != nil {
		return nil, spec.BadJSON("The event JSON contains an invalid sender")
	}
	verifyRequests := []VerifyJSONRequest{{
		ServerName:           sender.Domain(),
		Message:              redacted,
		AtTS:                 input.InviteEvent.OriginServerTS(),
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}}
	verifyResults, err := input.Verifier.VerifyJSONs(ctx, verifyRequests)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("keys.VerifyJSONs failed")
		return nil, spec.InternalServerError{}
	}
	if verifyResults[0].Error != nil {
		return nil, spec.Forbidden("The invite must be signed by the server it originated on")
	}

	// Sign the event so that other servers will know that we have received the invite.
	signedEvent := input.InviteEvent.Sign(
		string(input.InvitedUser.Domain()), input.KeyID, input.PrivateKey,
	)

	isKnownRoom, err := input.RoomQuerier.IsKnownRoom(ctx, input.RoomID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("failed querying known room")
		return nil, spec.InternalServerError{}
	}

	logger := createInviteLogger(ctx, signedEvent, input.RoomID)
	logger.WithFields(logrus.Fields{
		"room_version":     signedEvent.Version(),
		"room_info_exists": isKnownRoom,
	}).Debug("processing incoming federation invite event")

	inviteState := input.StrippedState
	if len(inviteState) == 0 {
		inviteState, err = GenerateStrippedState(ctx, input.RoomID, signedEvent, input.StateQuerier)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("failed generating stripped state")
			return nil, spec.InternalServerError{}
		}
	}

	if isKnownRoom {
		if len(inviteState) == 0 {
			util.GetLogger(ctx).WithError(err).Error("failed generating stripped state for known room")
			return nil, spec.InternalServerError{}
		}
		err := abortIfAlreadyJoined(ctx, input.RoomID, input.InvitedUser, input.MembershipQuerier)
		if err != nil {
			return nil, err
		}
	}

	err = setUnsignedFieldForInvite(signedEvent, inviteState)
	if err != nil {
		return nil, err
	}

	return signedEvent, nil
}
