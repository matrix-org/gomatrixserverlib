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
	RoomID        spec.RoomID
	RoomVersion   RoomVersion
	InvitedUser   spec.UserID
	InviteEvent   PDU
	StrippedState []InviteStrippedState

	KeyID      KeyID
	PrivateKey ed25519.PrivateKey
	Verifier   JSONVerifier

	InviteQuerier     RoomQuerier
	MembershipQuerier MembershipQuerier
	StateQuerier      StateQuerier
}

func HandleInvite(ctx context.Context, input HandleInviteInput) (PDU, error) {
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
		ServerName:             sender.Domain(),
		Message:                redacted,
		AtTS:                   input.InviteEvent.OriginServerTS(),
		StrictValidityChecking: true,
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

	if signedEvent.StateKey() == nil {
		util.GetLogger(ctx).Error("invite must be a state event")
		return nil, spec.BadJSON("The state key must be populated")
	}

	isKnownRoom, err := input.InviteQuerier.IsKnownRoom(ctx, input.RoomID)
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
