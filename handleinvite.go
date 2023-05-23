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
	"encoding/json"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
)

// InviteStrippedState is a cut-down set of fields from room state
// events that allow the invited server to identify the room.
type InviteStrippedState struct {
	fields struct {
		Content  spec.RawJSON `json:"content"`
		StateKey *string      `json:"state_key"`
		Type     string       `json:"type"`
		Sender   string       `json:"sender"`
	}
}

// NewInviteStrippedState creates a stripped state event from a
// regular state event.
func NewInviteStrippedState(event PDU) (ss InviteStrippedState) {
	ss.fields.Content = event.Content()
	ss.fields.StateKey = event.StateKey()
	ss.fields.Type = event.Type()
	ss.fields.Sender = event.Sender()
	return
}

// MarshalJSON implements json.Marshaller
func (i InviteStrippedState) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteStrippedState) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &i.fields)
}

// Content returns the content of the stripped state.
func (i *InviteStrippedState) Content() spec.RawJSON {
	return i.fields.Content
}

// StateKey returns the state key of the stripped state.
func (i *InviteStrippedState) StateKey() *string {
	return i.fields.StateKey
}

// Type returns the type of the stripped state.
func (i *InviteStrippedState) Type() string {
	return i.fields.Type
}

// Sender returns the sender of the stripped state.
func (i *InviteStrippedState) Sender() string {
	return i.fields.Sender
}

type RoomQuerier interface {
	IsKnownRoom(ctx context.Context, roomID spec.RoomID) (bool, error)
}

type HandleInviteInput struct {
	Context               context.Context
	RoomVersion           RoomVersion
	RoomID                spec.RoomID
	EventID               string
	InvitedUser           spec.UserID
	KeyID                 KeyID
	PrivateKey            ed25519.PrivateKey
	Verifier              JSONVerifier
	InviteQuerier         RoomQuerier
	MembershipQuerier     MembershipQuerier
	GenerateStrippedState func(ctx context.Context, roomID spec.RoomID, stateWanted []StateKeyTuple, inviteEvent PDU) ([]InviteStrippedState, error)

	InviteEvent   PDU
	StrippedState []InviteStrippedState
}

func HandleInvite(input HandleInviteInput) (PDU, error) {
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

	// Check that the event ID is correct.
	if input.InviteEvent.EventID() != input.EventID {
		return nil, spec.BadJSON("The event ID in the request path must match the event ID in the invite event JSON")
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
	verifyResults, err := input.Verifier.VerifyJSONs(input.Context, verifyRequests)
	if err != nil {
		util.GetLogger(input.Context).WithError(err).Error("keys.VerifyJSONs failed")
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
		util.GetLogger(input.Context).Error("invite must be a state event")
		return nil, spec.InternalServerError{}
	}

	isKnownRoom, err := input.InviteQuerier.IsKnownRoom(input.Context, input.RoomID)
	if err != nil {
		util.GetLogger(input.Context).WithError(err).Error("failed querying known room")
		return nil, spec.InternalServerError{}
	}

	inviteState := input.StrippedState
	if len(inviteState) == 0 {
		// "If they are set on the room, at least the state for m.room.avatar, m.room.canonical_alias, m.room.join_rules, and m.room.name SHOULD be included."
		// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-member
		stateWanted := []StateKeyTuple{}
		for _, t := range []string{
			spec.MRoomName, spec.MRoomCanonicalAlias,
			spec.MRoomJoinRules, spec.MRoomAvatar,
			spec.MRoomEncryption, spec.MRoomCreate,
		} {
			stateWanted = append(stateWanted, StateKeyTuple{
				EventType: t,
				StateKey:  "",
			})
		}
		if is, err := input.GenerateStrippedState(input.Context, input.RoomID, stateWanted, signedEvent); err == nil {
			inviteState = is
		} else {
			util.GetLogger(input.Context).WithError(err).Error("failed querying known room")
			return nil, spec.InternalServerError{}
		}
	}

	logger := util.GetLogger(input.Context).WithFields(map[string]interface{}{
		"inviter":  signedEvent.Sender(),
		"invitee":  *signedEvent.StateKey(),
		"room_id":  input.RoomID.String(),
		"event_id": signedEvent.EventID(),
	})
	logger.WithFields(logrus.Fields{
		"room_version":     signedEvent.Version(),
		"room_info_exists": isKnownRoom,
	}).Debug("processing incoming federation invite event")

	if len(inviteState) == 0 {
		if err = signedEvent.SetUnsignedField("invite_room_state", struct{}{}); err != nil {
			util.GetLogger(input.Context).WithError(err).Error("failed setting unsigned field")
			return nil, spec.InternalServerError{}
		}
	} else {
		if err = signedEvent.SetUnsignedField("invite_room_state", inviteState); err != nil {
			util.GetLogger(input.Context).WithError(err).Error("failed setting unsigned field")
			return nil, spec.InternalServerError{}
		}
	}

	if isKnownRoom {
		membership, err := input.MembershipQuerier.CurrentMembership(input.Context, input.RoomID, input.InvitedUser)
		if err != nil {
			util.GetLogger(input.Context).WithError(err).Error("failed getting user membership")
			return nil, spec.InternalServerError{}

		}
		isAlreadyJoined := (membership == spec.Join)

		if isAlreadyJoined {
			// If the user is joined to the room then that takes precedence over this
			// invite event. It makes little sense to move a user that is already
			// joined to the room into the invite state.
			// This could plausibly happen if an invite request raced with a join
			// request for a user. For example if a user was invited to a public
			// room and they joined the room at the same time as the invite was sent.
			// The other way this could plausibly happen is if an invite raced with
			// a kick. For example if a user was kicked from a room in error and in
			// response someone else in the room re-invited them then it is possible
			// for the invite request to race with the leave event so that the
			// target receives invite before it learns that it has been kicked.
			// There are a few ways this could be plausibly handled in the roomserver.
			// 1) Store the invite, but mark it as retired. That will result in the
			//    permanent rejection of that invite event. So even if the target
			//    user leaves the room and the invite is retransmitted it will be
			//    ignored. However a new invite with a new event ID would still be
			//    accepted.
			// 2) Silently discard the invite event. This means that if the event
			//    was retransmitted at a later date after the target user had left
			//    the room we would accept the invite. However since we hadn't told
			//    the sending server that the invite had been discarded it would
			//    have no reason to attempt to retry.
			// 3) Signal the sending server that the user is already joined to the
			//    room.
			// For now we will implement option 2. Since in the abesence of a retry
			// mechanism it will be equivalent to option 1, and we don't have a
			// signalling mechanism to implement option 3.
			logger.Debugf("user already joined")
			util.GetLogger(input.Context).Error("user is already joined to room")
			return nil, spec.InternalServerError{}
		}
	}

	return signedEvent, nil
}
