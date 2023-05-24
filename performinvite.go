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
)

type StateQuerier interface {
	GetAuthEvents(ctx context.Context, event PDU) (AuthEventProvider, error)
}

type PerformInviteInput struct {
	Context               context.Context
	RoomID                spec.RoomID
	Event                 PDU
	InvitedUser           spec.UserID
	IsTargetLocal         bool
	StrippedState         []InviteStrippedState
	MembershipQuerier     MembershipQuerier
	StateQuerier          StateQuerier
	GenerateStrippedState func(ctx context.Context, roomID spec.RoomID, stateWanted []StateKeyTuple, inviteEvent PDU) ([]InviteStrippedState, error)
}

type FederatedInviteClient interface {
	SendInvite(ctx context.Context, event PDU, strippedState []InviteStrippedState) (PDU, error)
}

func PerformInvite(input PerformInviteInput, fedClient FederatedInviteClient) (PDU, error) {
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
		if is, generateErr := input.GenerateStrippedState(input.Context, input.RoomID, stateWanted, input.Event); generateErr == nil {
			inviteState = is
		} else {
			util.GetLogger(input.Context).WithError(generateErr).Error("failed querying known room")
			return nil, spec.InternalServerError{}
		}
	}

	logger := util.GetLogger(input.Context).WithFields(map[string]interface{}{
		"inviter":  input.Event.Sender(),
		"invitee":  *input.Event.StateKey(),
		"room_id":  input.RoomID.String(),
		"event_id": input.Event.EventID(),
	})
	logger.WithFields(logrus.Fields{
		"room_version": input.Event.Version(),
		"target_local": input.IsTargetLocal,
		"origin_local": true,
	}).Debug("processing invite event")

	if len(inviteState) == 0 {
		if err := input.Event.SetUnsignedField("invite_room_state", struct{}{}); err != nil {
			return nil, fmt.Errorf("event.SetUnsignedField: %w", err)
		}
	} else {
		if err := input.Event.SetUnsignedField("invite_room_state", inviteState); err != nil {
			return nil, fmt.Errorf("event.SetUnsignedField: %w", err)
		}
	}

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
		return nil, spec.Forbidden("user is already joined to room")
	}

	// The invite originated locally. Therefore we have a responsibility to
	// try and see if the user is allowed to make this invite. We can't do
	// this for invites coming in over federation - we have to take those on
	// trust.
	authEventProvider, err := input.StateQuerier.GetAuthEvents(input.Context, input.Event)
	if err != nil {
		logger.WithError(err).WithField("event_id", input.Event.EventID()).WithField("auth_event_ids", input.Event.AuthEventIDs()).Error(
			"ProcessInvite.getAuthEvents failed for event",
		)
		return nil, spec.Forbidden(err.Error())
	}

	// Check if the event is allowed.
	if err = Allowed(input.Event, authEventProvider); err != nil {
		logger.WithError(err).WithField("event_id", input.Event.EventID()).WithField("auth_event_ids", input.Event.AuthEventIDs()).Error(
			"ProcessInvite: event not allowed",
		)
		return nil, spec.Forbidden(err.Error())
	}

	// If the target isn't local then we should try and send the invite
	// over federation first. It might be that the remote user doesn't exist,
	// in which case we can give up processing here.
	var inviteEvent PDU
	if !input.IsTargetLocal {
		inviteEvent, err = fedClient.SendInvite(input.Context, input.Event, inviteState)
		if err != nil {
			logger.WithError(err).WithField("event_id", input.Event.EventID()).Error("fedClient.SendInvite failed")
			return nil, spec.Forbidden(err.Error())
		}
		logger.Debugf("Federated SendInvite success with event ID %s", input.Event.EventID())
	}

	return inviteEvent, nil
}
