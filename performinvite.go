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

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"
)

type PerformInviteInput struct {
	RoomID          spec.RoomID           // The room the user is being invited to join
	InvitedUser     spec.UserID           // The user being invited join the room
	InvitedSenderID spec.SenderID         // The senderID of the user being invited to join the room
	IsTargetLocal   bool                  // Whether the user being invited is local to this server
	InviteEvent     PDU                   // The original invite event
	StrippedState   []InviteStrippedState // A small set of state events that can be used to identify the room

	MembershipQuerier MembershipQuerier    // Provides information about the room's membership
	StateQuerier      StateQuerier         // Provides access to state events
	UserIDQuerier     spec.UserIDForSender // Provides userID for a given senderID
}

// PerformInvite - Performs all the checks required to validate the invite is allowed
// to happen.
// On success will return either nothing (in the case of inviting a local user) or
// a fully formed & signed Invite Event (in the case of inviting a remote user)
func PerformInvite(ctx context.Context, input PerformInviteInput, fedClient FederatedInviteClient) (PDU, error) {
	if input.MembershipQuerier == nil || input.StateQuerier == nil || input.UserIDQuerier == nil {
		panic("Missing valid Querier")
	}
	if ctx == nil {
		panic("Missing valid Context")
	}

	logger := createInviteLogger(ctx, input.InviteEvent, input.RoomID)
	logger.WithFields(logrus.Fields{
		"room_version": input.InviteEvent.Version(),
		"target_local": input.IsTargetLocal,
		"origin_local": true,
	}).Debug("processing invite event")

	inviteState := input.StrippedState
	if len(inviteState) == 0 {
		var err error
		inviteState, err = GenerateStrippedState(ctx, input.RoomID, input.InviteEvent, input.StateQuerier)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("failed generating stripped state")
			return nil, spec.InternalServerError{}
		}
	}

	err := abortIfAlreadyJoined(ctx, input.RoomID, input.InvitedSenderID, input.MembershipQuerier)
	if err != nil {
		return nil, err
	}

	err = setUnsignedFieldForInvite(input.InviteEvent, inviteState)
	if err != nil {
		return nil, err
	}

	// The invite originated locally. Therefore we have a responsibility to
	// try and see if the user is allowed to make this invite. We can't do
	// this for invites coming in over federation - we have to take those on
	// trust.
	authEventProvider, err := input.StateQuerier.GetAuthEvents(ctx, input.InviteEvent)
	if err != nil {
		logger.WithError(err).WithField("event_id", input.InviteEvent.EventID()).WithField("auth_event_ids", input.InviteEvent.AuthEventIDs()).Error(
			"ProcessInvite.getAuthEvents failed for event",
		)
		return nil, spec.Forbidden(err.Error())
	}

	// Check if the event is allowed.
	if err = Allowed(input.InviteEvent, authEventProvider, input.UserIDQuerier); err != nil {
		logger.WithError(err).WithField("event_id", input.InviteEvent.EventID()).WithField("auth_event_ids", input.InviteEvent.AuthEventIDs()).Error(
			"ProcessInvite: event not allowed",
		)
		return nil, spec.Forbidden(err.Error())
	}

	// If the target isn't local then we should send the invite
	// over federation. It might be that the remote user doesn't exist,
	// in which case we can give up processing here.
	var signedEvent PDU
	if !input.IsTargetLocal {
		signedEvent, err = fedClient.SendInvite(ctx, input.InviteEvent, inviteState)
		if err != nil {
			logger.WithError(err).WithField("event_id", input.InviteEvent.EventID()).Error("fedClient.SendInvite failed")
			return nil, spec.Forbidden(err.Error())
		}
		logger.Debugf("Federated SendInvite success with event ID %s", input.InviteEvent.EventID())
	}

	return signedEvent, nil
}
