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
	RoomID        spec.RoomID
	InvitedUser   spec.UserID
	IsTargetLocal bool
	Event         PDU
	StrippedState []InviteStrippedState

	MembershipQuerier MembershipQuerier
	StateQuerier      StateQuerier
}

func PerformInvite(ctx context.Context, input PerformInviteInput, fedClient FederatedInviteClient) (PDU, error) {
	logger := createInviteLogger(ctx, input.Event, input.RoomID)
	logger.WithFields(logrus.Fields{
		"room_version": input.Event.Version(),
		"target_local": input.IsTargetLocal,
		"origin_local": true,
	}).Debug("processing invite event")

	inviteState := input.StrippedState
	if len(inviteState) == 0 {
		var err error
		inviteState, err = GenerateStrippedState(ctx, input.RoomID, input.Event, input.StateQuerier)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("failed generating stripped state")
			return nil, spec.InternalServerError{}
		}
	}

	err := abortIfAlreadyJoined(ctx, input.RoomID, input.InvitedUser, input.MembershipQuerier)
	if err != nil {
		return nil, err
	}

	err = setUnsignedFieldForInvite(input.Event, inviteState)
	if err != nil {
		return nil, err
	}

	// The invite originated locally. Therefore we have a responsibility to
	// try and see if the user is allowed to make this invite. We can't do
	// this for invites coming in over federation - we have to take those on
	// trust.
	authEventProvider, err := input.StateQuerier.GetAuthEvents(ctx, input.Event)
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
		inviteEvent, err = fedClient.SendInvite(ctx, input.Event, inviteState)
		if err != nil {
			logger.WithError(err).WithField("event_id", input.Event.EventID()).Error("fedClient.SendInvite failed")
			return nil, spec.Forbidden(err.Error())
		}
		logger.Debugf("Federated SendInvite success with event ID %s", input.Event.EventID())
	}

	return inviteEvent, nil
}
