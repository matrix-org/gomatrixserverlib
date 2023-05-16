package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
)

type HandleMakeJoinInput struct {
	Context           context.Context
	UserID            spec.UserID               // The user wanting to join the room
	RoomID            spec.RoomID               // The room the user wants to join
	RoomVersion       RoomVersion               // The room version for the room being joined
	RemoteVersions    []RoomVersion             // Room versions supported by the remote server
	RequestOrigin     spec.ServerName           // The server that sent the /make_join federation request
	LocalServerName   spec.ServerName           // The name of this local server
	LocalServerInRoom bool                      // Whether this local server has a user currently joined to the room
	RoomQuerier       RestrictedRoomJoinQuerier // Provides access to potentially required information when processing restricted joins

	// Returns a fully built version of the proto event and a list of state events required to auth this event
	BuildEventTemplate func(*ProtoEvent) (PDU, []PDU, error)
}

type HandleMakeJoinResponse struct {
	JoinTemplateEvent ProtoEvent
	RoomVersion       RoomVersion
}

func HandleMakeJoin(input HandleMakeJoinInput) (*HandleMakeJoinResponse, error) {
	if input.RoomQuerier == nil {
		panic("Missing valid RoomQuerier")
	}

	if input.Context == nil {
		panic("Missing valid Context")
	}

	// Check that the room that the remote side is trying to join is actually
	// one of the room versions that they listed in their supported ?ver= in
	// the make_join URL.
	// https://matrix.org/docs/spec/server_server/r0.1.3#get-matrix-federation-v1-make-join-roomid-userid
	// If it isn't, stop trying to join the room.
	if !roomVersionSupported(input.RoomVersion, input.RemoteVersions) {
		return nil, spec.IncompatibleRoomVersion(string(input.RoomVersion))
	}

	if input.UserID.Domain() != input.RequestOrigin {
		return nil, spec.Forbidden(fmt.Sprintf("The join must be sent by the server of the user. Origin %s != %s",
			input.RequestOrigin, input.UserID.Domain()))
	}

	// Check if we think we are still joined to the room
	if !input.LocalServerInRoom {
		return nil, spec.NotFound(fmt.Sprintf("Local server not currently joined to room: %s", input.RoomID.String()))
	}

	// Check if the restricted join is allowed. If the room doesn't
	// support restricted joins then this is effectively a no-op.
	authorisedVia, err := checkRestrictedJoin(input.Context, input.LocalServerName, input.RoomQuerier, input.RoomVersion, input.RoomID, input.UserID)
	switch e := err.(type) {
	case nil:
	case spec.MatrixError:
		util.GetLogger(input.Context).WithError(err).Error("checkRestrictedJoin failed")
		return nil, e
	default:
		return nil, spec.InternalServerError{Err: "checkRestrictedJoin failed"}
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
		Membership:    spec.Join,
		AuthorisedVia: authorisedVia,
	}
	if err = proto.SetContent(content); err != nil {
		return nil, spec.InternalServerError{Err: "builder.SetContent failed"}
	}

	event, state, templateErr := input.BuildEventTemplate(&proto)
	if templateErr != nil {
		return nil, templateErr
	}
	if event == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event"}
	}
	if state == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event state"}
	}
	if event.Type() != spec.MRoomMember {
		return nil, spec.InternalServerError{Err: fmt.Sprintf("expected join event from template builder. got: %s", event.Type())}
	}

	provider := NewAuthEvents(state)
	if err = Allowed(event, &provider); err != nil {
		return nil, spec.Forbidden(err.Error())
	}

	makeJoinResponse := HandleMakeJoinResponse{
		JoinTemplateEvent: proto,
		RoomVersion:       input.RoomVersion,
	}
	return &makeJoinResponse, nil
}

func roomVersionSupported(roomVersion RoomVersion, supportedVersions []RoomVersion) bool {
	remoteSupportsVersion := false
	for _, v := range supportedVersions {
		if v == roomVersion {
			remoteSupportsVersion = true
			break
		}
	}

	return remoteSupportsVersion
}

// checkRestrictedJoin finds out whether or not we can assist in processing
// a restricted room join. If the room version does not support restricted
// joins then this function returns with no side effects. This returns:
//   - a user ID of an authorising user, typically a user that has power to
//     issue invites in the room, if one has been found
//   - an error if there was a problem finding out if this was allowable,
//     like if the room version isn't known or a problem happened talking to
//     the roomserver
func checkRestrictedJoin(
	ctx context.Context,
	localServerName spec.ServerName,
	roomQuerier RestrictedRoomJoinQuerier,
	roomVersion RoomVersion,
	roomID spec.RoomID, userID spec.UserID,
) (string, error) {
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return "", err
	}
	if !verImpl.MayAllowRestrictedJoinsInEventAuth() {
		return "", nil
	}

	// If the room version doesn't allow restricted joins then don't
	// try to process any further.
	allowRestrictedJoins := verImpl.MayAllowRestrictedJoinsInEventAuth()
	if !allowRestrictedJoins {
		// The join rules for the room don't restrict membership.
		return "", nil
	}

	// Get the join rules to work out if the join rule is "restricted".
	joinRulesEvent, err := roomQuerier.CurrentStateEvent(ctx, roomID, spec.MRoomJoinRules, "")
	if err != nil {
		return "", fmt.Errorf("roomQuerier.StateEvent: %w", err)
	}
	if joinRulesEvent == nil {
		// The join rules for the room don't restrict membership.
		return "", nil
	}
	var joinRules JoinRuleContent
	if err = json.Unmarshal(joinRulesEvent.Content(), &joinRules); err != nil {
		return "", fmt.Errorf("json.Unmarshal: %w", err)
	}

	// If the join rule isn't "restricted" or "knock_restricted" then there's nothing more to do.
	restricted := joinRules.JoinRule == spec.Restricted || joinRules.JoinRule == spec.KnockRestricted
	if !restricted {
		// The join rules for the room don't restrict membership.
		return "", nil
	}

	// If the user is already invited to the room then the join is allowed
	// but we don't specify an authorised via user, since the event auth
	// will allow the join anyway.
	if pending, err := roomQuerier.InvitePending(ctx, roomID, userID); err != nil {
		return "", fmt.Errorf("helpers.IsInvitePending: %w", err)
	} else if pending {
		// The join rules for the room don't restrict membership.
		return "", nil
	}

	// We need to get the power levels content so that we can determine which
	// users in the room are entitled to issue invites. We need to use one of
	// these users as the authorising user.
	powerLevelsEvent, err := roomQuerier.CurrentStateEvent(ctx, roomID, spec.MRoomPowerLevels, "")
	if err != nil {
		return "", fmt.Errorf("roomQuerier.StateEvent: %w", err)
	}
	if powerLevelsEvent == nil {
		return "", fmt.Errorf("invalid power levels event")
	}
	powerLevels, err := powerLevelsEvent.PowerLevels()
	if err != nil {
		return "", fmt.Errorf("unable to get powerlevels: %w", err)
	}

	resident := true
	// Step through the join rules and see if the user matches any of them.
	for _, rule := range joinRules.Allow {
		// We only understand "m.room_membership" rules at this point in
		// time, so skip any rule that doesn't match those.
		if rule.Type != spec.MRoomMembership {
			continue
		}

		// See if the room exists. If it doesn't exist or if it's a stub
		// room entry then we can't check memberships.
		roomID, err := spec.NewRoomID(rule.RoomID)
		if err != nil {
			continue
		}

		// First of all work out if *we* are still in the room, otherwise
		// it's possible that the memberships will be out of date.
		targetRoomInfo, err := roomQuerier.RestrictedRoomJoinInfo(ctx, *roomID, userID, localServerName)
		if err != nil || targetRoomInfo == nil || !targetRoomInfo.LocalServerInRoom {
			// If we aren't in the room, we can no longer tell if the room
			// memberships are up-to-date.
			resident = false
			continue
		}

		// At this point we're happy that we are in the room, so now let's
		// see if the target user is in the room.
		// If the user is not in the room then we will skip this rule.
		if !targetRoomInfo.UserJoinedToRoom {
			continue
		}

		// The user is in the room, so now we will need to authorise the
		// join using the user ID of one of our own users in the room. Pick
		// one.
		if err != nil || len(targetRoomInfo.JoinedUsers) == 0 {
			// There should always be more than one join event at this point
			// because we are gated behind GetLocalServerInRoom, but y'know,
			// sometimes strange things happen.
			continue
		}

		// For each of the joined users, let's see if we can get a valid
		// membership event.
		for _, user := range targetRoomInfo.JoinedUsers {
			if user.Type() != spec.MRoomMember || user.StateKey() == nil {
				continue // shouldn't happen
			}
			// Only users that have the power to invite should be chosen.
			if powerLevels.UserLevel(*user.StateKey()) < powerLevels.Invite {
				continue
			}

			// The join rules restrict membership, our server is in the relevant
			// rooms and the user was allowed to join because they belong to one
			// of the allowed rooms. Return one of our own local users
			// from within the room to use as the authorising user ID, so that it
			// can be referred to from within the membership content.
			return *user.StateKey(), nil
		}
	}

	if !resident {
		// The join rules restrict membership but our server isn't currently
		// joined to all of the allowed rooms, so we can't actually decide
		// whether or not to allow the user to join. This error code should
		// tell the joining server to try joining via another resident server
		// instead.
		return "", spec.UnableToAuthoriseJoin("This server cannot authorise the join.")
	}

	// The join rules restrict membership, our server is in the relevant
	// rooms and the user wasn't joined to join any of the allowed rooms
	// and therefore can't join this room.
	return "", spec.Forbidden("You are not joined to any matching rooms.")
}
