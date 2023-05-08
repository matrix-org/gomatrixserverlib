package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
)

// What should this do?

// Make Join:
// Validate room version is supported
// Only accept valid userID/roomID (check if nil?)
// Validate join was sent by user's server
// Validate our server is participating in the room
// Validate restricted room join info
// Build join event template
// Validate join is allowed
// Return join event template

// Send Join:
// Validate room version info
// Parse event
// Validate state key
// Validate sender belongs to sending server
// Validate room IDs match
// Validate Event:
// Validate event ID
// Validate this is a join event
// Validate signatures
// Validate state/auth for this user joining
// Validate authorised via
// sign the event
// process the event on our side
// return the final join event

// First:
// Move over `checkRestrictedJoin` in a commit
// This involves pulling over `QueryRestrictedJoinAllowed` logic from the roomserver
// Needs DB access for:
// - room info
// - getStateEvent
// - pending invite
// - local server in room
// - membership & events

// How does this help with power DAGs?
// What is the abstraction I need here?

// MakeJoin returns the join event template & room version
// MakeJoin powerDAG will be the same

// SendJoin returns the join event & state/auth events
// SendJoin powerDAG will return the join event & powerDAG events, possibly some state too
// Could return some form of interface thing that provides auth/power & state events on request
// What is a good name for auth/power?

// For now just create a HandleMakeJoin & HandleSendJoin in gmsl
// Return interfaces which provide common results
// Then in dendrite both the current join endpoints & the new powerDAG join endpoint can
// call through to the same gmsl functions.

// In GMSL, it can deal with properly handling the different logic based on room version.

// TODO: This is currently copied from clientapi... what do?
type MatrixError struct {
	ErrCode string `json:"errcode"`
	Err     string `json:"error"`
}

func (e MatrixError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func Forbidden(msg string) *MatrixError {
	return &MatrixError{"M_FORBIDDEN", msg}
}

func NotFound(msg string) *MatrixError {
	return &MatrixError{"M_NOT_FOUND", msg}
}

func InternalServerError() util.JSONResponse {
	return util.JSONResponse{
		Code: http.StatusInternalServerError,
		JSON: Unknown("Internal Server Error"),
	}
}

type IncompatibleRoomVersionError struct {
	RoomVersion string `json:"room_version"`
	Error       string `json:"error"`
	Code        string `json:"errcode"`
}

func IncompatibleRoomVersion(roomVersion RoomVersion) *IncompatibleRoomVersionError {
	return &IncompatibleRoomVersionError{
		Code:        "M_INCOMPATIBLE_ROOM_VERSION",
		RoomVersion: string(roomVersion),
		Error:       "Your homeserver does not support the features required to join this room",
	}
}

// UnableToAuthoriseJoin is an error that is returned when a server can't
// determine whether to allow a restricted join or not.
func UnableToAuthoriseJoin(msg string) *MatrixError {
	return &MatrixError{"M_UNABLE_TO_AUTHORISE_JOIN", msg}
}

// BadJSON is an error when the client supplies malformed JSON.
func BadJSON(msg string) *MatrixError {
	return &MatrixError{"M_BAD_JSON", msg}
}

// Unknown is an unexpected error
func Unknown(msg string) *MatrixError {
	return &MatrixError{"M_UNKNOWN", msg}
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

type HandleMakeJoinInput struct {
	Context            context.Context
	UserID             *spec.UserID
	RoomID             *spec.RoomID
	RoomVersion        RoomVersion
	RemoteVersions     []RoomVersion
	RequestOrigin      spec.ServerName
	RequestDestination spec.ServerName
	LocalServerName    spec.ServerName
	RoomQuerier        RoomQuerier
	BuildEventTemplate func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse)
}

type HandleMakeJoinResponse struct {
	JoinTemplateEvent ProtoEvent
	RoomVersion       RoomVersion
}

func HandleMakeJoin(input HandleMakeJoinInput) (*HandleMakeJoinResponse, *util.JSONResponse) {
	// Check that the room that the remote side is trying to join is actually
	// one of the room versions that they listed in their supported ?ver= in
	// the make_join URL.
	// https://matrix.org/docs/spec/server_server/r0.1.3#get-matrix-federation-v1-make-join-roomid-userid
	// If it isn't, stop trying to join the room.
	if !roomVersionSupported(input.RoomVersion, input.RemoteVersions) {
		return nil, &util.JSONResponse{Code: http.StatusBadRequest, JSON: IncompatibleRoomVersion(input.RoomVersion)}
	}

	if input.UserID.Domain() != input.RequestOrigin {
		return nil, &util.JSONResponse{
			Code: http.StatusForbidden,
			JSON: Forbidden("The join must be sent by the server of the user"),
		}
	}

	inRoomRes, err := input.RoomQuerier.ServerInRoom(input.Context, input.LocalServerName, input.RoomID)
	if err != nil {
		util.GetLogger(input.Context).WithError(err).Error("ServerInRoom failed")
		return nil, &util.JSONResponse{
			Code: http.StatusNotFound,
			JSON: InternalServerError(),
		}
	}

	// Check if we think we are still joined to the room
	if !inRoomRes.RoomExists {
		return nil, &util.JSONResponse{
			Code: http.StatusNotFound,
			JSON: NotFound(fmt.Sprintf("Room ID %q was not found on this server", input.RoomID.String())),
		}
	}
	if !inRoomRes.ServerInRoom {
		return nil, &util.JSONResponse{
			Code: http.StatusNotFound,
			JSON: NotFound(fmt.Sprintf("Room ID %q has no remaining users on this server", input.RoomID.String())),
		}
	}

	// Check if the restricted join is allowed. If the room doesn't
	// support restricted joins then this is effectively a no-op.
	res, authorisedVia, err := checkRestrictedJoin(input.Context, input.LocalServerName, input.RoomQuerier, input.RoomVersion, input.RoomID, input.UserID)
	if err != nil {
		util.GetLogger(input.Context).WithError(err).Error("checkRestrictedJoin failed")
		e := InternalServerError()
		return nil, &e
	} else if res != nil {
		return nil, res
	}

	// Try building an event for the server
	rawUserID := input.UserID.String()
	proto := ProtoEvent{
		Sender:   input.UserID.String(),
		RoomID:   input.RoomID.String(),
		Type:     "m.room.member",
		StateKey: &rawUserID,
	}
	content := MemberContent{
		Membership:    spec.Join,
		AuthorisedVia: authorisedVia,
	}
	if err = proto.SetContent(content); err != nil {
		util.GetLogger(input.Context).WithError(err).Error("builder.SetContent failed")
		e := InternalServerError()
		return nil, &e
	}

	event, state, templateErr := input.BuildEventTemplate(&proto)
	if templateErr != nil {
		return nil, templateErr
	}

	provider := NewAuthEvents(state)
	if err = Allowed(event, &provider); err != nil {
		return nil, &util.JSONResponse{
			Code: http.StatusForbidden,
			JSON: Forbidden(err.Error()),
		}
	}

	makeJoinResponse := HandleMakeJoinResponse{
		JoinTemplateEvent: proto,
		RoomVersion:       input.RoomVersion,
	}
	return &makeJoinResponse, nil
}

// checkRestrictedJoin finds out whether or not we can assist in processing
// a restricted room join. If the room version does not support restricted
// joins then this function returns with no side effects. This returns three
// values:
//   - an optional JSON response body (i.e. M_UNABLE_TO_AUTHORISE_JOIN) which
//     should always be sent back to the client if one is specified
//   - a user ID of an authorising user, typically a user that has power to
//     issue invites in the room, if one has been found
//   - an error if there was a problem finding out if this was allowable,
//     like if the room version isn't known or a problem happened talking to
//     the roomserver
func checkRestrictedJoin(
	ctx context.Context,
	localServerName spec.ServerName,
	roomQuerier RoomQuerier,
	roomVersion RoomVersion,
	roomID *spec.RoomID, userID *spec.UserID,
) (*util.JSONResponse, string, error) {
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil, "", err
	}
	if !verImpl.MayAllowRestrictedJoinsInEventAuth() {
		return nil, "", nil
	}
	req := &QueryRestrictedJoinAllowedRequest{
		RoomID: roomID,
		UserID: userID,
	}
	res := &QueryRestrictedJoinAllowedResponse{}
	if err := QueryRestrictedJoinAllowed(ctx, localServerName, roomQuerier, req, res); err != nil {
		return nil, "", err
	}

	switch {
	case !res.Restricted:
		// The join rules for the room don't restrict membership.
		return nil, "", nil

	case !res.Resident:
		// The join rules restrict membership but our server isn't currently
		// joined to all of the allowed rooms, so we can't actually decide
		// whether or not to allow the user to join. This error code should
		// tell the joining server to try joining via another resident server
		// instead.
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: UnableToAuthoriseJoin("This server cannot authorise the join."),
		}, "", nil

	case !res.Allowed:
		// The join rules restrict membership, our server is in the relevant
		// rooms and the user wasn't joined to join any of the allowed rooms
		// and therefore can't join this room.
		return &util.JSONResponse{
			Code: http.StatusForbidden,
			JSON: Forbidden("You are not joined to any matching rooms."),
		}, "", nil

	default:
		// The join rules restrict membership, our server is in the relevant
		// rooms and the user was allowed to join because they belong to one
		// of the allowed rooms. We now need to pick one of our own local users
		// from within the room to use as the authorising user ID, so that it
		// can be referred to from within the membership content.
		return nil, res.AuthorisedVia, nil
	}
}

// nolint:gocyclo
func QueryRestrictedJoinAllowed(ctx context.Context, localServerName spec.ServerName, roomQuerier RoomQuerier, req *QueryRestrictedJoinAllowedRequest, res *QueryRestrictedJoinAllowedResponse) error {
	// Look up if we know anything about the room. If it doesn't exist
	// or is a stub entry then we can't do anything.
	//roomInfo, err := r.DB.RoomInfo(ctx, req.RoomID)
	roomInfo, err := roomQuerier.RoomInfo(ctx, req.RoomID)
	if err != nil {
		return fmt.Errorf("roomQuerier.RoomInfo: %w", err)
	}
	if roomInfo == nil {
		return fmt.Errorf("room %q doesn't exist or is stub room", req.RoomID)
	}
	verImpl, err := GetRoomVersion(roomInfo.Version)
	if err != nil {
		return err
	}

	// If the room version doesn't allow restricted joins then don't
	// try to process any further.
	allowRestrictedJoins := verImpl.MayAllowRestrictedJoinsInEventAuth()
	if !allowRestrictedJoins {
		return nil
	}

	// Start off by populating the "resident" flag in the response. If we
	// come across any rooms in the request that are missing, we will unset
	// the flag.
	res.Resident = true

	// Get the join rules to work out if the join rule is "restricted".
	//joinRulesEvent, err := r.DB.GetStateEvent(ctx, req.RoomID, spec.MRoomJoinRules, "")
	joinRulesEvent, err := roomQuerier.StateEvent(ctx, req.RoomID, spec.MRoomJoinRules, "")
	if err != nil {
		return fmt.Errorf("roomQuerier.StateEvent: %w", err)
	}
	if joinRulesEvent == nil {
		return nil
	}
	var joinRules JoinRuleContent
	if err = json.Unmarshal(joinRulesEvent.Content(), &joinRules); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	// If the join rule isn't "restricted" or "knock_restricted" then there's nothing more to do.
	res.Restricted = joinRules.JoinRule == spec.Restricted || joinRules.JoinRule == spec.KnockRestricted
	if !res.Restricted {
		return nil
	}

	// If the user is already invited to the room then the join is allowed
	// but we don't specify an authorised via user, since the event auth
	// will allow the join anyway.
	//var pending bool
	//if pending, _, _, _, err = helpers.IsInvitePending(ctx, r.DB, req.RoomID, req.UserID); err != nil {
	if pending, err := roomQuerier.InvitePending(ctx, req.RoomID, req.UserID); err != nil {
		return fmt.Errorf("helpers.IsInvitePending: %w", err)
	} else if pending {
		res.Allowed = true
		return nil
	}

	// We need to get the power levels content so that we can determine which
	// users in the room are entitled to issue invites. We need to use one of
	// these users as the authorising user.
	//powerLevelsEvent, err := r.DB.GetStateEvent(ctx, req.RoomID, spec.MRoomPowerLevels, "")
	powerLevelsEvent, err := roomQuerier.StateEvent(ctx, req.RoomID, spec.MRoomPowerLevels, "")
	if err != nil {
		return fmt.Errorf("roomQuerier.StateEvent: %w", err)
	}
	powerLevels, err := powerLevelsEvent.PowerLevels()
	if err != nil {
		return fmt.Errorf("unable to get powerlevels: %w", err)
	}

	// Step through the join rules and see if the user matches any of them.
	for _, rule := range joinRules.Allow {
		// We only understand "m.room_membership" rules at this point in
		// time, so skip any rule that doesn't match those.
		if rule.Type != spec.MRoomMembership {
			continue
		}

		// See if the room exists. If it doesn't exist or if it's a stub
		// room entry then we can't check memberships.
		//targetRoomInfo, err := r.DB.RoomInfo(ctx, rule.RoomID)
		roomID, err := spec.NewRoomID(rule.RoomID)
		if err != nil {
			continue
		}
		targetRoomInfo, err := roomQuerier.RoomInfo(ctx, roomID)
		if err != nil || targetRoomInfo == nil {
			res.Resident = false
			continue
		}

		// First of all work out if *we* are still in the room, otherwise
		// it's possible that the memberships will be out of date.
		//isIn, err := r.DB.GetLocalServerInRoom(ctx, targetRoomInfo.RoomNID)
		localMembership, err := roomQuerier.ServerInRoom(ctx, localServerName, roomID)
		if err != nil || !localMembership.ServerInRoom {
			// If we aren't in the room, we can no longer tell if the room
			// memberships are up-to-date.
			res.Resident = false
			continue
		}

		// At this point we're happy that we are in the room, so now let's
		// see if the target user is in the room.
		//_, isIn, _, err = r.DB.GetMembership(ctx, targetRoomInfo.RoomNID, req.UserID)
		joinerInRoom, err := roomQuerier.Membership(ctx, targetRoomInfo.NID, req.UserID)
		if err != nil {
			continue
		}

		// If the user is not in the room then we will skip them.
		if !joinerInRoom {
			continue
		}

		// The user is in the room, so now we will need to authorise the
		// join using the user ID of one of our own users in the room. Pick
		// one.
		joinedUsers, err := roomQuerier.GetJoinedUsers(ctx, targetRoomInfo.Version, targetRoomInfo.NID)
		if err != nil || len(joinedUsers) == 0 {
			// There should always be more than one join event at this point
			// because we are gated behind GetLocalServerInRoom, but y'know,
			// sometimes strange things happen.
			continue
		}

		// For each of the joined users, let's see if we can get a valid
		// membership event.
		for _, user := range joinedUsers {
			if user.Type() != spec.MRoomMember || user.StateKey() == nil {
				continue // shouldn't happen
			}
			// Only users that have the power to invite should be chosen.
			if powerLevels.UserLevel(*user.StateKey()) < powerLevels.Invite {
				continue
			}
			res.Resident = true
			res.Allowed = true
			res.AuthorisedVia = *user.StateKey()
			return nil
		}
	}
	return nil
}
