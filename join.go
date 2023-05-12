package gomatrixserverlib

import (
	"context"
	"encoding/json"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

type FederatedJoinClient interface {
	MakeJoin(ctx context.Context, origin, s spec.ServerName, roomID, userID string) (res MakeJoinResponse, err error)
	SendJoin(ctx context.Context, origin, s spec.ServerName, event PDU) (res SendJoinResponse, err error)
}

type RoomInfo struct {
	Version RoomVersion
	NID     int64
}

// JoinRoomQuerier provides the necessary information about a room to process a join request.
type JoinRoomQuerier interface {
	RoomInfo(ctx context.Context, roomID spec.RoomID) (*RoomInfo, error)
	StateEvent(ctx context.Context, roomID spec.RoomID, eventType spec.MatrixEventType, stateKey string) (PDU, error)
	ServerInRoom(ctx context.Context, server spec.ServerName, roomID spec.RoomID) (*JoinedToRoomResponse, error)
	Membership(ctx context.Context, roomNID int64, userID spec.UserID) (bool, error)
	GetJoinedUsers(ctx context.Context, roomVersion RoomVersion, roomNID int64) ([]PDU, error)
	InvitePending(ctx context.Context, roomID spec.RoomID, userID spec.UserID) (bool, error)
}

type ProtoEvent struct {
	// The user ID of the user sending the event.
	Sender string `json:"sender"`
	// The room ID of the room this event is in.
	RoomID string `json:"room_id"`
	// The type of the event.
	Type string `json:"type"`
	// The state_key of the event if the event is a state event or nil if the event is not a state event.
	StateKey *string `json:"state_key,omitempty"`
	// The events that immediately preceded this event in the room history. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	PrevEvents interface{} `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	AuthEvents interface{} `json:"auth_events"`
	// The event ID of the event being redacted if this event is a "m.room.redaction".
	Redacts string `json:"redacts,omitempty"`
	// The depth of the event, This should be one greater than the maximum depth of the previous events.
	// The create event has a depth of 1.
	Depth int64 `json:"depth"`
	// The JSON object for "signatures" key of the event.
	Signature spec.RawJSON `json:"signatures,omitempty"`
	// The JSON object for "content" key of the event.
	Content spec.RawJSON `json:"content"`
	// The JSON object for the "unsigned" key
	Unsigned spec.RawJSON `json:"unsigned,omitempty"`
}

func (pe *ProtoEvent) SetContent(content interface{}) (err error) {
	pe.Content, err = json.Marshal(content)
	return
}

// SetUnsigned sets the JSON unsigned key of the event.
func (pe *ProtoEvent) SetUnsigned(unsigned interface{}) (err error) {
	pe.Unsigned, err = json.Marshal(unsigned)
	return
}

type JoinedToRoomResponse struct {
	RoomExists   bool
	ServerInRoom bool
}

type QueryRestrictedJoinAllowedRequest struct {
	UserID spec.UserID
	RoomID spec.RoomID
}

type QueryRestrictedJoinAllowedResponse struct {
	// True if the room membership is restricted by the join rule being set to "restricted"
	Restricted bool `json:"restricted"`
	// True if our local server is joined to all of the allowed rooms specified in the "allow"
	// key of the join rule, false if we are missing from some of them and therefore can't
	// reliably decide whether or not we can satisfy the join
	Resident bool `json:"resident"`
	// True if the restricted join is allowed because we found the membership in one of the
	// allowed rooms from the join rule, false if not
	Allowed bool `json:"allowed"`
	// Contains the user ID of the selected user ID that has power to issue invites, this will
	// get populated into the "join_authorised_via_users_server" content in the membership
	AuthorisedVia string `json:"authorised_via,omitempty"`
}

type MakeJoinResponse interface {
	GetJoinEvent() ProtoEvent
	GetRoomVersion() RoomVersion
}

type SendJoinResponse interface {
	GetAuthEvents() EventJSONs
	GetStateEvents() EventJSONs
	GetOrigin() spec.ServerName
	GetJoinEvent() spec.RawJSON
	GetMembersOmitted() bool
	GetServersInRoom() []string
}
