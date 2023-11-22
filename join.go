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

type RestrictedRoomJoinInfo struct {
	LocalServerInRoom bool
	UserJoinedToRoom  bool
	JoinedUsers       []PDU
}

type MembershipQuerier interface {
	CurrentMembership(ctx context.Context, roomID spec.RoomID, senderID spec.SenderID) (string, error)
}

// RestrictedRoomJoinQuerier provides the information needed when processing a restricted room join request.
type RestrictedRoomJoinQuerier interface {
	CurrentStateEvent(ctx context.Context, roomID spec.RoomID, eventType string, stateKey string) (PDU, error)
	InvitePending(ctx context.Context, roomID spec.RoomID, senderID spec.SenderID) (bool, error)
	RestrictedRoomJoinInfo(ctx context.Context, roomID spec.RoomID, senderID spec.SenderID, localServerName spec.ServerName) (*RestrictedRoomJoinInfo, error)
}

type ProtoEvent struct {
	// The sender ID of the user sending the event.
	SenderID string `json:"sender"`
	// The room ID of the room this event is in.
	RoomID string `json:"room_id"`
	// The type of the event.
	Type string `json:"type"`
	// The state_key of the event if the event is a state event or nil if the event is not a state event.
	StateKey *string `json:"state_key,omitempty"`
	// The events that immediately preceded this event in the room history. This can be
	// either []eventReference for room v1/v2, and []string for room v3 onwards.
	PrevEvents interface{} `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []eventReference for room v1/v2, and []string for room v3 onwards.
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
