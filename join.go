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

type MakeJoinResponse interface {
	GetJoinEvent() ProtoEvent
	GetRoomVersion() RoomVersion
}

type SendJoinResponse interface {
	GetAuthEvents() EventJSONs
	GetStateEvents() EventJSONs
	GetOrigin() spec.ServerName
	GetJoinEvent() json.RawMessage
	GetMembersOmitted() bool
	GetServersInRoom() []string
}
