package gomatrixserverlib

import (
	"context"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

type FederatedJoinClient interface {
	MakeJoin(ctx context.Context, origin, s spec.ServerName, roomID, userID string) (res MakeJoinResponse, err error)
	SendJoin(ctx context.Context, origin, s spec.ServerName, event PDU) (res SendJoinResponse, err error)
}

type MakeJoinResponse interface {
	GetJoinEvent() EventBuilder
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
