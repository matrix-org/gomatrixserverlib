package gomatrixserverlib

import (
	"github.com/matrix-org/gomatrixserverlib/spec"
)

type PDU interface {
	EventID() string
	StateKey() *string
	StateKeyEquals(s string) bool
	Type() string
	Content() []byte
	Membership() (string, error)
	Version() RoomVersion
	RoomID() string
	Redacts() string
	PrevEventIDs() []string
	OriginServerTS() spec.Timestamp
	Sender() string
	EventReference() EventReference  // TODO: remove
	Depth() int64                    // TODO: remove
	JSON() []byte                    // TODO: remove
	AuthEventIDs() []string          // TODO: remove
	ToHeaderedJSON() ([]byte, error) // TODO: remove
}
