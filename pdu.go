package gomatrixserverlib

import (
	"github.com/matrix-org/gomatrixserverlib/spec"
	"golang.org/x/crypto/ed25519"
)

type PDU interface {
	EventID() string
	StateKey() *string
	StateKeyEquals(s string) bool
	Type() string
	Content() []byte
	// JoinRule returns the value of the content.join_rule field if this event
	// is an "m.room.join_rules" event.
	// Returns an error if the event is not a m.room.join_rules event or if the content
	// is not valid m.room.join_rules content.
	JoinRule() (string, error)
	// HistoryVisibility returns the value of the content.history_visibility field if this event
	// is an "m.room.history_visibility" event.
	// Returns an error if the event is not a m.room.history_visibility event or if the content
	// is not valid m.room.history_visibility content.
	HistoryVisibility() (HistoryVisibility, error)
	Membership() (string, error)
	PowerLevels() (*PowerLevelContent, error)
	Version() RoomVersion
	RoomID() string
	Redacts() string
	// Redacted returns whether the event is redacted.
	Redacted() bool
	PrevEventIDs() []string
	PrevEvents() []EventReference // TODO: remove, used in Dendrite in (d *EventDatabase) StoreEvent
	OriginServerTS() spec.Timestamp
	// Redact redacts the event.
	Redact()
	Sender() string
	Unsigned() []byte
	// SetUnsigned sets the unsigned key of the event.
	// Returns a copy of the event with the "unsigned" key set.
	SetUnsigned(unsigned interface{}) (PDU, error)
	// SetUnsignedField takes a path and value to insert into the unsigned dict of
	// the event.
	// path is a dot separated path into the unsigned dict (see gjson package
	// for details on format). In particular some characters like '.' and '*' must
	// be escaped.
	SetUnsignedField(path string, value interface{}) error
	// Sign returns a copy of the event with an additional signature.
	Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU
	EventReference() EventReference  // TODO: remove
	Depth() int64                    // TODO: remove
	JSON() []byte                    // TODO: remove
	AuthEventIDs() []string          // TODO: remove
	ToHeaderedJSON() ([]byte, error) // TODO: remove
}

// Convert a slice of concrete PDU implementations to a slice of PDUs. This is useful when
// interfacing with GMSL functions which require []PDU.
func ToPDUs[T PDU](events []T) []PDU {
	result := make([]PDU, len(events))
	for i := range events {
		result[i] = events[i]
	}
	return result
}
