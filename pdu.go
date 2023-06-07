package gomatrixserverlib

import (
	"encoding/json"
	"fmt"

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
	OriginServerTS() spec.Timestamp
	// Redact redacts the event.
	Redact()
	SenderID() spec.SenderID
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

// A StateKeyTuple is the combination of an event type and an event state key.
// It is often used as a key in maps.
type StateKeyTuple struct {
	// The "type" key of a matrix event.
	EventType string
	// The "state_key" of a matrix event.
	// The empty string is a legitimate value for the "state_key" in matrix
	// so take care to initialise this field lest you accidentally request a
	// "state_key" with the go default of the empty string.
	StateKey string
}

// An eventReference is a reference to a matrix event.
type eventReference struct {
	// The event ID of the event.
	EventID string
	// The sha256 of the redacted event.
	EventSHA256 spec.Base64Bytes
}

// UnmarshalJSON implements json.Unmarshaller
func (er *eventReference) UnmarshalJSON(data []byte) error {
	var tuple []spec.RawJSON
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) != 2 {
		return fmt.Errorf("gomatrixserverlib: invalid event reference, invalid length: %d != 2", len(tuple))
	}
	if err := json.Unmarshal(tuple[0], &er.EventID); err != nil {
		return fmt.Errorf("gomatrixserverlib: invalid event reference, first element is invalid: %q %v", string(tuple[0]), err)
	}
	var hashes struct {
		SHA256 spec.Base64Bytes `json:"sha256"`
	}
	if err := json.Unmarshal(tuple[1], &hashes); err != nil {
		return fmt.Errorf("gomatrixserverlib: invalid event reference, second element is invalid: %q %v", string(tuple[1]), err)
	}
	er.EventSHA256 = hashes.SHA256
	return nil
}

// MarshalJSON implements json.Marshaller
func (er eventReference) MarshalJSON() ([]byte, error) {
	hashes := struct {
		SHA256 spec.Base64Bytes `json:"sha256"`
	}{er.EventSHA256}

	tuple := []interface{}{er.EventID, hashes}

	return json.Marshal(&tuple)
}
