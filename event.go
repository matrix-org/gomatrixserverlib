package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"time"
)

// An EventReference is a reference to a matrix event.
type EventReference struct {
	// The event ID of the event.
	EventID string
	// The sha256 of the redacted event.
	EventSHA256 Base64String
}

// An EventBuilder is used to build a new event.
type EventBuilder struct {
	// The user ID of the user sending the event.
	Sender string `json:"sender"`
	// The room ID of the room this event is in.
	RoomID string `json:"room_id"`
	// The type of the event.
	Type string `json:"type"`
	// The state_key of the event if the event is a state event or nil if the event is not a state event.
	StateKey *string `json:"state_key,omitempty"`
	// The events that immediately preceeded this event in the room history.
	PrevEvents []EventReference `json:"prev_events"`
	// The events needed to authenticate this event.
	AuthEvents []EventReference `json:"auth_events"`
	// The event ID of the event being redacted if this event is a "m.room.redaction".
	Redacts  string `json:"redacts,omitempty"`
	content  []byte
	unsigned []byte
}

// SetContent sets the JSON content key of the event.
func (eb *EventBuilder) SetContent(content interface{}) (err error) {
	eb.content, err = json.Marshal(content)
	return
}

// SetUnsigned sets the JSON unsigned key of the event.
func (eb *EventBuilder) SetUnsigned(unsigned interface{}) (err error) {
	eb.unsigned, err = json.Marshal(unsigned)
	return
}

// An Event is a matrix event.
// The event should always contain valid JSON.
// If the event content hash is invalid then the event is redacted.
// Redacted events contain only the fields covered by the event signature.
type Event struct {
	redacted  bool
	eventJSON []byte
}

var emptyEventReferenceList = []EventReference{}

// Build a new Event.
// This is used when a local event is created on this server.
// Call this after filling out the necessary fields.
// This can be called mutliple times on the same builder.
// A different event ID must be supplied each time this is called.
func (eb *EventBuilder) Build(eventID string, now time.Time, origin, keyID string, privateKey ed25519.PrivateKey) (result Event, err error) {
	var event struct {
		EventBuilder
		EventID        string  `json:"event_id"`
		RawContent     rawJSON `json:"content"`
		RawUnsigned    rawJSON `json:"unsigned"`
		OriginServerTS int64   `json:"origin_server_ts"`
		Origin         string  `json:"origin"`
	}
	event.EventBuilder = *eb
	if event.PrevEvents == nil {
		event.PrevEvents = emptyEventReferenceList
	}
	if event.AuthEvents == nil {
		event.AuthEvents = emptyEventReferenceList
	}
	event.RawContent = rawJSON(event.content)
	event.RawUnsigned = rawJSON(event.unsigned)
	event.OriginServerTS = now.UnixNano() / 1000000
	event.Origin = origin
	event.EventID = eventID

	// TODO: Check size limits.

	var eventJSON []byte

	if eventJSON, err = json.Marshal(&event); err != nil {
		return
	}

	if eventJSON, err = addContentHashesToEvent(eventJSON); err != nil {
		return
	}

	if eventJSON, err = signEvent(origin, keyID, privateKey, eventJSON); err != nil {
		return
	}

	if eventJSON, err = CanonicalJSON(eventJSON); err != nil {
		return
	}

	result.eventJSON = eventJSON
	return
}

// NewEventFromUntrustedJSON loads a new event from some JSON that may be invalid.
// This checks that the event is valid JSON.
// It also checks the content hashes to ensure the event has not been tampered with.
// This should be used when receiving new events from remote servers.
func NewEventFromUntrustedJSON(eventJSON []byte) (result Event, err error) {
	var event map[string]rawJSON
	if err = json.Unmarshal(eventJSON, &event); err != nil {
		return
	}
	// Synapse removes these keys from events in case a server accidentally added them.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/crypto/event_signing.py#L57-L62
	delete(event, "outlier")
	delete(event, "destinations")
	delete(event, "age_ts")

	// TODO: Check that the event fields are correctly defined.
	// TODO: Check size limits.

	if eventJSON, err = json.Marshal(event); err != nil {
		return
	}

	if err = checkEventContentHash(eventJSON); err != nil {
		result.redacted = true
		// If the content hash doesn't match then we have to discard all non-essential fields
		// because they've been tampered with.
		if eventJSON, err = redactEvent(eventJSON); err != nil {
			return
		}
	}

	if eventJSON, err = CanonicalJSON(eventJSON); err != nil {
		return
	}

	result.eventJSON = eventJSON
	return
}

// NewEventFromTrustedJSON loads a new event from some JSON that must be valid.
// This will be more efficient than NewEventFromUntrustedJSON since it can skip cryptographic checks.
// This can be used when loading matrix events from a local database.
func NewEventFromTrustedJSON(eventJSON []byte, redacted bool) Event {
	return Event{redacted, eventJSON}
}

// Redacted returns whether the event is redacted.
func (e Event) Redacted() bool { return e.redacted }

// JSON returns the JSON bytes for the event.
func (e Event) JSON() []byte { return e.eventJSON }

// Redact returns a redacted copy of the event.
func (e Event) Redact() Event {
	if e.redacted {
		return e
	}
	eventJSON, err := redactEvent(e.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	if eventJSON, err = CanonicalJSON(eventJSON); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	return Event{
		redacted:  true,
		eventJSON: eventJSON,
	}
}

// EventReference returns an EventReference for the event.
// The reference can be used to refer to this event from other events.
func (e Event) EventReference() EventReference {
	reference, err := referenceOfEvent(e.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		// This can be reached if NewEventFromTrustedJSON is given JSON from an untrusted source.
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	return reference
}

// Sign returns a copy of the event with an additional signature.
func (e Event) Sign(signingName, keyID string, privateKey ed25519.PrivateKey) Event {
	eventJSON, err := signEvent(signingName, keyID, privateKey, e.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	if eventJSON, err = CanonicalJSON(eventJSON); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	return Event{
		redacted:  e.redacted,
		eventJSON: eventJSON,
	}
}

// KeyIDs returns a list of key IDs that the named entity has signed the event with.
func (e Event) KeyIDs(signingName string) []string {
	var event struct {
		Signatures map[string]map[string]rawJSON `json:"signatures"`
	}
	if err := json.Unmarshal(e.eventJSON, &event); err != nil {
		// This should unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	var keyIDs []string
	for keyID := range event.Signatures[signingName] {
		keyIDs = append(keyIDs, keyID)
	}
	return keyIDs
}

// Verify checks a ed25519 signature
func (e Event) Verify(signingName, keyID string, publicKey ed25519.PublicKey) error {
	return verifyEventSignature(signingName, keyID, publicKey, e.eventJSON)
}
