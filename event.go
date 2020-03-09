/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

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

// An EventReference is a reference to a matrix event.
type EventReference struct {
	// The event ID of the event.
	EventID string
	// The sha256 of the redacted event.
	EventSHA256 Base64String
}

// An EventBuilder is used to build a new event.
// These can be exchanged between matrix servers in the federation APIs when
// joining or leaving a room.
type EventBuilder struct {
	// The user ID of the user sending the event.
	Sender string `json:"sender"`
	// The room ID of the room this event is in.
	RoomID string `json:"room_id"`
	// The type of the event.
	Type string `json:"type"`
	// The state_key of the event if the event is a state event or nil if the event is not a state event.
	StateKey *string `json:"state_key,omitempty"`
	// The events that immediately preceded this event in the room history.
	PrevEvents []EventReference `json:"prev_events"`
	// The events needed to authenticate this event.
	AuthEvents []EventReference `json:"auth_events"`
	// The event ID of the event being redacted if this event is a "m.room.redaction".
	Redacts string `json:"redacts,omitempty"`
	// The depth of the event, This should be one greater than the maximum depth of the previous events.
	// The create event has a depth of 1.
	Depth int64 `json:"depth"`
	// The JSON object for "content" key of the event.
	Content RawJSON `json:"content"`
	// The JSON object for the "unsigned" key
	Unsigned RawJSON `json:"unsigned,omitempty"`
}

// SetContent sets the JSON content key of the event.
func (eb *EventBuilder) SetContent(content interface{}) (err error) {
	eb.Content, err = json.Marshal(content)
	return
}

// SetUnsigned sets the JSON unsigned key of the event.
func (eb *EventBuilder) SetUnsigned(unsigned interface{}) (err error) {
	eb.Unsigned, err = json.Marshal(unsigned)
	return
}

// An Event is a matrix event.
// The event should always contain valid JSON.
// If the event content hash is invalid then the event is redacted.
// Redacted events contain only the fields covered by the event signature.
type Event struct {
	redacted    bool
	eventJSON   []byte
	fields      interface{}
	roomVersion RoomVersion
}

type eventFields struct {
	EventID        string     `json:"event_id,omitempty"`
	RoomID         string     `json:"room_id"`
	Sender         string     `json:"sender"`
	Type           string     `json:"type"`
	StateKey       *string    `json:"state_key"`
	Content        RawJSON    `json:"content"`
	Redacts        string     `json:"redacts"`
	Depth          int64      `json:"depth"`
	Unsigned       RawJSON    `json:"unsigned"`
	OriginServerTS Timestamp  `json:"origin_server_ts"`
	Origin         ServerName `json:"origin"`
}

type eventFieldsRoomV1 struct {
	eventFields
	PrevEvents []EventReference `json:"prev_events"`
	AuthEvents []EventReference `json:"auth_events"`
}

type eventFieldsRoomV3 struct {
	eventFields
	PrevEvents []string `json:"prev_events"`
	AuthEvents []string `json:"auth_events"`
}

var emptyEventReferenceList = []EventReference{}

// Build a new Event.
// This is used when a local event is created on this server.
// Call this after filling out the necessary fields.
// This can be called multiple times on the same builder.
// A different event ID must be supplied each time this is called.
func (eb *EventBuilder) Build(
	eventID string, now time.Time, origin ServerName, keyID KeyID,
	privateKey ed25519.PrivateKey, roomVersion RoomVersion,
) (result Event, err error) {
	var event struct {
		EventBuilder
		EventID        string     `json:"event_id"`
		OriginServerTS Timestamp  `json:"origin_server_ts"`
		Origin         ServerName `json:"origin"`
		// This key is either absent or an empty list.
		// If it is absent then the pointer is nil and omitempty removes it.
		// Otherwise it points to an empty list and omitempty keeps it.
		PrevState *[]EventReference `json:"prev_state,omitempty"`
	}
	event.EventBuilder = *eb
	if event.PrevEvents == nil {
		event.PrevEvents = emptyEventReferenceList
	}
	if event.AuthEvents == nil {
		event.AuthEvents = emptyEventReferenceList
	}
	event.OriginServerTS = AsTimestamp(now)
	event.Origin = origin
	event.EventID = eventID

	if event.StateKey != nil {
		// In early versions of the matrix protocol state events
		// had a "prev_state" key that listed the state events with
		// the same type and state key that this event replaced.
		// This was later dropped from the protocol.
		// Synapse ignores the contents of the key but still expects
		// the key to be present in state events.
		event.PrevState = &emptyEventReferenceList
	}

	var eventJSON []byte

	if eventJSON, err = json.Marshal(&event); err != nil {
		return
	}

	if eventJSON, err = addContentHashesToEvent(eventJSON); err != nil {
		return
	}

	if eventJSON, err = signEvent(string(origin), keyID, privateKey, eventJSON); err != nil {
		return
	}

	if eventJSON, err = CanonicalJSON(eventJSON); err != nil {
		return
	}

	result.roomVersion = roomVersion
	result.eventJSON = eventJSON
	if err = json.Unmarshal(eventJSON, &result.fields); err != nil {
		return
	}

	if err = result.CheckFields(); err != nil {
		return
	}

	return
}

// NewEventFromUntrustedJSON loads a new event from some JSON that may be invalid.
// This checks that the event is valid JSON.
// It also checks the content hashes to ensure the event has not been tampered with.
// This should be used when receiving new events from remote servers.
func NewEventFromUntrustedJSON(eventJSON []byte, roomVersion RoomVersion) (result Event, err error) {
	result.roomVersion = roomVersion

	// We parse the JSON early on so that we don't have to check if the JSON
	// is valid
	switch roomVersion.EventIDFormat() {
	case EventIDFormatV1:
		var fields eventFieldsRoomV1
		if err = json.Unmarshal(eventJSON, &fields); err != nil {
			return
		}
		result.fields = fields
	case EventIDFormatV2, EventIDFormatV3:
		var fields eventFieldsRoomV3
		if err = json.Unmarshal(eventJSON, &fields); err != nil {
			return
		}
		result.fields = fields
	default:
		panic("event ID format not supported")
	}

	// Synapse removes these keys from events in case a server accidentally added them.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/crypto/event_signing.py#L57-L62
	for _, key := range []string{"outlier", "destinations", "age_ts"} {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, key); err != nil {
			return
		}
	}

	// If the event ID format is for room versions 1 or 2 then we keep the event
	// ID, otherwise strip it and generate a new one from the reference hash
	var eventID string
	if roomVersion.EventIDFormat() == EventIDFormatV1 {
		// Room version 1 or 2 - just preserve the event ID from the event
		eventID = result.fields.(eventFieldsRoomV1).EventID
	} else {
		// Room versions 3, 4 or 5 - scrap the event ID in the event, if it is there
		if eventJSON, err = sjson.DeleteBytes(eventJSON, "event_id"); err != nil {
			return
		}
		// Select the algorithm
		var encoder *base64.Encoding
		switch roomVersion.EventIDFormat() {
		case EventIDFormatV2:
			encoder = base64.RawStdEncoding.WithPadding(base64.NoPadding)
		case EventIDFormatV3:
			encoder = base64.RawURLEncoding.WithPadding(base64.NoPadding)
		}
		// Generate the new event ID from the reference hash
		if encoder != nil {
			sum := sha256.Sum256(eventJSON)
			eventID = fmt.Sprintf("$%s", encoder.EncodeToString(sum[:]))
		}
	}

	// We know the JSON must be valid here.
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	if err = checkEventContentHash(eventJSON); err != nil {
		result.redacted = true

		// If the content hash doesn't match then we have to discard all non-essential fields
		// because they've been tampered with.
		var redactedJSON []byte
		if redactedJSON, err = redactEvent(eventJSON); err != nil {
			return
		}

		redactedJSON = CanonicalJSONAssumeValid(redactedJSON)

		// We need to ensure that `result` is the redacted event.
		// If redactedJSON is the same as eventJSON then `result` is already
		// correct. If not then we need to reparse.
		//
		// Yes, this means that for some events we parse twice (which is slow),
		// but means that parsing unredacted events is fast.
		if !bytes.Equal(redactedJSON, eventJSON) {
			result = Event{redacted: true}
			if err = json.Unmarshal(redactedJSON, &result.fields); err != nil {
				return
			}
			if roomVersion <= RoomVersionV2 {
				result.fields.(*eventFieldsRoomV1).EventID = eventID
			} else if roomVersion <= RoomVersionV5 {
				result.fields.(*eventFieldsRoomV3).EventID = eventID
			}
		}

		eventJSON = redactedJSON
	}

	result.eventJSON = eventJSON

	if err = result.CheckFields(); err != nil {
		return
	}

	return
}

// NewEventFromTrustedJSON loads a new event from some JSON that must be valid.
// This will be more efficient than NewEventFromUntrustedJSON since it can skip cryptographic checks.
// This can be used when loading matrix events from a local database.
func NewEventFromTrustedJSON(eventJSON []byte, redacted bool, roomVersion RoomVersion) (result Event, err error) {
	result.roomVersion = roomVersion

	result.redacted = redacted
	result.eventJSON = eventJSON

	switch roomVersion.EventIDFormat() {
	case EventIDFormatV1:
		var fields eventFieldsRoomV1
		if err = json.Unmarshal(eventJSON, &fields); err != nil {
			return
		}
		result.fields = fields
	case EventIDFormatV2, EventIDFormatV3:
		var fields eventFieldsRoomV3
		if err = json.Unmarshal(eventJSON, &fields); err != nil {
			return
		}
		result.fields = fields
	default:
		panic("event ID format not supported")
	}

	return
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
	result := Event{
		redacted:  true,
		eventJSON: eventJSON,
	}
	if err = json.Unmarshal(eventJSON, &result.fields); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	return result
}

// SetUnsigned sets the unsigned key of the event.
// Returns a copy of the event with the "unsigned" key set.
func (e Event) SetUnsigned(unsigned interface{}) (Event, error) {
	var eventAsMap map[string]RawJSON
	var err error
	if err = json.Unmarshal(e.eventJSON, &eventAsMap); err != nil {
		return Event{}, err
	}
	unsignedJSON, err := json.Marshal(unsigned)
	if err != nil {
		return Event{}, err
	}
	eventAsMap["unsigned"] = unsignedJSON
	eventJSON, err := json.Marshal(eventAsMap)
	if err != nil {
		return Event{}, err
	}
	if eventJSON, err = CanonicalJSON(eventJSON); err != nil {
		return Event{}, err
	}
	result := e
	result.eventJSON = eventJSON
	if e.roomVersion.EventIDFormat() == EventIDFormatV1 {
		result.fields.(*eventFieldsRoomV1).Unsigned = unsignedJSON
	} else {
		result.fields.(*eventFieldsRoomV3).Unsigned = unsignedJSON
	}
	return result, nil
}

// SetUnsignedField takes a path and value to insert into the unsigned dict of
// the event.
// path is a dot separated path into the unsigned dict (see gjson package
// for details on format). In particular some characters like '.' and '*' must
// be escaped.
func (e *Event) SetUnsignedField(path string, value interface{}) error {
	// The safest way is to change the unsigned json and then reparse the
	// event fully. But since we are only changing the unsigned section,
	// which doesn't affect the signatures or hashes, we can cheat and
	// just fiddle those bits directly.

	path = "unsigned." + path
	eventJSON, err := sjson.SetBytes(e.eventJSON, path, value)
	if err != nil {
		return err
	}
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	res := gjson.GetBytes(eventJSON, "unsigned")
	unsigned := RawJSONFromResult(res, eventJSON)

	e.eventJSON = eventJSON
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		fields.Unsigned = unsigned
	case eventFieldsRoomV3:
		fields.Unsigned = unsigned
	default:
		panic("unexpected field type")
	}

	return nil
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
func (e Event) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) Event {
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
		fields:    e.fields,
	}
}

// KeyIDs returns a list of key IDs that the named entity has signed the event with.
func (e Event) KeyIDs(signingName string) []KeyID {
	keyIDs, err := ListKeyIDs(signingName, e.eventJSON)
	if err != nil {
		// This should unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	return keyIDs
}

// Verify checks a ed25519 signature
func (e Event) Verify(signingName string, keyID KeyID, publicKey ed25519.PublicKey) error {
	return verifyEventSignature(signingName, keyID, publicKey, e.eventJSON)
}

// StateKey returns the "state_key" of the event, or the nil if the event is not a state event.
func (e Event) StateKey() *string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.StateKey
	case eventFieldsRoomV3:
		return fields.StateKey
	default:
		panic("unexpected field type")
	}
}

// StateKeyEquals returns true if the event is a state event and the "state_key" matches.
func (e Event) StateKeyEquals(stateKey string) bool {
	var sk *string
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		sk = fields.StateKey
	case eventFieldsRoomV3:
		sk = fields.StateKey
	default:
		panic("unexpected field type")
	}
	if sk == nil {
		return false
	}
	return *sk == stateKey
}

const (
	// The event ID, room ID, sender, event type and state key fields cannot be
	// bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L173-L182
	maxIDLength = 255
	// The entire event JSON, including signatures cannot be bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L183-184
	maxEventLength = 65536
)

// CheckFields checks that the event fields are valid.
// Returns an error if the IDs have the wrong format or too long.
// Returns an error if the total length of the event JSON is too long.
// Returns an error if the event ID doesn't match the origin of the event.
// https://matrix.org/docs/spec/client_server/r0.2.0.html#size-limits
func (e Event) CheckFields() error { // nolint: gocyclo
	var fields eventFields
	switch f := e.fields.(type) {
	case eventFieldsRoomV1:
		fields = f.eventFields
	case eventFieldsRoomV3:
		fields = f.eventFields
	default:
		panic("unexpected field type")
	}

	if len(e.eventJSON) > maxEventLength {
		return fmt.Errorf(
			"gomatrixserverlib: event is too long, length %d > maximum %d",
			len(e.eventJSON), maxEventLength,
		)
	}

	if len(fields.Type) > maxIDLength {
		return fmt.Errorf(
			"gomatrixserverlib: event type is too long, length %d > maximum %d",
			len(fields.Type), maxIDLength,
		)
	}

	if fields.StateKey != nil && len(*fields.StateKey) > maxIDLength {
		return fmt.Errorf(
			"gomatrixserverlib: state key is too long, length %d > maximum %d",
			len(*fields.StateKey), maxIDLength,
		)
	}

	_, err := checkID(fields.RoomID, "room", '!')
	if err != nil {
		return err
	}

	origin := fields.Origin

	senderDomain, err := checkID(fields.Sender, "user", '@')
	if err != nil {
		return err
	}

	if e.roomVersion.EventIDFormat() == EventIDFormatV1 {
		eventDomain, err := checkID(e.fields.(eventFieldsRoomV1).EventID, "event", '$')
		if err != nil {
			return err
		}
		// Synapse requires that the event ID domain has a valid signature.
		// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L66-L68
		// Synapse requires that the event origin has a valid signature.
		// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/federation/federation_base.py#L133-L136
		// Since both domains must be valid domains, and there is no good reason for them
		// to be different we might as well ensure that they are the same since it
		// makes the signature checks simpler.
		if origin != ServerName(eventDomain) {
			return fmt.Errorf(
				"gomatrixserverlib: event ID domain doesn't match origin: %q != %q",
				eventDomain, origin,
			)
		}

		if origin != ServerName(senderDomain) {
			// For the most part all events should be sent by a user on the
			// originating server.
			//
			// However "m.room.member" events created from third-party invites
			// are allowed to have a different sender because they have the same
			// sender as the "m.room.third_party_invite" event they derived from.
			// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L58-L64
			//
			// Also, some old versions of synapse had a bug wherein some
			// joins/leaves used the origin and event id supplied by the helping
			// server instead of the joining/leaving server.
			//
			// So in general we allow the sender to be different from the
			// origin for m.room.member events. In any case, we check it was
			// signed by both servers later.
			if fields.Type != MRoomMember {
				return fmt.Errorf(
					"gomatrixserverlib: sender domain doesn't match origin: %q != %q",
					senderDomain, origin,
				)
			}
		}
	}

	return nil
}

func checkID(id, kind string, sigil byte) (domain string, err error) {
	domain, err = domainFromID(id)
	if err != nil {
		return
	}
	if id[0] != sigil {
		err = fmt.Errorf(
			"gomatrixserverlib: invalid %s ID, wanted first byte to be '%c' got '%c'",
			kind, sigil, id[0],
		)
		return
	}
	if len(id) > maxIDLength {
		err = fmt.Errorf(
			"gomatrixserverlib: %s ID is too long, length %d > maximum %d",
			kind, len(id), maxIDLength,
		)
		return
	}
	return
}

// Origin returns the name of the server that sent the event
func (e Event) Origin() ServerName {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.Origin
	case eventFieldsRoomV3:
		return fields.Origin
	default:
		panic("unexpected field type")
	}
}

// EventID returns the event ID of the event.
func (e Event) EventID() string {
	switch e.roomVersion {
	case RoomVersionV1, RoomVersionV2:
		return e.fields.(eventFieldsRoomV1).EventID
	case RoomVersionV3, RoomVersionV4, RoomVersionV5:
		return e.fields.(eventFieldsRoomV3).EventID
	default:
		panic("unexpected room version")
	}
}

// Sender returns the user ID of the sender of the event.
func (e Event) Sender() string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.Sender
	case eventFieldsRoomV3:
		return fields.Sender
	default:
		panic("unexpected field type")
	}
}

// Type returns the type of the event.
func (e Event) Type() string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.Type
	case eventFieldsRoomV3:
		return fields.Type
	default:
		panic("unexpected field type")
	}
}

// OriginServerTS returns the unix timestamp when this event was created on the origin server, with millisecond resolution.
func (e Event) OriginServerTS() Timestamp {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.OriginServerTS
	case eventFieldsRoomV3:
		return fields.OriginServerTS
	default:
		panic("unexpected field type")
	}
}

// Unsigned returns the object under the 'unsigned' key of the event.
func (e Event) Unsigned() []byte {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return []byte(fields.Unsigned)
	case eventFieldsRoomV3:
		return []byte(fields.Unsigned)
	default:
		panic("unexpected field type")
	}
}

// Content returns the content JSON of the event.
func (e Event) Content() []byte {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return []byte(fields.Content)
	case eventFieldsRoomV3:
		return []byte(fields.Content)
	default:
		panic("unexpected field type")
	}
}

// PrevEvents returns references to the direct ancestors of the event.
func (e Event) PrevEvents() []EventReference {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.PrevEvents
	case eventFieldsRoomV3:
		return []EventReference{}
	default:
		panic("unexpected field type")
	}
}

// PrevEventIDs returns the event IDs of the direct ancestors of the event.
func (e Event) PrevEventIDs() []string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		result := make([]string, len(fields.PrevEvents))
		for i := range fields.PrevEvents {
			result[i] = fields.PrevEvents[i].EventID
		}
		return result
	case eventFieldsRoomV3:
		return fields.PrevEvents
	default:
		panic("unexpected field type")
	}
}

// Membership returns the value of the content.membership field if this event
// is an "m.room.member" event.
// Returns an error if the event is not a m.room.member event or if the content
// is not valid m.room.member content.
func (e Event) Membership() (string, error) {
	var fields eventFields
	switch f := e.fields.(type) {
	case eventFieldsRoomV1:
		fields = f.eventFields
	case eventFieldsRoomV3:
		fields = f.eventFields
	default:
		panic("unexpected field type")
	}
	if fields.Type != MRoomMember {
		return "", fmt.Errorf("gomatrixserverlib: not an m.room.member event")
	}
	var content MemberContent
	if err := json.Unmarshal(fields.Content, &content); err != nil {
		return "", err
	}
	return content.Membership, nil
}

// AuthEvents returns references to the events needed to auth the event.
func (e Event) AuthEvents() []EventReference {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.AuthEvents
	case eventFieldsRoomV3:
		return []EventReference{}
	default:
		panic("unexpected field type")
	}
}

// AuthEventIDs returns the event IDs of the events needed to auth the event.
func (e Event) AuthEventIDs() []string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		result := make([]string, len(fields.AuthEvents))
		for i := range fields.AuthEvents {
			result[i] = fields.AuthEvents[i].EventID
		}
		return result
	case eventFieldsRoomV3:
		return fields.AuthEvents
	default:
		panic("unexpected field type")
	}
}

// Redacts returns the event ID of the event this event redacts.
func (e Event) Redacts() string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.Redacts
	case eventFieldsRoomV3:
		return fields.Redacts
	default:
		panic("unexpected field type")
	}
}

// RoomID returns the room ID of the room the event is in.
func (e Event) RoomID() string {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.RoomID
	case eventFieldsRoomV3:
		return fields.RoomID
	default:
		panic("unexpected field type")
	}
}

// Depth returns the depth of the event.
func (e Event) Depth() int64 {
	switch fields := e.fields.(type) {
	case eventFieldsRoomV1:
		return fields.Depth
	case eventFieldsRoomV3:
		return fields.Depth
	default:
		panic("unexpected field type")
	}
}

// MarshalJSON implements json.Marshaller
func (e Event) MarshalJSON() ([]byte, error) {
	if e.eventJSON == nil {
		return nil, fmt.Errorf("gomatrixserverlib: cannot serialise uninitialised Event")
	}
	return e.eventJSON, nil
}

// UnmarshalJSON implements json.Unmarshaller
func (er *EventReference) UnmarshalJSON(data []byte) error {
	var tuple []RawJSON
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
		SHA256 Base64String `json:"sha256"`
	}
	if err := json.Unmarshal(tuple[1], &hashes); err != nil {
		return fmt.Errorf("gomatrixserverlib: invalid event reference, second element is invalid: %q %v", string(tuple[1]), err)
	}
	er.EventSHA256 = hashes.SHA256
	return nil
}

// MarshalJSON implements json.Marshaller
func (er EventReference) MarshalJSON() ([]byte, error) {
	hashes := struct {
		SHA256 Base64String `json:"sha256"`
	}{er.EventSHA256}

	tuple := []interface{}{er.EventID, hashes}

	return json.Marshal(&tuple)
}

// SplitID splits a matrix ID into a local part and a server name.
func SplitID(sigil byte, id string) (local string, domain ServerName, err error) {
	// IDs have the format: SIGIL LOCALPART ":" DOMAIN
	// Split on the first ":" character since the domain can contain ":"
	// characters.
	if len(id) == 0 || id[0] != sigil {
		return "", "", fmt.Errorf("gomatrixserverlib: invalid ID %q doesn't start with %q", id, sigil)
	}
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		// The ID must have a ":" character.
		return "", "", fmt.Errorf("gomatrixserverlib: invalid ID %q missing ':'", id)
	}
	return parts[0][1:], ServerName(parts[1]), nil
}
