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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

// Event validation errors
const (
	EventValidationTooLarge int = 1
)

// EventValidationError is returned if there is a problem validating an event
type EventValidationError struct {
	Message string
	Code    int
}

func (e EventValidationError) Error() string {
	return e.Message
}

// An Event is a matrix event.
// The event should always contain valid JSON.
// If the event content hash is invalid then the event is redacted.
// Redacted events contain only the fields covered by the event signature.
// The fields have different formats depending on the room version - see
// eventFormatV1Fields, eventFormatV2Fields.
type event struct {
	redacted    bool
	eventID     string
	eventJSON   []byte
	fields      any
	roomVersion RoomVersion
}

type eventFields struct {
	RoomID         string         `json:"room_id"`
	Sender         string         `json:"sender"`
	Type           string         `json:"type"`
	StateKey       *string        `json:"state_key"`
	Content        spec.RawJSON   `json:"content"`
	Redacts        string         `json:"redacts"`
	Depth          int64          `json:"depth"`
	Unsigned       spec.RawJSON   `json:"unsigned"`
	OriginServerTS spec.Timestamp `json:"origin_server_ts"`
	//Origin         spec.ServerName `json:"origin"`
}

// Fields for room versions 1, 2.
type eventFormatV1Fields struct {
	eventFields
	EventID    string           `json:"event_id,omitempty"`
	PrevEvents []eventReference `json:"prev_events"`
	AuthEvents []eventReference `json:"auth_events"`
}

// Fields for room versions 3, 4, 5.
type eventFormatV2Fields struct {
	eventFields
	PrevEvents []string `json:"prev_events"`
	AuthEvents []string `json:"auth_events"`
}

var emptyEventReferenceList = []eventReference{}

// newEventFromUntrustedJSON loads a new event from some JSON that may be invalid.
// This checks that the event is valid JSON.
// It also checks the content hashes to ensure the event has not been tampered with.
// This should be used when receiving new events from remote servers.
func newEventFromUntrustedJSON(eventJSON []byte, roomVersion IRoomVersion) (result *event, err error) {
	if r := gjson.GetBytes(eventJSON, "_*"); r.Exists() {
		err = fmt.Errorf("gomatrixserverlib NewEventFromUntrustedJSON: found top-level '_' key, is this a headered event: %v", string(eventJSON))
		return
	}
	if err = roomVersion.CheckCanonicalJSON(eventJSON); err != nil {
		err = BadJSONError{err}
		return
	}

	result = &event{}
	result.roomVersion = roomVersion.Version()

	eventFormat := roomVersion.EventFormat()

	if eventJSON, err = sjson.DeleteBytes(eventJSON, "unsigned"); err != nil {
		return
	}
	if eventFormat == EventFormatV2 {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, "event_id"); err != nil {
			return
		}
	}

	if err = result.populateFieldsFromJSON("", eventJSON); err != nil {
		return
	}

	// Synapse removes these keys from events in case a server accidentally added them.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/crypto/event_signing.py#L57-L62
	for _, key := range []string{"outlier", "destinations", "age_ts"} {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, key); err != nil {
			return
		}
	}

	// We know the JSON must be valid here.
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	if err = checkEventContentHash(eventJSON); err != nil {
		result.redacted = true

		// If the content hash doesn't match then we have to discard all non-essential fields
		// because they've been tampered with.
		var redactedJSON []byte
		if redactedJSON, err = roomVersion.RedactEventJSON(eventJSON); err != nil {
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
			if result, err = newEventFromTrustedJSON(redactedJSON, true, roomVersion); err != nil {
				return
			}
		}
	}

	err = result.CheckFields()
	return
}

// newEventFromTrustedJSON loads a new event from some JSON that must be valid.
// This will be more efficient than NewEventFromUntrustedJSON since it can skip cryptographic checks.
// This can be used when loading matrix events from a local database.
func newEventFromTrustedJSON(eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result *event, err error) {
	result = &event{}
	result.roomVersion = roomVersion.Version()
	result.redacted = redacted
	err = result.populateFieldsFromJSON("", eventJSON) // "" -> event ID not known
	return
}

// newEventFromTrustedJSONWithEventID loads a new event from some JSON that must be valid
// and that the event ID is already known. This must ONLY be used when retrieving
// an event from the database and NEVER when accepting an event over federation.
// This will be more efficient than NewEventFromTrustedJSON since, if the event
// ID is known, we skip all the reference hash and canonicalisation work.
func newEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result *event, err error) {
	result = &event{}
	result.roomVersion = roomVersion.Version()
	result.redacted = redacted
	err = result.populateFieldsFromJSON(eventID, eventJSON)
	return
}

func (e *event) ToHeaderedJSON() ([]byte, error) {
	var err error
	eventJSON := e.JSON()
	eventJSON, err = sjson.SetBytes(eventJSON, "_room_version", e.Version())
	if err != nil {
		return []byte{}, err
	}
	eventJSON, err = sjson.SetBytes(eventJSON, "_event_id", e.EventID())
	if err != nil {
		return []byte{}, err
	}
	return eventJSON, nil
}

// populateFieldsFromJSON takes the JSON and populates the event
// fields with it. If the event ID is already known, because the
// event came from storage, then we pass it in here as a means of
// avoiding all of the canonicalisation and reference hash
// calculations etc as they are expensive operations. If the event
// ID isn't known, pass an empty string and we'll work it out.
func (e *event) populateFieldsFromJSON(eventIDIfKnown string, eventJSON []byte) error {
	verImpl, err := GetRoomVersion(e.roomVersion)
	if err != nil {
		return err
	}
	// Work out the format of the event from the room version.
	eventFormat := verImpl.EventFormat()
	if err != nil {
		return err
	}

	switch eventFormat {
	case EventFormatV1:
		e.eventJSON = eventJSON
		// Unmarshal the event fields.
		fields := eventFormatV1Fields{}
		if err := json.Unmarshal(eventJSON, &fields); err != nil {
			return err
		}
		// Populate the fields of the received object.
		fields.fixNilSlices()
		e.fields = fields
		// In room versions 1 and 2, we will use the event_id from the
		// event itself.
		e.eventID = fields.EventID
	case EventFormatV2:
		e.eventJSON = eventJSON
		// Unmarshal the event fields.
		fields := eventFormatV2Fields{}
		if err := json.Unmarshal(eventJSON, &fields); err != nil {
			return err
		}
		// Generate a hash of the event which forms the event ID. There
		// is no event_id field in room versions 3 and later so we will
		// always generate our own.
		if eventIDIfKnown != "" {
			e.eventID = eventIDIfKnown
		} else if e.eventID, err = e.generateEventID(); err != nil {
			return err
		}
		// Populate the fields of the received object.
		fields.fixNilSlices()
		e.fields = fields
	default:
		return errors.New("gomatrixserverlib: room version not supported")
	}

	return nil
}

// Redacted returns whether the event is redacted.
func (e *event) Redacted() bool { return e.redacted }

// Version returns the version of this event
func (e *event) Version() RoomVersion { return e.roomVersion }

// JSON returns the JSON bytes for the event.
func (e *event) JSON() []byte { return e.eventJSON }

// Redact redacts the event.
func (e *event) Redact() {
	if e.redacted {
		return
	}
	verImpl, err := GetRoomVersion(e.roomVersion)
	if err != nil {
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	eventJSON, err := verImpl.RedactEventJSON(e.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.roomVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	if err = e.populateFieldsFromJSON(e.EventID(), eventJSON); err != nil {
		panic(fmt.Errorf("gomatrixserverlib: populateFieldsFromJSON failed %v", err))
	}
	e.redacted = true
}

// SetUnsigned sets the unsigned key of the event.
// Returns a copy of the event with the "unsigned" key set.
func (e *event) SetUnsigned(unsigned interface{}) (PDU, error) {
	var eventAsMap map[string]spec.RawJSON
	var err error
	if err = json.Unmarshal(e.eventJSON, &eventAsMap); err != nil {
		return nil, err
	}
	unsignedJSON, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	eventAsMap["unsigned"] = unsignedJSON
	eventJSON, err := json.Marshal(eventAsMap)
	if err != nil {
		return nil, err
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.roomVersion); err != nil {
		return nil, err
	}
	if err = e.updateUnsignedFields(unsignedJSON); err != nil {
		return nil, err
	}
	result := *e
	result.eventJSON = eventJSON
	return &result, nil
}

// SetUnsignedField takes a path and value to insert into the unsigned dict of
// the event.
// path is a dot separated path into the unsigned dict (see gjson package
// for details on format). In particular some characters like '.' and '*' must
// be escaped.
func (e *event) SetUnsignedField(path string, value interface{}) error {
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
	if err = e.updateUnsignedFields(unsigned); err != nil {
		return err
	}

	e.eventJSON = eventJSON

	return nil
}

// updateUnsignedFields sets the value of the unsigned field and then
// fixes nil slices if needed.
func (e *event) updateUnsignedFields(unsigned []byte) error {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		fields.Unsigned = unsigned
		fields.fixNilSlices()
		e.fields = fields
	case eventFormatV2Fields:
		fields.Unsigned = unsigned
		fields.fixNilSlices()
		e.fields = fields
	default:
		return UnsupportedRoomVersionError{Version: e.roomVersion}
	}
	return nil
}

// Sign returns a copy of the event with an additional signature.
func (e *event) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU {
	eventJSON, err := signEvent(signingName, keyID, privateKey, e.eventJSON, e.roomVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.roomVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	return &event{
		redacted:    e.redacted,
		eventID:     e.eventID,
		eventJSON:   eventJSON,
		fields:      e.fields,
		roomVersion: e.roomVersion,
	}
}

// KeyIDs returns a list of key IDs that the named entity has signed the event with.
func (e *event) KeyIDs(signingName string) []KeyID {
	keyIDs, err := ListKeyIDs(signingName, e.eventJSON)
	if err != nil {
		// This should unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	return keyIDs
}

// StateKey returns the "state_key" of the event, or the nil if the event is not a state event.
func (e *event) StateKey() *string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.StateKey
	case eventFormatV2Fields:
		return fields.StateKey
	default:
		panic(e.invalidFieldType())
	}
}

// StateKeyEquals returns true if the event is a state event and the "state_key" matches.
func (e *event) StateKeyEquals(stateKey string) bool {
	var sk *string
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		sk = fields.StateKey
	case eventFormatV2Fields:
		sk = fields.StateKey
	default:
		panic(e.invalidFieldType())
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
func (e *event) CheckFields() error { // nolint: gocyclo
	var fields eventFields
	switch f := e.fields.(type) {
	case eventFormatV1Fields:
		if f.AuthEvents == nil || f.PrevEvents == nil {
			return errors.New("gomatrixserverlib: auth events and prev events must not be nil")
		}
		fields = f.eventFields
	case eventFormatV2Fields:
		if f.AuthEvents == nil || f.PrevEvents == nil {
			return errors.New("gomatrixserverlib: auth events and prev events must not be nil")
		}
		fields = f.eventFields
	default:
		panic(e.invalidFieldType())
	}

	if l := len(e.eventJSON); l > maxEventLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event is too long, length %d bytes > maximum %d bytes", l, maxEventLength),
		}
	}

	if l := len(fields.Type); l > maxIDLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
		}
	}

	if fields.StateKey != nil {
		if l := len(*fields.StateKey); l > maxIDLength {
			return EventValidationError{
				Code:    EventValidationTooLarge,
				Message: fmt.Sprintf("gomatrixserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			}
		}
	}

	if err := checkID(fields.RoomID, "room", '!'); err != nil {
		return err
	}

	if err := checkID(fields.Sender, "user", '@'); err != nil {
		return err
	}

	return nil
}

func checkID(id, kind string, sigil byte) (err error) {
	if _, err = domainFromID(id); err != nil {
		return
	}
	if id[0] != sigil {
		err = fmt.Errorf(
			"gomatrixserverlib: invalid %s ID, wanted first byte to be '%c' got '%c'",
			kind, sigil, id[0],
		)
		return
	}
	if l := len(id); l > maxIDLength {
		err = EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: %s ID is too long, length %d bytes > maximum %d bytes", kind, l, maxIDLength),
		}
		return
	}
	return
}

func (e *event) generateEventID() (eventID string, err error) {
	verImpl, err := GetRoomVersion(e.roomVersion)
	if err != nil {
		return "", err
	}
	eventFormat := verImpl.EventFormat()
	switch eventFormat {
	case EventFormatV1:
		eventID = e.fields.(eventFormatV1Fields).EventID
	case EventFormatV2:
		var reference eventReference
		reference, err = referenceOfEvent(e.eventJSON, e.roomVersion)
		if err != nil {
			return
		}
		eventID = reference.EventID
	default:
		err = errors.New("gomatrixserverlib: unknown room version")
	}
	return
}

// EventID returns the event ID of the event.
func (e *event) EventID() string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.EventID
	case eventFormatV2Fields:
		return e.eventID
	default:
		panic(e.invalidFieldType())
	}
}

// Sender returns the user ID of the sender of the event.
func (e *event) Sender() string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.Sender
	case eventFormatV2Fields:
		return fields.Sender
	default:
		panic(e.invalidFieldType())
	}
}

// Type returns the type of the event.
func (e *event) Type() string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.Type
	case eventFormatV2Fields:
		return fields.Type
	default:
		panic(e.invalidFieldType())
	}
}

// OriginServerTS returns the unix timestamp when this event was created on the origin server, with millisecond resolution.
func (e *event) OriginServerTS() spec.Timestamp {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.OriginServerTS
	case eventFormatV2Fields:
		return fields.OriginServerTS
	default:
		panic(e.invalidFieldType())
	}
}

// Unsigned returns the object under the 'unsigned' key of the event.
func (e *event) Unsigned() []byte {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.Unsigned
	case eventFormatV2Fields:
		return fields.Unsigned
	default:
		panic(e.invalidFieldType())
	}
}

// Content returns the content JSON of the event.
func (e *event) Content() []byte {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return []byte(fields.Content)
	case eventFormatV2Fields:
		return []byte(fields.Content)
	default:
		panic(e.invalidFieldType())
	}
}

// PrevEventIDs returns the event IDs of the direct ancestors of the event.
func (e *event) PrevEventIDs() []string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		result := make([]string, 0, len(fields.PrevEvents))
		for _, id := range fields.PrevEvents {
			result = append(result, id.EventID)
		}
		return result
	case eventFormatV2Fields:
		return fields.PrevEvents
	default:
		panic(e.invalidFieldType())
	}
}

func (e *event) extractContent(eventType string, content interface{}) error {
	verImpl, err := GetRoomVersion(e.roomVersion)
	if err != nil {
		panic(err)
	}
	eventFormat := verImpl.EventFormat()
	var fields eventFields
	switch eventFormat {
	case EventFormatV1:
		fields = e.fields.(eventFormatV1Fields).eventFields
	case EventFormatV2:
		fields = e.fields.(eventFormatV2Fields).eventFields
	default:
		panic(e.invalidFieldType())
	}
	if fields.Type != eventType {
		return fmt.Errorf("gomatrixserverlib: not a %s event", eventType)
	}
	return json.Unmarshal(fields.Content, &content)
}

// Membership returns the value of the content.membership field if this event
// is an "m.room.member" event.
// Returns an error if the event is not a m.room.member event or if the content
// is not valid m.room.member content.
func (e *event) Membership() (string, error) {
	var content struct {
		Membership string `json:"membership"`
	}
	if err := e.extractContent(spec.MRoomMember, &content); err != nil {
		return "", err
	}
	if e.StateKey() == nil {
		return "", fmt.Errorf("gomatrixserverlib: Membersip() event is not a m.room.member event, missing state key")
	}
	return content.Membership, nil
}

// JoinRule returns the value of the content.join_rule field if this event
// is an "m.room.join_rules" event.
// Returns an error if the event is not a m.room.join_rules event or if the content
// is not valid m.room.join_rules content.
func (e *event) JoinRule() (string, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gomatrixserverlib: JoinRule() event is not a m.room.join_rules event, bad state key")
	}
	var content JoinRuleContent
	if err := e.extractContent(spec.MRoomJoinRules, &content); err != nil {
		return "", err
	}
	return content.JoinRule, nil
}

// HistoryVisibility returns the value of the content.history_visibility field if this event
// is an "m.room.history_visibility" event.
// Returns an error if the event is not a m.room.history_visibility event or if the content
// is not valid m.room.history_visibility content.
func (e *event) HistoryVisibility() (HistoryVisibility, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gomatrixserverlib: HistoryVisibility() event is not a m.room.history_visibility event, bad state key")
	}
	var content HistoryVisibilityContent
	if err := e.extractContent(spec.MRoomHistoryVisibility, &content); err != nil {
		return "", err
	}
	return content.HistoryVisibility, nil
}

// PowerLevels returns the power levels content if this event
// is an "m.room.power_levels" event.
// Returns an error if the event is not a m.room.power_levels event or if the content
// is not valid m.room.power_levels content.
func (e *event) PowerLevels() (*PowerLevelContent, error) {
	if !e.StateKeyEquals("") {
		return nil, fmt.Errorf("gomatrixserverlib: PowerLevels() event is not a m.room.power_levels event, bad state key")
	}
	c, err := NewPowerLevelContentFromEvent(e)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// AuthEventIDs returns the event IDs of the events needed to auth the event.
func (e *event) AuthEventIDs() []string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		result := make([]string, 0, len(fields.AuthEvents))
		for _, id := range fields.AuthEvents {
			result = append(result, id.EventID)
		}
		return result
	case eventFormatV2Fields:
		return fields.AuthEvents
	default:
		panic(e.invalidFieldType())
	}
}

// Redacts returns the event ID of the event this event redacts.
func (e *event) Redacts() string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.Redacts
	case eventFormatV2Fields:
		return fields.Redacts
	default:
		panic(e.invalidFieldType())
	}
}

// RoomID returns the room ID of the room the event is in.
func (e *event) RoomID() string {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.RoomID
	case eventFormatV2Fields:
		return fields.RoomID
	default:
		panic(e.invalidFieldType())
	}
}

// Depth returns the depth of the event.
func (e *event) Depth() int64 {
	switch fields := e.fields.(type) {
	case eventFormatV1Fields:
		return fields.Depth
	case eventFormatV2Fields:
		return fields.Depth
	default:
		panic(e.invalidFieldType())
	}
}

// MarshalJSON implements json.Marshaller
func (e event) MarshalJSON() ([]byte, error) {
	if e.eventJSON == nil {
		return nil, fmt.Errorf("gomatrixserverlib: cannot serialise uninitialised Event")
	}
	return e.eventJSON, nil
}

// SplitID splits a matrix ID into a local part and a server name.
func SplitID(sigil byte, id string) (local string, domain spec.ServerName, err error) {
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
	return parts[0][1:], spec.ServerName(parts[1]), nil
}

// fixNilSlices corrects cases where nil slices end up with "null" in the
// marshalled JSON because Go stupidly doesn't care about the type in this
// situation.
func (e *eventFormatV1Fields) fixNilSlices() {
	if e.AuthEvents == nil {
		e.AuthEvents = []eventReference{}
	}
	if e.PrevEvents == nil {
		e.PrevEvents = []eventReference{}
	}
}

// fixNilSlices corrects cases where nil slices end up with "null" in the
// marshalled JSON because Go stupidly doesn't care about the type in this
// situation.
func (e *eventFormatV2Fields) fixNilSlices() {
	if e.AuthEvents == nil {
		e.AuthEvents = []string{}
	}
	if e.PrevEvents == nil {
		e.PrevEvents = []string{}
	}
}

// invalidFieldType is used to generate something semi-helpful when panicing.
func (e *event) invalidFieldType() string {
	if e == nil {
		return "gomatrixserverlib: attempt to call function on nil event"
	}
	if e.fields == nil {
		return fmt.Sprintf("gomatrixserverlib: event has no fields (room version %q)", e.roomVersion)
	}
	return fmt.Sprintf("gomatrixserverlib: field type %q invalid", reflect.TypeOf(e.fields).Name())
}
