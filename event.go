/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, RoomVersion 2.0 (the "License");
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
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

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
	PrevEvents json.RawMessage `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	AuthEvents json.RawMessage `json:"auth_events"`
	// The event ID of the event being redacted if this event is a "m.room.redaction".
	Redacts string `json:"redacts,omitempty"`
	// The depth of the event, This should be one greater than the maximum depth of the previous events.
	// The create event has a depth of 1.
	Depth int64 `json:"depth"`
	// The JSON object for "signatures" key of the event.
	Signature json.RawMessage `json:"signatures,omitempty"`
	// The JSON object for "content" key of the event.
	Content json.RawMessage `json:"content"`
	// The JSON object for the "unsigned" key
	Unsigned json.RawMessage `json:"unsigned,omitempty"`

	// The EventID of this event
	EventID string `json:"event_id,omitempty"`

	// The origin server timestamp
	OriginServerTS spec.Timestamp `json:"origin_server_ts,omitempty"`
	// The origin server
	Origin spec.ServerName `json:"origin,omitempty"`

	// This key is either absent or an empty list.
	// If it is absent then the pointer is nil and omitempty removes it.
	// Otherwise it points to an empty list and omitempty keeps it.
	PrevState *[]EventReference `json:"prev_state,omitempty"`

	// internally used fields
	roomVersion RoomVersion     `json:"-"`
	redacted    bool            `json:"-"`
	eventJSON   json.RawMessage `json:"-"`
}

func (pe *ProtoEvent) GetEventID() string {
	// If the eventID is already set, return that
	if pe.EventID != "" {
		return pe.EventID
	}

	// calculate the eventID
	var reference EventReference
	reference, err := referenceOfEvent(pe.eventJSON, pe.roomVersion)
	if err != nil {
		return ""
	}
	pe.EventID = reference.EventID

	return pe.EventID
}

// MarshalJSON implements json.Marshaller

func (pe *ProtoEvent) MarshalJSON() ([]byte, error) {
	if pe.eventJSON == nil {
		var temp ProtoEvent
		if pe.PrevEvents == nil {
			pe.PrevEvents, _ = json.Marshal([]string{})
		}
		if pe.AuthEvents == nil {
			pe.AuthEvents, _ = json.Marshal([]string{})
		}
		switch pe.roomVersion {
		case RoomVersionV1, RoomVersionV2:
		default:
			var refs []EventReference
			if err := json.Unmarshal(pe.PrevEvents, &refs); err == nil {
				eventIDs := make([]string, 0, len(refs))
				for _, ref := range refs {
					eventIDs = append(eventIDs, ref.EventID)
				}
				pe.PrevEvents, _ = json.Marshal(eventIDs)
			}
			if err := json.Unmarshal(pe.AuthEvents, &refs); err == nil {
				eventIDs := make([]string, 0, len(refs))
				for _, ref := range refs {
					eventIDs = append(eventIDs, ref.EventID)
				}
				pe.AuthEvents, _ = json.Marshal(eventIDs)
			}
		}
		temp = *pe
		return json.Marshal(temp)
	}
	return pe.eventJSON, nil
}

func (pe *ProtoEvent) GetStateKey() *string {
	return pe.StateKey
}

func (pe *ProtoEvent) StateKeyEquals(stateKey string) bool {
	if pe.StateKey == nil {
		return false
	}
	return *pe.StateKey == stateKey
}

func (pe *ProtoEvent) GetType() string {
	return pe.Type
}

func (pe *ProtoEvent) GetContent() []byte {
	return pe.Content
}

func (pe *ProtoEvent) JoinRule() (string, error) {
	if !pe.StateKeyEquals("") {
		return "", fmt.Errorf("gomatrixserverlib: JoinRule() event is not a m.room.join_rules event, bad state key")
	}
	var content JoinRuleContent
	if err := json.Unmarshal(pe.Content, &content); err != nil {
		return "", err
	}
	return content.JoinRule, nil
}

func (pe *ProtoEvent) HistoryVisibility() (HistoryVisibility, error) {
	if !pe.StateKeyEquals("") {
		return "", fmt.Errorf("gomatrixserverlib: HistoryVisibility() event is not a m.room.history_visibility event, bad state key")
	}
	var content HistoryVisibilityContent
	if err := json.Unmarshal(pe.Content, &content); err != nil {
		return "", err
	}
	return content.HistoryVisibility, nil
}

func (pe *ProtoEvent) Membership() (string, error) {
	if pe.GetStateKey() == nil {
		return "", fmt.Errorf("gomatrixserverlib: Membersip() event is not a m.room.member event, missing state key")
	}
	var content struct {
		Membership string `json:"membership"`
	}
	if err := json.Unmarshal(pe.Content, &content); err != nil {
		return "", err
	}
	return content.Membership, nil
}

func (pe *ProtoEvent) PowerLevels() (*PowerLevelContent, error) {
	if !pe.StateKeyEquals("") {
		return nil, fmt.Errorf("gomatrixserverlib: PowerLevels() event is not a m.room.power_levels event, bad state key")
	}
	c, err := NewPowerLevelContentFromEvent(pe)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (pe *ProtoEvent) RoomVersion() RoomVersion {
	return pe.roomVersion
}

func (pe *ProtoEvent) GetRoomID() string {
	return pe.RoomID
}

func (pe *ProtoEvent) GetRedacts() string {
	return pe.Redacts
}

func (pe *ProtoEvent) IsRedacted() bool {
	return pe.redacted
}

func (pe *ProtoEvent) Build(now time.Time, origin spec.ServerName, keyID KeyID, privateKey ed25519.PrivateKey) (result PDU, err error) {
	if pe.roomVersion == "" {
		return nil, fmt.Errorf("EventBuilderV1.Build: unknown version, did you create this via NewEventBuilder?")
	}

	verImpl := MustGetRoomVersion(pe.roomVersion)
	eventIDFormat := verImpl.EventIDFormat()

	if eventIDFormat == EventIDFormatV1 {
		pe.EventID = fmt.Sprintf("$%s:%s", util.RandomString(16), origin)
	} else {
		pe.EventID = ""
	}
	pe.OriginServerTS = spec.AsTimestamp(now)
	pe.Origin = origin

	// If either prev_events or auth_events are nil slices then Go will
	// marshal them into 'null' instead of '[]', which is bad. Since the
	// EventBuilderV1 struct is instantiated outside of gomatrixserverlib
	// let's just make sure that they haven't been left as nil slices.

	if pe.StateKey != nil {
		// In early versions of the matrix protocol state events
		// had a "prev_state" key that listed the state events with
		// the same type and state key that this event replaced.
		// This was later dropped from the protocol.
		// Synapse ignores the contents of the key but still expects
		// the key to be present in state events.
		pe.PrevState = &emptyEventReferenceList
	}

	var eventJSON []byte
	if eventJSON, err = json.Marshal(&pe); err != nil {
		return
	}

	if eventJSON, err = addContentHashesToEvent(eventJSON); err != nil {
		return
	}

	if eventJSON, err = signEvent(string(origin), keyID, privateKey, eventJSON, pe.roomVersion); err != nil {
		return
	}

	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, pe.roomVersion); err != nil {
		return
	}

	pe.eventJSON = eventJSON

	if err != nil {
		return nil, err
	}

	if err = checkFields(pe, eventJSON); err != nil {
		return
	}
	return pe, nil
}

func (pe *ProtoEvent) GetPrevEventIDs() []string {
	var refs []EventReference
	if err := json.Unmarshal(pe.PrevEvents, &refs); err == nil {
		result := make([]string, 0, len(refs))
		for _, ref := range refs {
			result = append(result, ref.EventID)
		}
		return result
	}
	var result []string
	if err := json.Unmarshal(pe.PrevEvents, &result); err != nil {
		return []string{}
	}
	return result
}

func (pe *ProtoEvent) GetPrevEvents() []EventReference {
	var refs []EventReference
	if err := json.Unmarshal(pe.PrevEvents, &refs); err == nil {
		return refs
	}
	return []EventReference{}
}

func (pe *ProtoEvent) GetOriginServerTS() spec.Timestamp {
	return pe.OriginServerTS
}

func (pe *ProtoEvent) Redact() {
	if pe.redacted {
		return
	}
	verImpl, err := GetRoomVersion(pe.roomVersion)
	if err != nil {
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	eventJSON, err := verImpl.RedactEventJSON(pe.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilderV1.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, pe.roomVersion); err != nil {
		// This is unreachable for events created with EventBuilderV1.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v", err))
	}

	_ = json.Unmarshal(eventJSON, &pe)
	pe.eventJSON = eventJSON
	pe.redacted = true
}

func (pe *ProtoEvent) GetSender() string {
	return pe.Sender
}

func (pe *ProtoEvent) GetUnsigned() []byte {
	return pe.Unsigned
}

func (pe *ProtoEvent) SetUnsigned(unsigned interface{}) (PDU, error) {
	var eventAsMap map[string]json.RawMessage
	var err error
	if err = json.Unmarshal(pe.eventJSON, &eventAsMap); err != nil {
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
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, pe.roomVersion); err != nil {
		return nil, err
	}
	pe.Unsigned = unsignedJSON
	result := *pe
	result.eventJSON = eventJSON
	return &result, nil
}

func (pe *ProtoEvent) SetUnsignedField(path string, value interface{}) error {
	path = "unsigned." + path
	eventJSON, err := sjson.SetBytes(pe.eventJSON, path, value)
	if err != nil {
		return err
	}
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	res := gjson.GetBytes(eventJSON, "unsigned")
	unsigned := RawJSONFromResult(res, eventJSON)

	pe.Unsigned = unsigned

	pe.eventJSON = eventJSON
	return nil
}

func (pe *ProtoEvent) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU {
	eventJSON, err := signEvent(signingName, keyID, privateKey, pe.eventJSON, pe.roomVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(pe.eventJSON)))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, pe.roomVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(pe.eventJSON)))
	}
	return &ProtoEvent{
		redacted:    pe.redacted,
		EventID:     pe.EventID,
		eventJSON:   eventJSON,
		roomVersion: pe.roomVersion,
	}
}

func (pe *ProtoEvent) EventReference() EventReference {
	reference, err := referenceOfEvent(pe.eventJSON, pe.roomVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilderV1.Build or NewEventFromUntrustedJSON
		// This can be reached if NewEventFromTrustedJSON is given JSON from an untrusted source.
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(pe.eventJSON)))
	}
	return reference
}

func (pe *ProtoEvent) GetDepth() int64 {
	return pe.Depth
}

func (pe *ProtoEvent) JSON() []byte {
	return pe.eventJSON
}

func (pe *ProtoEvent) GetAuthEventIDs() []string {

	var refs []EventReference
	if err := json.Unmarshal(pe.AuthEvents, &refs); err == nil {
		result := make([]string, 0, len(refs))
		for _, ref := range refs {
			result = append(result, ref.EventID)
		}
		return result
	}
	var result []string
	if err := json.Unmarshal(pe.AuthEvents, &result); err != nil {
		return nil
	}
	return result
}

func (pe *ProtoEvent) ToHeaderedJSON() ([]byte, error) {
	var err error
	eventJSON := pe.JSON()
	eventJSON, err = sjson.SetBytes(eventJSON, "_room_version", pe.RoomVersion())
	if err != nil {
		return []byte{}, err
	}
	eventJSON, err = sjson.SetBytes(eventJSON, "_event_id", pe.GetEventID())
	if err != nil {
		return []byte{}, err
	}
	return eventJSON, nil
}

func (pe *ProtoEvent) SetContent(content any) (err error) {
	pe.Content, err = json.Marshal(content)
	return
}

func (pe *ProtoEvent) SetPrevEvents(prevEvents []EventReference) (err error) {
	switch pe.roomVersion {
	case RoomVersionV1, RoomVersionV2:
		pe.PrevEvents, err = json.Marshal(prevEvents)
		return
	}

	eventIDs := make([]string, 0, len(prevEvents))
	for _, ref := range prevEvents {
		eventIDs = append(eventIDs, ref.EventID)
	}
	pe.PrevEvents, err = json.Marshal(eventIDs)

	return
}

func (pe *ProtoEvent) SetAuthEvents(authEvents []EventReference) (err error) {
	switch pe.roomVersion {
	case RoomVersionV1, RoomVersionV2:
		pe.AuthEvents, err = json.Marshal(authEvents)
		return
	}

	eventIDs := make([]string, 0, len(authEvents))
	for _, ref := range authEvents {
		eventIDs = append(eventIDs, ref.EventID)
	}
	pe.AuthEvents, err = json.Marshal(eventIDs)

	return
}

func (pe *ProtoEvent) AddAuthEvents(provider AuthEventProvider) error {
	eventsNeeded, err := StateNeededForProtoEvent(&ProtoEvent{
		Type:     pe.Type,
		StateKey: pe.StateKey,
		Content:  pe.Content,
		Sender:   pe.Sender,
	})
	if err != nil {
		return err
	}

	refs, err := eventsNeeded.AuthEventReferences(provider)
	if err != nil {
		return err
	}

	return pe.SetAuthEvents(refs)
}

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

var emptyEventReferenceList = []EventReference{}

// newEventFromUntrustedJSON loads a new event from some JSON that may be invalid.
// This checks that the event is valid JSON.
// It also checks the content hashes to ensure the event has not been tampered with.
// This should be used when receiving new events from remote servers.
func newEventFromUntrustedJSON(eventJSON []byte, roomVersion IRoomVersion) (result *ProtoEvent, err error) {
	if r := gjson.GetBytes(eventJSON, "_*"); r.Exists() {
		err = fmt.Errorf("gomatrixserverlib NewEventFromUntrustedJSON: found top-level '_' key, is this a headered event: %v", string(eventJSON))
		return
	}
	if roomVersion.EnforceCanonicalJSON() {
		if err = verifyEnforcedCanonicalJSON(eventJSON); err != nil {
			err = BadJSONError{err}
			return
		}
	}

	result = &ProtoEvent{}
	result.roomVersion = roomVersion.Version()

	if eventJSON, err = sjson.DeleteBytes(eventJSON, "unsigned"); err != nil {
		return
	}

	if err = json.Unmarshal(eventJSON, &result); err != nil {
		return
	}

	switch MustGetRoomVersion(result.roomVersion).Version() {
	case RoomVersionV1, RoomVersionV2:
	default:
		result.EventID = ""
		// If we have an EBv2, also verify prev/auth_events
		var refs []EventReference
		if err = json.Unmarshal(result.AuthEvents, &refs); err == nil && len(refs) > 0 {
			return nil, fmt.Errorf("unexpected event reference")
		}
		if err = json.Unmarshal(result.PrevEvents, &refs); err == nil && len(refs) > 0 {
			return nil, fmt.Errorf("unexpected event reference")
		}
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

	err = checkFields(result, eventJSON)
	result.eventJSON = eventJSON
	return
}

// newEventFromTrustedJSON loads a new event from some JSON that must be valid.
// This will be more efficient than NewEventFromUntrustedJSON since it can skip cryptographic checks.
// This can be used when loading matrix events from a local database.
func newEventFromTrustedJSON(eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result *ProtoEvent, err error) {
	result = &ProtoEvent{}
	result.roomVersion = roomVersion.Version()
	result.redacted = redacted
	result.EventID = ""
	if err = json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
	}
	result.eventJSON = eventJSON
	return
}

// newEventFromTrustedJSONWithEventID loads a new event from some JSON that must be valid
// and that the event ID is already known. This must ONLY be used when retrieving
// an event from the database and NEVER when accepting an event over federation.
// This will be more efficient than NewEventFromTrustedJSON since, if the event
// ID is known, we skip all the reference hash and canonicalisation work.
func newEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result *ProtoEvent, err error) {
	result = &ProtoEvent{}
	result.roomVersion = roomVersion.Version()
	result.redacted = redacted
	if err = json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
	}
	if result.EventID == "" {
		result.EventID = eventID
	}
	result.eventJSON = eventJSON
	return
}

const (
	// The event ID, room ID, GetSender, event type and state key fields cannot be
	// bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L173-L182
	maxIDLength = 255
	// The entire event JSON, including signatures cannot be bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L183-184
	maxEventLength = 65536
)

// checkFields checks that the event fields are valid.
// Returns an error if the IDs have the wrong format or too long.
// Returns an error if the total length of the event JSON is too long.
// Returns an error if the event ID doesn't match the origin of the event.
// https://matrix.org/docs/spec/client_server/r0.2.0.html#size-limits
func checkFields(p PDU, eventJSON []byte) error { // nolint: gocyclo

	if l := len(eventJSON); l > maxEventLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event is too long, length %d bytes > maximum %d bytes", l, maxEventLength),
		}
	}

	if l := len(p.GetType()); l > maxIDLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
		}
	}

	if p.GetStateKey() != nil {
		if l := len(*p.GetStateKey()); l > maxIDLength {
			return EventValidationError{
				Code:    EventValidationTooLarge,
				Message: fmt.Sprintf("gomatrixserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			}
		}
	}

	if err := checkID(p.GetRoomID(), "room", '!'); err != nil {
		return err
	}

	if err := checkID(p.GetSender(), "user", '@'); err != nil {
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
