package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

type eventV1 struct {
	redacted    bool
	eventJSON   []byte
	roomVersion RoomVersion

	eventFields

	EventIDRaw string           `json:"event_id,omitempty"`
	PrevEvents []eventReference `json:"prev_events"`
	AuthEvents []eventReference `json:"auth_events"`
}

func newEventFromUntrustedJSONV1(eventJSON []byte, roomVersion IRoomVersion) (result *eventV1, err error) {
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

	result = &eventV1{}
	result.roomVersion = roomVersion.Version()

	if eventJSON, err = sjson.DeleteBytes(eventJSON, "unsigned"); err != nil {
		return
	}

	if err := json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
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

	result.eventJSON = eventJSON

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
			if result, err = newEventFromTrustedJSONV1(redactedJSON, true, roomVersion); err != nil {
				return
			}
		}
	}

	err = CheckFieldsV1(*result)

	return
}

func CheckFieldsV1(input eventV1) error { // nolint: gocyclo
	if input.AuthEvents == nil || input.PrevEvents == nil {
		return errors.New("gomatrixserverlib: auth events and prev events must not be nil")
	}

	if l := len(input.eventJSON); l > maxEventLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event is too long, length %d bytes > maximum %d bytes", l, maxEventLength),
		}
	}

	if l := len(input.eventFields.Type); l > maxIDLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
		}
	}

	if input.eventFields.StateKey != nil {
		if l := len(*input.eventFields.StateKey); l > maxIDLength {
			return EventValidationError{
				Code:    EventValidationTooLarge,
				Message: fmt.Sprintf("gomatrixserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			}
		}
	}

	if err := checkID(input.eventFields.RoomID, "room", '!'); err != nil {
		return err
	}

	if err := checkID(input.eventFields.Sender, "user", '@'); err != nil {
		return err
	}

	return nil
}

func newEventFromTrustedJSONV1(eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result *eventV1, err error) {
	result = &eventV1{}
	result.roomVersion = roomVersion.Version()
	result.redacted = redacted
	if err := json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
	}
	return
}

func newEventFromTrustedJSONWithEventIDV1(eventID string, eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result *eventV1, err error) {
	result = &eventV1{}
	result.roomVersion = roomVersion.Version()
	result.redacted = redacted
	if err := json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
	}
	result.EventIDRaw = eventID
	return
}

func (e *eventV1) EventID() string {
	return e.EventIDRaw
}

func (e *eventV1) StateKey() *string {
	return e.eventFields.StateKey
}

func (e *eventV1) StateKeyEquals(s string) bool {
	if e.eventFields.StateKey == nil {
		return false
	}
	return *e.eventFields.StateKey == s
}

func (e *eventV1) Type() string {
	return e.eventFields.Type
}

func (e *eventV1) Content() []byte {
	return e.eventFields.Content
}

func (e *eventV1) JoinRule() (string, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gomatrixserverlib: JoinRule() event is not a m.room.join_rules event, bad state key")
	}
	var content JoinRuleContent
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	return content.JoinRule, nil
}

func (e *eventV1) HistoryVisibility() (HistoryVisibility, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gomatrixserverlib: HistoryVisibility() event is not a m.room.history_visibility event, bad state key")
	}
	var content HistoryVisibilityContent
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	return content.HistoryVisibility, nil
}

func (e *eventV1) Membership() (string, error) {
	var content struct {
		Membership string `json:"membership"`
	}
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	if e.StateKey() == nil {
		return "", fmt.Errorf("gomatrixserverlib: Membersip() event is not a m.room.member event, missing state key")
	}
	return content.Membership, nil
}

func (e *eventV1) PowerLevels() (*PowerLevelContent, error) {
	if !e.StateKeyEquals("") {
		return nil, fmt.Errorf("gomatrixserverlib: PowerLevels() event is not a m.room.power_levels event, bad state key")
	}
	c, err := NewPowerLevelContentFromEvent(e)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (e *eventV1) Version() RoomVersion {
	return e.roomVersion
}

func (e *eventV1) RoomID() string {
	return e.eventFields.RoomID
}

func (e *eventV1) Redacts() string {
	return e.eventFields.Redacts
}

func (e *eventV1) Redacted() bool {
	return e.redacted
}

func (e *eventV1) PrevEventIDs() []string {
	result := make([]string, 0, len(e.PrevEvents))
	for _, id := range e.PrevEvents {
		result = append(result, id.EventID)
	}
	return result
}

func (e *eventV1) OriginServerTS() spec.Timestamp {
	return e.eventFields.OriginServerTS
}

func (e *eventV1) Redact() {
	eventJSON, err := redactEventJSONV1(e.eventJSON)
	if err != nil {
		panic(err)
	}
	e.eventJSON = eventJSON
}

func (e *eventV1) Sender() string {
	return e.eventFields.Sender
}

func (e *eventV1) Unsigned() []byte {
	return e.eventFields.Unsigned
}

func (e *eventV1) SetUnsigned(unsigned interface{}) (PDU, error) {
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
	e.eventFields.Unsigned = unsignedJSON
	result := *e
	result.eventJSON = eventJSON
	return &result, nil
}

func (e *eventV1) SetUnsignedField(path string, value interface{}) error {
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
	e.eventFields.Unsigned = unsigned

	e.eventJSON = eventJSON

	return nil
}

func (e *eventV1) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU {
	eventJSON, err := signEvent(signingName, keyID, privateKey, e.eventJSON, e.roomVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.roomVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	return &eventV1{
		redacted:    e.redacted,
		EventIDRaw:  e.EventIDRaw,
		eventJSON:   eventJSON,
		roomVersion: e.roomVersion,
	}
}

func (e *eventV1) Depth() int64 {
	return e.eventFields.Depth
}

func (e *eventV1) JSON() []byte {
	return e.eventJSON
}

func (e *eventV1) AuthEventIDs() []string {
	result := make([]string, 0, len(e.AuthEvents))
	for _, id := range e.AuthEvents {
		result = append(result, id.EventID)
	}
	return result
}

func (e *eventV1) ToHeaderedJSON() ([]byte, error) {
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
