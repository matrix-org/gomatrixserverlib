package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

type eventV2 struct {
	eventV1
	PrevEvents []string `json:"prev_events"`
	AuthEvents []string `json:"auth_events"`
}

func (e *eventV2) PrevEventIDs() []string {
	return e.PrevEvents
}

func (e *eventV2) AuthEventIDs() []string {
	return e.AuthEvents
}

// MarshalJSON implements json.Marshaller
func (e *eventV2) MarshalJSON() ([]byte, error) {
	if e.eventJSON == nil {
		return nil, fmt.Errorf("gomatrixserverlib: cannot serialise uninitialised Event")
	}
	return e.eventJSON, nil
}

func (e *eventV2) SetUnsigned(unsigned interface{}) (PDU, error) {
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
	result := *e
	result.eventJSON = eventJSON
	result.eventFields.Unsigned = unsignedJSON
	return &result, nil
}

func (e *eventV2) SenderID() spec.SenderID {
	return spec.SenderID(e.eventFields.SenderID)
}

func (e *eventV2) EventID() string {
	// if we already generated the eventID, don't do it again
	if e.EventIDRaw != "" {
		return e.EventIDRaw
	}
	ref, err := referenceOfEvent(e.eventJSON, e.roomVersion)
	if err != nil {
		panic(fmt.Errorf("failed to generate reference of event: %w", err))
	}
	e.EventIDRaw = ref.EventID
	return ref.EventID
}

func (e *eventV2) Redact() {
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
	var res eventV2
	err = json.Unmarshal(eventJSON, &res)
	if err != nil {
		panic(fmt.Errorf("gomatrixserverlib: Redact failed %v", err))
	}
	res.redacted = true
	res.eventJSON = eventJSON
	res.roomVersion = e.roomVersion
	*e = res
}

func (e *eventV2) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU {
	eventJSON, err := signEvent(signingName, keyID, privateKey, e.eventJSON, e.roomVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.roomVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gomatrixserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	res := &e
	(*res).eventJSON = eventJSON
	return *res
}

func newEventFromUntrustedJSONV2(eventJSON []byte, roomVersion IRoomVersion) (PDU, error) {
	if r := gjson.GetBytes(eventJSON, "_*"); r.Exists() {
		return nil, fmt.Errorf("gomatrixserverlib NewEventFromUntrustedJSON: found top-level '_' key, is this a headered event: %v", string(eventJSON))
	}
	if err := roomVersion.CheckCanonicalJSON(eventJSON); err != nil {
		return nil, BadJSONError{err}
	}

	res := &eventV2{}
	var err error
	// Synapse removes these keys from events in case a server accidentally added them.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/crypto/event_signing.py#L57-L62
	for _, key := range []string{"outlier", "destinations", "age_ts", "unsigned", "event_id"} {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, key); err != nil {
			return nil, err
		}
	}

	if err = json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}

	if err := checkID(res.eventFields.RoomID, "room", '!'); err != nil {
		return nil, err
	}

	res.roomVersion = roomVersion.Version()

	// We know the JSON must be valid here.
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	res.eventJSON = eventJSON

	if err = checkEventContentHash(eventJSON); err != nil {
		res.redacted = true

		// If the content hash doesn't match then we have to discard all non-essential fields
		// because they've been tampered with.
		var redactedJSON []byte
		if redactedJSON, err = roomVersion.RedactEventJSON(eventJSON); err != nil {
			return nil, err
		}

		redactedJSON = CanonicalJSONAssumeValid(redactedJSON)

		// We need to ensure that `result` is the redacted event.
		// If redactedJSON is the same as eventJSON then `result` is already
		// correct. If not then we need to reparse.
		//
		// Yes, this means that for some events we parse twice (which is slow),
		// but means that parsing unredacted events is fast.
		if !bytes.Equal(redactedJSON, eventJSON) {
			result, err := roomVersion.NewEventFromTrustedJSON(redactedJSON, true)
			if err != nil {
				return nil, err
			}
			err = CheckFields(result)
			return result, err
		}
	}

	err = CheckFields(res)

	return res, err
}

var lenientByteLimitRoomVersions = map[RoomVersion]struct{}{
	RoomVersionV1:        {},
	RoomVersionV2:        {},
	RoomVersionV3:        {},
	RoomVersionV4:        {},
	RoomVersionV5:        {},
	RoomVersionV6:        {},
	RoomVersionV7:        {},
	RoomVersionV8:        {},
	RoomVersionV9:        {},
	RoomVersionV10:       {},
	RoomVersionV11:       {},
	RoomVersionPseudoIDs: {},
	"org.matrix.msc3787": {},
	"org.matrix.msc3667": {},
}

func CheckFields(input PDU) error { // nolint: gocyclo
	if input.AuthEventIDs() == nil || input.PrevEventIDs() == nil {
		return errors.New("gomatrixserverlib: auth events and prev events must not be nil")
	}
	if l := len(input.JSON()); l > maxEventLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event is too long, length %d bytes > maximum %d bytes", l, maxEventLength),
		}
	}

	// Compatibility to Synapse and older rooms. This was always enforced by Synapse
	if l := utf8.RuneCountInString(input.Type()); l > maxIDLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
		}
	}

	if input.StateKey() != nil {
		if l := utf8.RuneCountInString(*input.StateKey()); l > maxIDLength {
			return EventValidationError{
				Code:    EventValidationTooLarge,
				Message: fmt.Sprintf("gomatrixserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			}
		}
	}

	_, persistable := lenientByteLimitRoomVersions[input.Version()]

	// Byte size check: if these fail, then be lenient to avoid breaking rooms.
	if l := len(input.Type()); l > maxIDLength {
		return EventValidationError{
			Code:        EventValidationTooLarge,
			Message:     fmt.Sprintf("gomatrixserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			Persistable: persistable,
		}
	}

	if input.StateKey() != nil {
		if l := len(*input.StateKey()); l > maxIDLength {
			return EventValidationError{
				Code:        EventValidationTooLarge,
				Message:     fmt.Sprintf("gomatrixserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
				Persistable: persistable,
			}
		}
	}

	switch input.Version() {
	case RoomVersionPseudoIDs:
	default:
		if err := checkID(string(input.SenderID()), "user", '@'); err != nil {
			return err
		}
	}

	return nil
}

func newEventFromTrustedJSONV2(eventJSON []byte, redacted bool, roomVersion IRoomVersion) (PDU, error) {
	res := eventV2{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}

	if err := checkID(res.eventFields.RoomID, "room", '!'); err != nil {
		return nil, err
	}

	res.roomVersion = roomVersion.Version()
	res.redacted = redacted
	res.eventJSON = eventJSON
	return &res, nil
}

func newEventFromTrustedJSONWithEventIDV2(eventID string, eventJSON []byte, redacted bool, roomVersion IRoomVersion) (PDU, error) {
	res := &eventV2{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}

	if err := checkID(res.eventFields.RoomID, "room", '!'); err != nil {
		return nil, err
	}

	res.roomVersion = roomVersion.Version()
	res.eventJSON = eventJSON
	res.EventIDRaw = eventID
	res.redacted = redacted
	return res, nil
}
