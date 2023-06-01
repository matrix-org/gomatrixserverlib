package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
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

func newEventFromUntrustedJSONV2(eventJSON []byte, roomVersion IRoomVersion) (result PDU, err error) {
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

	res := &eventV2{}
	res.roomVersion = roomVersion.Version()

	if eventJSON, err = sjson.DeleteBytes(eventJSON, "unsigned"); err != nil {
		return
	}

	if eventJSON, err = sjson.DeleteBytes(eventJSON, "event_id"); err != nil {
		return
	}

	if err = json.Unmarshal(eventJSON, &res); err != nil {
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

	res.eventJSON = eventJSON

	if err = checkEventContentHash(eventJSON); err != nil {
		res.redacted = true

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
			if result, err = newEventFromTrustedJSONV2(redactedJSON, true, roomVersion); err != nil {
				return
			}
		}
	}

	err = CheckFieldsV2(*res)

	return res, err
}

func CheckFieldsV2(input eventV2) error { // nolint: gocyclo
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

func newEventFromTrustedJSONV2(eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result PDU, err error) {
	res := &eventV2{}
	res.roomVersion = roomVersion.Version()
	res.redacted = redacted
	if err := json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
	}
	return res, nil
}

func newEventFromTrustedJSONWithEventIDV2(eventID string, eventJSON []byte, redacted bool, roomVersion IRoomVersion) (result PDU, err error) {
	res := &eventV2{}
	res.roomVersion = roomVersion.Version()
	res.redacted = redacted
	if err := json.Unmarshal(eventJSON, &result); err != nil {
		return nil, err
	}
	res.EventIDRaw = eventID
	return res, nil
}
