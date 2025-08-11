package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type eventV3 struct {
	eventV2
}

func (e *eventV3) RoomID() spec.RoomID {
	roomIDStr := e.eventFields.RoomID
	isCreateEvent := e.Type() == spec.MRoomCreate && e.StateKeyEquals("")
	if isCreateEvent {
		roomIDStr = fmt.Sprintf("!%s", e.EventID()[1:])
	}
	roomID, err := spec.NewRoomID(roomIDStr)
	if err != nil {
		panic(fmt.Errorf("RoomID is invalid: %w", err))
	}
	return *roomID
}

func (e *eventV3) AuthEventIDs() []string {
	isCreateEvent := e.Type() == spec.MRoomCreate && e.StateKeyEquals("")
	if isCreateEvent {
		return []string{}
	}
	createEventID := fmt.Sprintf("$%s", e.eventFields.RoomID[1:])
	if len(e.AuthEvents) > 0 {
		// always include the create event
		return append([]string{createEventID}, e.AuthEvents...)
	}
	return []string{createEventID}
}

func newEventFromUntrustedJSONV3(eventJSON []byte, roomVersion IRoomVersion) (PDU, error) {
	if r := gjson.GetBytes(eventJSON, "_*"); r.Exists() {
		return nil, fmt.Errorf("gomatrixserverlib NewEventFromUntrustedJSON: found top-level '_' key, is this a headered event: %v", string(eventJSON))
	}
	if err := roomVersion.CheckCanonicalJSON(eventJSON); err != nil {
		return nil, BadJSONError{err}
	}

	res := &eventV3{}
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

	// v3 events have room IDs as the create event ID.
	// TODO: allow validation to be enhanced/relaxed to help users like Complement.
	if err := checkRoomID(res); err != nil {
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

func newEventFromTrustedJSONV3(eventJSON []byte, redacted bool, roomVersion IRoomVersion) (PDU, error) {
	res := eventV3{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}

	// v3 events have room IDs as the create event ID.
	// TODO: allow validation to be enhanced/relaxed to help users like Complement.
	// TODO: feels weird to only have this validation here and not length checks etc :S
	if err := checkRoomID(&res); err != nil {
		return nil, err
	}

	res.roomVersion = roomVersion.Version()
	res.redacted = redacted
	res.eventJSON = eventJSON
	return &res, nil
}

func newEventFromTrustedJSONWithEventIDV3(eventID string, eventJSON []byte, redacted bool, roomVersion IRoomVersion) (PDU, error) {
	res := &eventV3{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}

	// v3 events have room IDs as the create event ID.
	// TODO: allow validation to be enhanced/relaxed to help users like Complement.
	if err := checkRoomID(res); err != nil {
		return nil, err
	}

	res.roomVersion = roomVersion.Version()
	res.eventJSON = eventJSON
	res.EventIDRaw = eventID
	res.redacted = redacted
	return res, nil
}

func checkRoomID(res *eventV3) error {
	isCreateEvent := res.Type() == spec.MRoomCreate && res.StateKeyEquals("")
	// TODO: We can't do this so long as we support partial Hydra impls in Complement
	// because otherwise if MSC4291=0 and MSC4289=1 then this check fails as the create
	// event will have a room_id.
	//if isCreateEvent && res.eventFields.RoomID != "" {
	//return fmt.Errorf("gomatrixserverlib: room_id must not exist on create event")
	//}
	if !isCreateEvent && !strings.HasPrefix(res.eventFields.RoomID, "!") {
		return fmt.Errorf("gomatrixserverlib: room_id must start with !")
	}
	return nil
}
