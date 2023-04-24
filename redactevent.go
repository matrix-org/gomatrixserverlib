package gomatrixserverlib

import (
	"encoding/json"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

// For satisfying "Upon receipt of a redaction event, the server must strip off any keys not in the following list:"
type unredactableEventFields struct {
	EventID        spec.RawJSON           `json:"event_id,omitempty"`
	Type           string                 `json:"type"`
	RoomID         spec.RawJSON           `json:"room_id,omitempty"`
	Sender         spec.RawJSON           `json:"sender,omitempty"`
	StateKey       spec.RawJSON           `json:"state_key,omitempty"`
	Content        map[string]interface{} `json:"content"`
	Hashes         spec.RawJSON           `json:"hashes,omitempty"`
	Signatures     spec.RawJSON           `json:"signatures,omitempty"`
	Depth          spec.RawJSON           `json:"depth,omitempty"`
	PrevEvents     spec.RawJSON           `json:"prev_events,omitempty"`
	PrevState      spec.RawJSON           `json:"prev_state,omitempty"`
	AuthEvents     spec.RawJSON           `json:"auth_events,omitempty"`
	Origin         spec.RawJSON           `json:"origin,omitempty"`
	OriginServerTS spec.RawJSON           `json:"origin_server_ts,omitempty"`
	Membership     spec.RawJSON           `json:"membership,omitempty"`
}

// For satisfying "The content object must also be stripped of all keys, unless it is one of one of the following event types:"
var (
	unredactableContentFieldsV1 = map[string][]string{
		"m.room.member":             {"membership"},
		"m.room.create":             {"creator"},
		"m.room.join_rules":         {"join_rule"},
		"m.room.power_levels":       {"ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default"},
		"m.room.aliases":            {"aliases"},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV2 = map[string][]string{
		"m.room.member":             {"membership"},
		"m.room.create":             {"creator"},
		"m.room.join_rules":         {"join_rule"},
		"m.room.power_levels":       {"ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default"},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV3 = map[string][]string{
		"m.room.member":             {"membership"},
		"m.room.create":             {"creator"},
		"m.room.join_rules":         {"join_rule", "allow"},
		"m.room.power_levels":       {"ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default"},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV4 = map[string][]string{
		"m.room.member":             {"membership", "join_authorised_via_users_server"},
		"m.room.create":             {"creator"},
		"m.room.join_rules":         {"join_rule", "allow"},
		"m.room.power_levels":       {"ban", "events", "events_default", "kick", "redact", "state_default", "users", "users_default"},
		"m.room.history_visibility": {"history_visibility"},
	}
)

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event. Implements https://spec.matrix.org/unstable/rooms/v9/#redactions
// which protects membership 'join_authorised_via_users_server' key
func redactEventJSONV4(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, unredactableContentFieldsV4)
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event. Implements https://spec.matrix.org/unstable/rooms/v8/#redactions
// which protects join rules 'allow' key
func redactEventJSONV3(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, unredactableContentFieldsV3)
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event. Implements https://spec.matrix.org/unstable/rooms/v6/#redactions
// which has no special meaning for m.room.aliases
func redactEventJSONV2(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, unredactableContentFieldsV2)
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event. Implements https://spec.matrix.org/unstable/rooms/v1/#redactions
func redactEventJSONV1(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, unredactableContentFieldsV1)
}

func redactEventJSON(eventJSON []byte, eventTypeToKeepContentFields map[string][]string) ([]byte, error) {
	var event unredactableEventFields
	// Unmarshalling into a struct will discard any extra fields from the event.
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}
	newContent := map[string]interface{}{}
	keepContentFields := eventTypeToKeepContentFields[event.Type]
	for _, contentKey := range keepContentFields {
		val, ok := event.Content[contentKey]
		if ok {
			newContent[contentKey] = val
		}
	}
	// Replace the content with our new filtered content.
	// This will zero out any keys that weren't copied in the loop above.
	event.Content = newContent
	// Return the redacted event encoded as JSON.
	return json.Marshal(&event)
}
