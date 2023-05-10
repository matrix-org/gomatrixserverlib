package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

// An EventBuilderV2 is used to build a new event.
// These can be exchanged between matrix servers in the federation APIs when
// joining or leaving a room.
type EventBuilderV2 struct {
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
	PrevEvents []string `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	AuthEvents []string `json:"auth_events"`
	// The event ID of the event being redacted if this event is a "m.room.redaction".
	Redacts string `json:"redacts,omitempty"`
	// The depth of the event, This should be one greater than the maximum depth of the previous events.
	// The create event has a depth of 1.
	Depth int64 `json:"depth"`
	// The JSON object for "signatures" key of the event.
	Signature spec.RawJSON `json:"signatures,omitempty"`
	// The JSON object for "content" key of the event.
	Content spec.RawJSON `json:"content"`
	// The JSON object for the "unsigned" key
	Unsigned spec.RawJSON `json:"unsigned,omitempty"`

	// private: forces the user to go through NewEventBuilder
	version IRoomVersion
}

// SetContent sets the JSON content key of the event.
func (eb *EventBuilderV2) SetContent(content interface{}) (err error) {
	eb.Content, err = json.Marshal(content)
	return
}

// SetUnsigned sets the JSON unsigned key of the event.
func (eb *EventBuilderV2) SetUnsigned(unsigned interface{}) (err error) {
	eb.Unsigned, err = json.Marshal(unsigned)
	return
}

func (eb *EventBuilderV2) SetPrevEvents(evs any) {
	switch e := evs.(type) {
	case []EventReference:
		for _, ev := range e {
			eb.PrevEvents = append(eb.PrevEvents, ev.EventID)
		}
	case []string:
		eb.PrevEvents = e
	default:
		panic("invalid type")
	}
}

func (eb *EventBuilderV2) SetAuthEvents(evs any) {
	switch e := evs.(type) {
	case []EventReference:
		for _, ev := range e {
			eb.AuthEvents = append(eb.AuthEvents, ev.EventID)
		}
	case []string:
		eb.AuthEvents = e
	default:
		panic("invalid type")
	}
}

func (eb *EventBuilderV2) AddAuthEvents(provider AuthEventProvider) error {
	eventsNeeded, err := StateNeededForProtoEvent(&ProtoEvent{
		Type:     eb.Type,
		StateKey: eb.StateKey,
		Content:  eb.Content,
		Sender:   eb.Sender,
	})
	if err != nil {
		return err
	}
	refs, err := eventsNeeded.AuthEventReferences(provider)
	if err != nil {
		return err
	}

	eb.SetAuthEvents(refs)
	return nil
}

// Build a new Event.
// This is used when a local event is created on this server.
// Call this after filling out the necessary fields.
// This can be called multiple times on the same builder.
// A different event ID must be supplied each time this is called.
func (eb *EventBuilderV2) Build(
	now time.Time, origin spec.ServerName, keyID KeyID,
	privateKey ed25519.PrivateKey,
) (result PDU, err error) {
	if eb.version == nil {
		return nil, fmt.Errorf("EventBuilderV2.Build: unknown version, did you create this via NewEventBuilder?")
	}

	var eventStruct struct {
		EventBuilderV2
		OriginServerTS spec.Timestamp  `json:"origin_server_ts"`
		Origin         spec.ServerName `json:"origin"`
		// This key is either absent or an empty list.
		// If it is absent then the pointer is nil and omitempty removes it.
		// Otherwise it points to an empty list and omitempty keeps it.
		PrevState *[]EventReference `json:"prev_state,omitempty"`
	}
	eventStruct.EventBuilderV2 = *eb
	eventStruct.OriginServerTS = spec.AsTimestamp(now)
	eventStruct.Origin = origin

	// In this event format, prev_events and auth_events are lists of
	// event IDs as a []string, rather than full-blown []EventReference.
	// Since gomatrixserverlib otherwise deals with EventReferences,
	// take the event IDs out of these and replace the prev_events and
	// auth_events with those new arrays.
	if eventStruct.PrevEvents == nil || len(eventStruct.PrevEvents) == 0 {
		eventStruct.PrevEvents = []string{}
	}
	if eventStruct.AuthEvents == nil || len(eventStruct.AuthEvents) == 0 {
		eventStruct.AuthEvents = []string{}
	}

	if eventStruct.StateKey != nil {
		// In early versions of the matrix protocol state events
		// had a "prev_state" key that listed the state events with
		// the same type and state key that this event replaced.
		// This was later dropped from the protocol.
		// Synapse ignores the contents of the key but still expects
		// the key to be present in state events.
		eventStruct.PrevState = &emptyEventReferenceList
	}

	var eventJSON []byte
	if eventJSON, err = json.Marshal(&eventStruct); err != nil {
		return
	}

	if eventJSON, err = sjson.DeleteBytes(eventJSON, "event_id"); err != nil {
		return
	}

	if eventJSON, err = addContentHashesToEvent(eventJSON); err != nil {
		return
	}

	if eventJSON, err = signEvent(string(origin), keyID, privateKey, eventJSON, eb.version.Version()); err != nil {
		return
	}

	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, eb.version.Version()); err != nil {
		return
	}

	ev := event{
		eventJSON:   eventJSON,
		roomVersion: eb.version.Version(),
	}
	res := &eventV2{
		event: ev,
		fields: eventFormatV2Fields{
			eventFields: eventFields{
				RoomID:         eb.RoomID,
				Sender:         eb.Sender,
				Type:           eb.Type,
				StateKey:       eb.StateKey,
				Content:        eb.Content,
				Redacts:        eb.Redacts,
				Depth:          eb.Depth,
				Unsigned:       eb.Unsigned,
				OriginServerTS: eventStruct.OriginServerTS,
			},
			PrevEvents: eventStruct.PrevEvents,
			AuthEvents: eventStruct.AuthEvents,
		},
	}
	res.eventID, err = res.generateEventID()
	if err != nil {
		return nil, err
	}

	res.event.fields = res.fields
	if err = checkFields(res.fields, eventJSON); err != nil {
		return
	}

	return res, nil
}
