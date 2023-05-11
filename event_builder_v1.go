package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"golang.org/x/crypto/ed25519"
)

// An EventBuilderV1 is used to build a new event.
// These can be exchanged between matrix servers in the federation APIs when
// joining or leaving a room.
type EventBuilderV1 struct {
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
	PrevEvents []EventReference `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	AuthEvents []EventReference `json:"auth_events"`
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
func (eb *EventBuilderV1) SetContent(content interface{}) (err error) {
	eb.Content, err = json.Marshal(content)
	return
}

// SetUnsigned sets the JSON unsigned key of the event.
func (eb *EventBuilderV1) SetUnsigned(unsigned interface{}) (err error) {
	eb.Unsigned, err = json.Marshal(unsigned)
	return
}

func (eb *EventBuilderV1) SetPrevEvents(evs any) {
	switch e := evs.(type) {
	case []EventReference:
		eb.PrevEvents = e
	default:
		panic("invalid type")
	}
}

func (eb *EventBuilderV1) SetAuthEvents(evs any) {
	switch e := evs.(type) {
	case []EventReference:
		eb.AuthEvents = e
	default:
		panic("invalid type")
	}
}

func (eb *EventBuilderV1) AddAuthEvents(provider AuthEventProvider) error {
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
	eb.AuthEvents = refs
	return nil
}

// Build a new Event.
// This is used when a local event is created on this server.
// Call this after filling out the necessary fields.
// This can be called multiple times on the same builder.
// A different event ID must be supplied each time this is called.
func (eb *EventBuilderV1) Build(
	now time.Time, origin spec.ServerName, keyID KeyID,
	privateKey ed25519.PrivateKey,
) (result PDU, err error) {
	if eb.version == nil {
		return nil, fmt.Errorf("EventBuilderV1.Build: unknown version, did you create this via NewEventBuilder?")
	}

	eventIDFormat := eb.version.EventIDFormat()
	var eventStruct struct {
		EventBuilderV1
		EventID        string          `json:"event_id"`
		OriginServerTS spec.Timestamp  `json:"origin_server_ts"`
		Origin         spec.ServerName `json:"origin"`
		// This key is either absent or an empty list.
		// If it is absent then the pointer is nil and omitempty removes it.
		// Otherwise it points to an empty list and omitempty keeps it.
		PrevState *[]EventReference `json:"prev_state,omitempty"`
	}
	eventStruct.EventBuilderV1 = *eb
	if eventIDFormat == EventIDFormatV1 {
		eventStruct.EventID = fmt.Sprintf("$%s:%s", util.RandomString(16), origin)
	}
	eventStruct.OriginServerTS = spec.AsTimestamp(now)
	eventStruct.Origin = origin

	// If either prev_events or auth_events are nil slices then Go will
	// marshal them into 'null' instead of '[]', which is bad. Since the
	// EventBuilderV1 struct is instantiated outside of gomatrixserverlib
	// let's just make sure that they haven't been left as nil slices.
	if eb.PrevEvents == nil {
		eventStruct.PrevEvents = []EventReference{}
	}
	if eb.AuthEvents == nil {
		eventStruct.AuthEvents = []EventReference{}
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
		eventID:     eventStruct.EventID,
		eventJSON:   eventJSON,
		roomVersion: eb.version.Version(),
	}
	res := &eventV1{
		event: ev,
		fields: eventFormatV1Fields{
			EventID: eventStruct.EventID,
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
	res.event.eventID = res.eventID
	res.fields.EventID = res.eventID

	if err = checkFields(res.fields, eventJSON); err != nil {
		return
	}

	return res, nil
}
