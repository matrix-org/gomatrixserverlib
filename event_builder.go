package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

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
	// The events that immediately preceded this event in the room history. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	PrevEvents interface{} `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []EventReference for room v1/v2, and []string for room v3 onwards.
	AuthEvents interface{} `json:"auth_events"`
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
func (eb *EventBuilder) SetContent(content interface{}) (err error) {
	eb.Content, err = json.Marshal(content)
	return
}

// SetUnsigned sets the JSON unsigned key of the event.
func (eb *EventBuilder) SetUnsigned(unsigned interface{}) (err error) {
	eb.Unsigned, err = json.Marshal(unsigned)
	return
}

func (eb *EventBuilder) AddAuthEventsAndBuild(serverName spec.ServerName, provider AuthEventProvider,
	evTime time.Time, keyID KeyID, privateKey ed25519.PrivateKey,
) (PDU, error) {
	eventsNeeded, err := StateNeededForEventBuilder(eb)
	if err != nil {
		return nil, err
	}
	refs, err := eventsNeeded.AuthEventReferences(provider)
	if err != nil {
		return nil, err
	}
	eb.AuthEvents = refs
	event, err := eb.Build(
		evTime, serverName, keyID,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot build event %s : Builder failed to build. %w", eb.Type, err)
	}
	return event, nil
}

// Build a new Event.
// This is used when a local event is created on this server.
// Call this after filling out the necessary fields.
// This can be called multiple times on the same builder.
// A different event ID must be supplied each time this is called.
func (eb *EventBuilder) Build(
	now time.Time, origin spec.ServerName, keyID KeyID,
	privateKey ed25519.PrivateKey,
) (result PDU, err error) {
	if eb.version == nil {
		return nil, fmt.Errorf("EventBuilder.Build: unknown version, did you create this via NewEventBuilder?")
	}

	eventFormat := eb.version.EventFormat()
	eventIDFormat := eb.version.EventIDFormat()
	var eventStruct struct {
		EventBuilder
		EventID        string          `json:"event_id"`
		OriginServerTS spec.Timestamp  `json:"origin_server_ts"`
		Origin         spec.ServerName `json:"origin"`
		// This key is either absent or an empty list.
		// If it is absent then the pointer is nil and omitempty removes it.
		// Otherwise it points to an empty list and omitempty keeps it.
		PrevState *[]EventReference `json:"prev_state,omitempty"`
	}
	eventStruct.EventBuilder = *eb
	if eventIDFormat == EventIDFormatV1 {
		eventStruct.EventID = fmt.Sprintf("$%s:%s", util.RandomString(16), origin)
	}
	eventStruct.OriginServerTS = spec.AsTimestamp(now)
	eventStruct.Origin = origin
	switch eventFormat {
	case EventFormatV1:
		// If either prev_events or auth_events are nil slices then Go will
		// marshal them into 'null' instead of '[]', which is bad. Since the
		// EventBuilder struct is instantiated outside of gomatrixserverlib
		// let's just make sure that they haven't been left as nil slices.
		if eventStruct.PrevEvents == nil {
			eventStruct.PrevEvents = []EventReference{}
		}
		if eventStruct.AuthEvents == nil {
			eventStruct.AuthEvents = []EventReference{}
		}
	case EventFormatV2:
		// In this event format, prev_events and auth_events are lists of
		// event IDs as a []string, rather than full-blown []EventReference.
		// Since gomatrixserverlib otherwise deals with EventReferences,
		// take the event IDs out of these and replace the prev_events and
		// auth_events with those new arrays.
		switch prevEvents := eventStruct.PrevEvents.(type) {
		case []string:
			eventStruct.PrevEvents = prevEvents
		case []EventReference:
			resPrevEvents := []string{}
			for _, prevEvent := range prevEvents {
				resPrevEvents = append(resPrevEvents, prevEvent.EventID)
			}
			eventStruct.PrevEvents = resPrevEvents
		case nil:
			eventStruct.PrevEvents = []string{}
		}
		switch authEvents := eventStruct.AuthEvents.(type) {
		case []string:
			eventStruct.AuthEvents = authEvents
		case []EventReference:
			resAuthEvents := []string{}
			for _, authEvent := range authEvents {
				resAuthEvents = append(resAuthEvents, authEvent.EventID)
			}
			eventStruct.AuthEvents = resAuthEvents
		case nil:
			eventStruct.AuthEvents = []string{}
		}
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

	if eventFormat == EventFormatV2 {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, "event_id"); err != nil {
			return
		}
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

	res := &event{}
	res.roomVersion = eb.version.Version()

	if err = res.populateFieldsFromJSON("", eventJSON); err != nil {
		return
	}

	if err = res.CheckFields(); err != nil {
		return
	}

	return res, nil
}
