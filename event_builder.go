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
	// The sender ID of the user sending the event.
	SenderID string `json:"sender"`
	// The room ID of the room this event is in.
	RoomID string `json:"room_id"`
	// The type of the event.
	Type string `json:"type"`
	// The state_key of the event if the event is a state event or nil if the event is not a state event.
	StateKey *string `json:"state_key,omitempty"`
	// The events that immediately preceded this event in the room history. This can be
	// either []eventReference for room v1/v2, and []string for room v3 onwards.
	PrevEvents interface{} `json:"prev_events"`
	// The events needed to authenticate this event. This can be
	// either []eventReference for room v1/v2, and []string for room v3 onwards.
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

func (eb *EventBuilder) AddAuthEvents(provider AuthEventProvider) error {
	eventsNeeded, err := StateNeededForProtoEvent(&ProtoEvent{
		Type:     eb.Type,
		StateKey: eb.StateKey,
		Content:  eb.Content,
		SenderID: eb.SenderID,
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

// TODO: Remove?
func toEventReference(data any) []eventReference {
	switch evs := data.(type) {
	case nil:
		return []eventReference{}
	case []string:
		newEvents := make([]eventReference, 0, len(evs))
		for _, eventID := range evs {
			newEvents = append(newEvents, eventReference{
				EventID:     eventID,
				EventSHA256: eventHashFromEventID(eventID),
			})
		}
		return newEvents
	case []eventReference:
		return evs
	case []interface{}:
		evRefs := make([]eventReference, 0, len(evs))
		for _, b := range evs {
			evID, ok := b.(string)
			if ok {
				evRefs = append(evRefs, eventReference{
					EventID:     evID,
					EventSHA256: eventHashFromEventID(evID)},
				)
				continue
			}
			ev, ok := b.([]interface{})
			if ok {
				evRefs = append(evRefs, eventReference{
					EventID:     ev[0].(string),
					EventSHA256: eventHashFromEventID(ev[0].(string))},
				)
				continue
			}
		}
		return evRefs
	default:
		return []eventReference{}
	}
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
		PrevState *[]eventReference `json:"prev_state,omitempty"`
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
		eventStruct.PrevEvents = toEventReference(eventStruct.PrevEvents)
		eventStruct.AuthEvents = toEventReference(eventStruct.AuthEvents)
	case EventFormatV2:
		// In this event format, prev_events and auth_events are lists of
		// event IDs as a []string.
		switch prevEvents := eventStruct.PrevEvents.(type) {
		case []string:
			eventStruct.PrevEvents = prevEvents
		case nil:
			eventStruct.PrevEvents = []string{}
		}
		switch authEvents := eventStruct.AuthEvents.(type) {
		case []string:
			eventStruct.AuthEvents = authEvents
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

	res, err := eb.version.NewEventFromTrustedJSON(eventJSON, false)
	if err != nil {
		return nil, err
	}

	err = CheckFields(res)

	return res, err
}

// Base64FromEventID returns, if possible, the base64bytes representation
// of the given eventID. Returns an empty spec.Base64Bytes if an error occurs decoding.
func eventHashFromEventID(eventID string) spec.Base64Bytes {
	// In the new event format, the event ID is already the hash of
	// the event. Since we will have generated the event ID before
	// now, we can just knock the sigil $ off the front and use that
	// as the event SHA256.
	var sha spec.Base64Bytes
	if err := sha.Decode(eventID[1:]); err != nil {
		return sha
	}
	return sha
}
