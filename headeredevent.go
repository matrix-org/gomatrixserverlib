package gomatrixserverlib

import (
	"unsafe"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// HeaderedEvent is a wrapper around an Event that contains information
// about the room version. All header fields will be added into the event
// when marshalling into JSON and will be separated out when unmarshalling.
type HeaderedEvent struct {
	RoomVersion RoomVersion       `json:"-"`
	Visibility  HistoryVisibility `json:"-"`
	*Event
}

func (e *HeaderedEvent) CacheCost() int {
	return int(unsafe.Sizeof(*e)) +
		len(e.RoomVersion) +
		e.Event.CacheCost()
}

// Unwrap extracts the event object from the headered event.
func (e *HeaderedEvent) Unwrap() *Event {
	if e.RoomVersion == "" {
		// TODO: Perhaps return an error here instead of panicing
		panic("gomatrixserverlib: malformed HeaderedEvent doesn't contain room version")
	}
	event := e.Event
	event.eventID = e.eventID
	event.roomVersion = e.RoomVersion
	return event
}

// UnwrapEventHeaders unwraps an array of headered events.
func UnwrapEventHeaders(in []*HeaderedEvent) []*Event {
	result := make([]*Event, len(in))
	for i := range in {
		result[i] = in[i].Event
	}
	return result
}

// UnmarshalJSON implements json.Unmarshaller
func (e *HeaderedEvent) UnmarshalJSON(data []byte) error {
	eventID := gjson.GetBytes(data, "_event_id").String()
	return e.UnmarshalJSONWithEventID(data, eventID)
}

// UnmarshalJSONWithEventID allows lighter unmarshalling when the
// event ID is already known, rather than burning CPU cycles calculating
// it again. If it isn't, supply "" instead.
func (e *HeaderedEvent) UnmarshalJSONWithEventID(data []byte, eventID string) error {
	var err error
	// First extract the room version from the JSON.
	e.RoomVersion = RoomVersion(gjson.GetBytes(data, "_room_version").String())
	// Get the event field format.
	eventFormat, err := e.RoomVersion.EventFormat()
	if err != nil {
		return err
	}
	// Check what the room version is and prepare the Event struct for
	// that specific version type.
	if e.Event == nil {
		e.Event = &Event{}
	}
	switch eventFormat {
	case EventFormatV1:
		e.fields = eventFormatV1Fields{}
	case EventFormatV2:
		e.fields = eventFormatV2Fields{}
	default:
		return UnsupportedRoomVersionError{e.RoomVersion}
	}
	// Finally, unmarshal the remaining event JSON (less the headers)
	// into the event struct.
	data, _ = sjson.DeleteBytes(data, "_room_version")
	data, _ = sjson.DeleteBytes(data, "_event_id")
	if e.Event, err = NewEventFromTrustedJSONWithEventID(eventID, data, false, e.RoomVersion); err != nil {
		return err
	}
	// At this point unmarshalling is complete.
	return nil
}

// MarshalJSON implements json.Marshaller
func (e HeaderedEvent) MarshalJSON() ([]byte, error) {
	var err error
	// First marshal the event struct itself.
	content := e.Event.JSON()
	// Then add the fields.
	content, err = sjson.SetBytes(content, "_room_version", e.RoomVersion)
	if err != nil {
		return []byte{}, err
	}
	content, err = sjson.SetBytes(content, "_event_id", e.Event.EventID())
	if err != nil {
		return []byte{}, err
	}
	// Return the newly marshalled JSON.
	return content, nil
}

type UnexpectedHeaderedEvent struct{}

func (u UnexpectedHeaderedEvent) Error() string {
	return "unexpected headered event"
}
