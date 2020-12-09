package gomatrixserverlib

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/tidwall/sjson"
)

// HeaderedEventHeader contains header fields for an event that contains
// additional metadata, e.g. room version. IMPORTANT NOTE: All fields in
// this struct must have a "json:" name tag or otherwise the reflection
// code for marshalling and unmarshalling headered events will not work.
// They must be unique and not overlap with a name tag from the Event
// struct or otherwise panics may occur, so header  name tags are instead
// prefixed with an underscore.
type EventHeader struct {
	RoomVersion RoomVersion `json:"_room_version,omitempty"`
}

// HeaderedEvent is a wrapper around an Event that contains information
// about the room version. All header fields will be added into the event
// when marshalling into JSON and will be separated out when unmarshalling.
type HeaderedEvent struct {
	EventHeader
	*Event
}

// Unwrap extracts the event object from the headered event.
func (e *HeaderedEvent) Unwrap() *Event {
	if e.RoomVersion == "" {
		// TODO: Perhaps return an error here instead of panicing
		panic("gomatrixserverlib: malformed HeaderedEvent doesn't contain room version")
	}
	event := e.Event
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
	return e.UnmarshalJSONWithEventID(data, "")
}

// UnmarshalJSONWithEventID allows lighter unmarshalling when the
// event ID is already known, rather than burning CPU cycles calculating
// it again. If it isn't, supply "" instead.
func (e *HeaderedEvent) UnmarshalJSONWithEventID(data []byte, eventID string) error {
	var err error
	// First extract the headers from the JSON.
	var m EventHeader
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	e.EventHeader = m
	// Now strip any of the header fields from the JSON input data.
	fields := reflect.TypeOf(e.EventHeader)
	for i := 0; i < fields.NumField(); i++ {
		tag := strings.Split(fields.Field(i).Tag.Get("json"), ",")[0]
		if data, err = sjson.DeleteBytes(data, tag); err != nil {
			return err
		}
	}
	// Get the event field format.
	eventFormat, err := m.RoomVersion.EventFormat()
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
		return UnsupportedRoomVersionError{m.RoomVersion}
	}
	// Finally, unmarshal the remaining event JSON (less the headers)
	// into the event struct.
	if e.Event, err = NewEventFromTrustedJSONWithEventID(eventID, data, false, m.RoomVersion); err != nil {
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
	// Now jump through the fields of the header struct and add them
	// in separately. This is needed because of the way that Go handles
	// function overloading on embedded types, since Event also
	// implements custom marshalling and unmarshalling functions.
	// Doing this also ensures the least number of changes to Event
	// references elsewhere.
	fields := reflect.TypeOf(e.EventHeader)
	values := reflect.ValueOf(e.EventHeader)
	for i := 0; i < fields.NumField(); i++ {
		tag := strings.Split(fields.Field(i).Tag.Get("json"), ",")[0]
		if content, err = sjson.SetBytes(
			content, tag,
			values.Field(i).Interface(),
		); err != nil {
			return []byte{}, err
		}
	}
	// Return the newly marshalled JSON.
	return content, nil
}

type UnexpectedHeaderedEvent struct{}

func (u UnexpectedHeaderedEvent) Error() string {
	return "unexpected headered event"
}
