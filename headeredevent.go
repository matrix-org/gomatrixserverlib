package gomatrixserverlib

import (
	"encoding/json"
	"reflect"

	"github.com/tidwall/sjson"
)

// HeaderedEventHeader contains header fields for an event that contains
// additional metadata, e.g. room version. IMPORTANT NOTE: All fields in
// this struct must have a "json:" name tag or otherwise the reflection
// code for marshalling and unmarshalling headered events will not work.
type EventHeader struct {
	RoomVersion RoomVersion `json:"room_version"`
}

// HeaderedEvent is a wrapper around an Event that contains information
// about the room version. All header fields will be added into the event
// when marshalling into JSON and will be separated out when unmarshalling.
type HeaderedEvent struct {
	EventHeader
	Event
}

// UnmarshalJSON implements json.Unmarshaller
func (e *HeaderedEvent) UnmarshalJSON(data []byte) error {
	var err error
	// First extract the headers from the JSON.
	var m EventHeader
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	// Now strip any of the header fields from the JSON input data.
	fields := reflect.TypeOf(e.EventHeader)
	for i := 0; i < fields.NumField(); i++ {
		if data, err = sjson.DeleteBytes(
			data, fields.Field(i).Tag.Get("json"),
		); err != nil {
			return err
		}
	}
	// Check what the room version is and prepare the Event struct for
	// that specific version type.
	switch m.RoomVersion {
	case RoomVersionV1, RoomVersionV2:
	case RoomVersionV3, RoomVersionV4, RoomVersionV5:
	default:
		return UnsupportedRoomVersionError{m.RoomVersion}
	}
	// Finally, unmarshal the remaining event JSON (less the headers)
	// into the event struct.
	if err := json.Unmarshal(data, &e.Event); err != nil {
		return err
	}
	// At this point unmarshalling is complete.
	return nil
}

// MarshalJSON implements json.Marshaller
func (e HeaderedEvent) MarshalJSON() ([]byte, error) {
	// First marshal the event struct itself.
	content, err := json.Marshal(e.Event)
	if err != nil {
		return []byte{}, err
	}
	// Now jump through the fields of the header struct and add them
	// in separately. This is needed because of the way that Go handles
	// function overloading on embedded types. Doing this ensures the
	// least number of changes to event references elsewhere.
	fields := reflect.TypeOf(e.EventHeader)
	values := reflect.ValueOf(e.EventHeader)
	for i := 0; i < fields.NumField(); i++ {
		if content, err = sjson.SetBytes(
			content,
			fields.Field(i).Tag.Get("json"),
			values.Field(i).Interface(),
		); err != nil {
			return []byte{}, err
		}
	}
	// Return the newly marshalled JSON.
	return content, nil
}
