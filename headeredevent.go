package gomatrixserverlib

import (
	"encoding/json"
	"reflect"

	"github.com/tidwall/sjson"
)

// HeaderedEventHeader contains header fields for an event that contains
// additional metadata, e.g. room version.
type EventHeader struct {
	RoomVersion RoomVersion `json:"room_version"`
}

// HeaderedEvent is a wrapper around an Event that contains information
// about the room version.
type HeaderedEvent struct {
	EventHeader
	Event
}

// UnmarshalJSON implements json.Unmarshaller
func (e *HeaderedEvent) UnmarshalJSON(data []byte) error {
	var err error
	var m EventHeader
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	fields := reflect.TypeOf(e.EventHeader)
	for i := 0; i < fields.NumField(); i++ {
		if data, err = sjson.DeleteBytes(
			data,
			fields.Field(i).Tag.Get("json"),
		); err != nil {
			return err
		}
	}
	switch m.RoomVersion {
	case RoomVersionV1, RoomVersionV2:
	case RoomVersionV3, RoomVersionV4, RoomVersionV5:
	default:
		return UnsupportedRoomVersionError{m.RoomVersion}
	}
	if err := json.Unmarshal(data, &e.Event); err != nil {
		return err
	}
	return nil
}

// MarshalJSON implements json.Marshaller
func (e HeaderedEvent) MarshalJSON() ([]byte, error) {
	content, err := json.Marshal(e.Event)
	if err != nil {
		return []byte{}, err
	}
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
	return content, nil
}
