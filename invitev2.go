package gomatrixserverlib

import (
	"encoding/json"
	"errors"

	"github.com/tidwall/gjson"
)

// InviteV2Request and InviteV2StrippedState are defined in
// https://matrix.org/docs/spec/server_server/r0.1.3#put-matrix-federation-v2-invite-roomid-eventid

func NewInviteV2Request(event *HeaderedEvent, state []InviteV2StrippedState) (
	request InviteV2Request, err error,
) {
	if ver, ok := SupportedRoomVersions()[event.RoomVersion]; !ok || !ver.Supported {
		err = UnsupportedRoomVersionError{
			Version: event.RoomVersion,
		}
		return
	}
	request.fields.inviteV2RequestHeaders = inviteV2RequestHeaders{
		RoomVersion:     event.RoomVersion,
		InviteRoomState: state,
	}
	request.fields.Event = event.Unwrap()
	return
}

type inviteV2RequestHeaders struct {
	RoomVersion     RoomVersion             `json:"room_version"`
	InviteRoomState []InviteV2StrippedState `json:"invite_room_state"`
}

// InviteV2Request is used in the body of a /_matrix/federation/v2/invite request.
type InviteV2Request struct {
	fields struct {
		inviteV2RequestHeaders
		Event *Event `json:"event"`
	}
}

// MarshalJSON implements json.Marshaller
func (i InviteV2Request) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteV2Request) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &i.fields.inviteV2RequestHeaders)
	if err != nil {
		return err
	}
	eventJSON := gjson.GetBytes(data, "event")
	if !eventJSON.Exists() {
		return errors.New("gomatrixserverlib: request doesn't contain event")
	}
	if ver, ok := SupportedRoomVersions()[i.fields.RoomVersion]; !ok || !ver.Supported {
		return UnsupportedRoomVersionError{
			Version: i.fields.RoomVersion,
		}
	}
	i.fields.Event, err = NewEventFromUntrustedJSON([]byte(eventJSON.String()), i.fields.RoomVersion)
	return err
}

// Event returns the invite event.
func (i *InviteV2Request) Event() *Event {
	return i.fields.Event
}

// RoomVersion returns the room version of the invited room.
func (i *InviteV2Request) RoomVersion() RoomVersion {
	return i.fields.RoomVersion
}

// InviteRoomState returns stripped state events for the room, containing
// enough information for the client to identify the room.
func (i *InviteV2Request) InviteRoomState() []InviteV2StrippedState {
	return i.fields.InviteRoomState
}

// InviteV2StrippedState is a cut-down set of fields from room state
// events that allow the invited server to identify the room.
type InviteV2StrippedState struct {
	fields struct {
		Content  RawJSON `json:"content"`
		StateKey *string `json:"state_key"`
		Type     string  `json:"type"`
		Sender   string  `json:"sender"`
	}
}

// NewInviteV2StrippedState creates a stripped state event from a
// regular state event.
func NewInviteV2StrippedState(event *Event) (ss InviteV2StrippedState) {
	ss.fields.Content = event.Content()
	ss.fields.StateKey = event.StateKey()
	ss.fields.Type = event.Type()
	ss.fields.Sender = event.Sender()
	return
}

// MarshalJSON implements json.Marshaller
func (i InviteV2StrippedState) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteV2StrippedState) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &i.fields)
}

// Content returns the content of the stripped state.
func (i *InviteV2StrippedState) Content() RawJSON {
	return i.fields.Content
}

// StateKey returns the state key of the stripped state.
func (i *InviteV2StrippedState) StateKey() *string {
	return i.fields.StateKey
}

// Type returns the type of the stripped state.
func (i *InviteV2StrippedState) Type() string {
	return i.fields.Type
}

// Sender returns the sender of the stripped state.
func (i *InviteV2StrippedState) Sender() string {
	return i.fields.Sender
}
