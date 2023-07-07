package fclient

import (
	"encoding/json"

	"github.com/matrix-org/gomatrixserverlib"
)

func NewInviteV3Request(event gomatrixserverlib.ProtoEvent, version gomatrixserverlib.RoomVersion, state []gomatrixserverlib.InviteStrippedState) (
	request InviteV3Request, err error,
) {
	if !gomatrixserverlib.KnownRoomVersion(version) {
		err = gomatrixserverlib.UnsupportedRoomVersionError{
			Version: version,
		}
		return
	}
	request.fields.inviteV2RequestHeaders = inviteV2RequestHeaders{
		RoomVersion:     version,
		InviteRoomState: state,
	}
	request.fields.Event = event
	return
}

// InviteV3Request is used in the body of a /_matrix/federation/v3/invite request.
type InviteV3Request struct {
	fields struct {
		inviteV2RequestHeaders
		Event gomatrixserverlib.ProtoEvent `json:"event"`
	}
}

// MarshalJSON implements json.Marshaller
func (i InviteV3Request) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteV3Request) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &i.fields)
	if err != nil {
		return err
	}
	return err
}

// Event returns the invite event.
func (i *InviteV3Request) Event() gomatrixserverlib.ProtoEvent {
	return i.fields.Event
}

// RoomVersion returns the room version of the invited room.
func (i *InviteV3Request) RoomVersion() gomatrixserverlib.RoomVersion {
	return i.fields.RoomVersion
}

// InviteRoomState returns stripped state events for the room, containing
// enough information for the client to identify the room.
func (i *InviteV3Request) InviteRoomState() []gomatrixserverlib.InviteStrippedState {
	return i.fields.InviteRoomState
}
