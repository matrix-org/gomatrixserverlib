package fclient

import (
	"encoding/json"

	"github.com/matrix-org/gomatrixserverlib"
)

func NewSendInviteCryptoIDsRequest(event gomatrixserverlib.PDU, version gomatrixserverlib.RoomVersion) (
	request SendInviteCryptoIDsRequest, err error,
) {
	if !gomatrixserverlib.KnownRoomVersion(version) {
		err = gomatrixserverlib.UnsupportedRoomVersionError{
			Version: version,
		}
		return
	}
	request.fields.RoomVersion = version
	request.fields.Event = event
	return
}

// SendInviteCryptoIDsRequest is used in the body of a /_matrix/federation/v3/invite request.
type SendInviteCryptoIDsRequest struct {
	fields struct {
		RoomVersion gomatrixserverlib.RoomVersion `json:"room_version"`
		Event       gomatrixserverlib.PDU         `json:"event"`
	}
}

// MarshalJSON implements json.Marshaller
func (i SendInviteCryptoIDsRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *SendInviteCryptoIDsRequest) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &i.fields)
	if err != nil {
		return err
	}
	return err
}

// Event returns the invite event.
func (i *SendInviteCryptoIDsRequest) Event() gomatrixserverlib.PDU {
	return i.fields.Event
}

// RoomVersion returns the room version of the invited room.
func (i *SendInviteCryptoIDsRequest) RoomVersion() gomatrixserverlib.RoomVersion {
	return i.fields.RoomVersion
}
