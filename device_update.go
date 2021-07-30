package gomatrixserverlib

// DeviceListUpdateEvent is https://matrix.org/docs/spec/server_server/latest#m-device-list-update-schema
type DeviceListUpdateEvent struct {
	UserID            string      `json:"user_id"`
	DeviceID          string      `json:"device_id"`
	DeviceDisplayName string      `json:"device_display_name,omitempty"`
	StreamID          int         `json:"stream_id"`
	PrevID            []int       `json:"prev_id,omitempty"`
	Deleted           bool        `json:"deleted,omitempty"`
	Keys              *DeviceKeys `json:"keys,omitempty"`
}
