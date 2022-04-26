package gomatrixserverlib

import "encoding/json"

// DeviceListUpdateEvent is https://matrix.org/docs/spec/server_server/latest#m-device-list-update-schema
type DeviceListUpdateEvent struct {
	Deleted           bool            `json:"deleted,omitempty"`
	DeviceDisplayName string          `json:"device_display_name,omitempty"`
	DeviceID          string          `json:"device_id"`
	Keys              json.RawMessage `json:"keys,omitempty"`
	PrevID            []int64         `json:"prev_id,omitempty"`
	StreamID          int64           `json:"stream_id"`
	UserID            string          `json:"user_id"`
}
