package gomatrixserverlib

import "encoding/json"

// DeviceListUpdateEvent is https://matrix.org/docs/spec/server_server/latest#m-device-list-update-schema
type DeviceListUpdateEvent struct {
	UserID            string          `json:"user_id"`
	DeviceID          string          `json:"device_id"`
	DeviceDisplayName string          `json:"device_display_name"`
	StreamID          int             `json:"stream_id"`
	PrevID            []int           `json:"prev_id"`
	Deleted           bool            `json:"deleted"`
	Keys              json.RawMessage `json:"keys"`
}
