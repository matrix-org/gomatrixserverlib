package gomatrixserverlib

import "encoding/json"

type SendToDeviceEvent struct {
	// The user ID to send the update to.
	UserID string `json:"user_id"`
	// The device ID to send the update to.
	DeviceID string `json:"device_id"`
	// The type of the event.
	EventType string `json:"event_type"`
	// The contents of the message.
	Message json.RawMessage `json:"message"`
}
