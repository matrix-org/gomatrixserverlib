package gomatrixserverlib

import "encoding/json"

type SendToDeviceEvent struct {
	Sender  string          `json:"sender"`
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type DirectToDeviceSchema struct {
	EDUType string          `json:"edu_type"`
	Content ToDeviceMessage `json:"content"`
}

type ToDeviceMessage struct {
	Sender    string                                `json:"sender"`
	Type      string                                `json:"type"`
	MessageID string                                `json:"message_id"`
	Messages  map[string]map[string]json.RawMessage `json:"messages"`
}
