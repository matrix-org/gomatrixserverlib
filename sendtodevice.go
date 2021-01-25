package gomatrixserverlib

import jsoniter "github.com/json-iterator/go"

type SendToDeviceEvent struct {
	Sender  string              `json:"sender"`
	Type    string              `json:"type"`
	Content jsoniter.RawMessage `json:"content"`
}

type ToDeviceMessage struct {
	Sender    string                                    `json:"sender"`
	Type      string                                    `json:"type"`
	MessageID string                                    `json:"message_id"`
	Messages  map[string]map[string]jsoniter.RawMessage `json:"messages"`
}
