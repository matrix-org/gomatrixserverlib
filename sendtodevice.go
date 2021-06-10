package gomatrixserverlib

type SendToDeviceEvent struct {
	Sender  string `json:"sender"`
	Type    string `json:"type"`
	Content []byte `json:"content"`
}

type ToDeviceMessage struct {
	Sender    string                       `json:"sender"`
	Type      string                       `json:"type"`
	MessageID string                       `json:"message_id"`
	Messages  map[string]map[string][]byte `json:"messages"`
}
