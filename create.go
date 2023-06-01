package gomatrixserverlib

// FledglingEvent is a helper representation of an event used when creating many events in succession.
type FledglingEvent struct {
	// The type of the event.
	Type string `json:"type"`
	// The state_key of the event if the event is a state event or nil if the event is not a state event.
	StateKey string `json:"state_key"`
	// The JSON object for "content" key of the event.
	Content interface{} `json:"content"`
}
