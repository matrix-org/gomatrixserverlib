package gomatrixserverlib

// InviteStateFormattedEvent is an event which is explicitly formatted for
// the 'invite_state' of a /sync response. It is not a real event.
type InviteStateFormattedEvent struct {
	Content  rawJSON `json:"content"`
	Sender   string  `json:"sender"`
	StateKey *string `json:"state_key,omitempty"`
	Type     string  `json:"type"`
}
