package gomatrixserverlib

// A RelayEntry is used to track the nid of an event received from a relay server.
type RelayEntry struct {
	EntryID int64 `json:"entry_id"`
}
