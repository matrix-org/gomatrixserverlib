package gomatrixserverlib

// A RelayEntry is used to track the nid of an event received from a relay server.
type RelayEntry struct {
	EntryID int64 `json:"entry_id"`
}

// A RespGetRelayTransaction is the content of a response to GET /_matrix/federation/v1/relay_txn/{userID}/
type RespGetRelayTransaction struct {
	Txn           Transaction `json:"transaction"`
	EntryID       int64       `json:"entry_id"`
	EntriesQueued bool        `json:"entries_queued"`
}
