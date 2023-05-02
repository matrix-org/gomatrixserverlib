package fclient

import (
	"encoding/json"

	"github.com/matrix-org/gomatrixserverlib"
)

// A RelayEntry is used to track the nid of an event received from a relay server.
// It is used as the request body of a GET to /_matrix/federation/v1/relay_txn/{userID}
type RelayEntry struct {
	EntryID int64 `json:"entry_id"`
}

// A RespGetRelayTransaction is the response body of a successful GET to /_matrix/federation/v1/relay_txn/{userID}
type RespGetRelayTransaction struct {
	Transaction   gomatrixserverlib.Transaction `json:"transaction"`
	EntryID       int64                         `json:"entry_id,omitempty"`
	EntriesQueued bool                          `json:"entries_queued"`
}

// RelayEvents is the request body of a PUT to /_matrix/federation/v1/send_relay/{txnID}/{userID}
type RelayEvents struct {
	PDUs []json.RawMessage       `json:"pdus"`
	EDUs []gomatrixserverlib.EDU `json:"edus"`
}
