package gomatrixserverlib

import (
	"encoding/json"
)

// A Transaction is used to push data from one matrix server to another matrix
// server.
type Transaction struct {
	// The ID of the transaction.
	TransactionID TransactionID `json:"transaction_id"`
	// The server that sent the transaction.
	Origin ServerName `json:"origin"`
	// The server that should receive the transaction.
	Destination ServerName `json:"destination"`
	// The millisecond posix timestamp on the origin server when the transction
	// was created.
	OriginServerTS Timestamp `json:"origin_server_ts"`
	// The IDs of the most recent transactions sent by the server.
	// Mutliple transactions can be sent in parallel so there may be
	// more than one previous transaction.
	PreviousIDs []TransactionID `json:"previous_ids"`
	// The room events pushed by this transaction.
	PDUs []Event `json:"pdus"`
	// The ephemeral events pushed by this transaction.
	EDUs []EDU `json:"edus"`
}

// A TransactionID identifies a transaction sent by a matrix server to another
// matrix server. The ID must be unique amoungst the transactions sent from the
// origin server to the destination, but doesn't have to be globally unique.
type TransactionID string

// An EDU is used to transmit ephemeral data such as presence and typing from
// one matrix server to another.
type EDU struct {
	// The type of the EDU, this tells the receiver how to interpret the
	// contents.
	EDUType string
	// The JSON content of the EDU.
	Content []byte
}

// SetContent sets the JSON "content" of an EDU.
// Returns an error if there was a problem encoding the JSON.
func (e *EDU) SetContent(content interface{}) (err error) {
	e.Content, err = json.Marshal(content)
	return
}

type eduFields struct {
	EDUType string  `json:"edu_type"`
	Content rawJSON `json:"content"`
}

// MarshalJSON implements json.Marshaller
func (e EDU) MarshalJSON() (data []byte, err error) {
	data, err = json.Marshal(eduFields{e.EDUType, rawJSON(e.Content)})
	return
}

// UnmarshalJSON implements json.Unmarshaller
func (e *EDU) UnmarshalJSON(data []byte) error {
	var fields eduFields
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	e.EDUType = fields.EDUType
	e.Content = []byte(fields.Content)
	return nil
}
