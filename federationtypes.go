package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
)

// A SendRequest is the content of a request to PUT /_matrix/federation/v1/send/{txnID}/
type SendRequest Transaction

// A SendResponse is the content of a response to PUT /_matrix/federation/v1/send/{txnID}/
type SendResponse struct {
	// Map of string room event ID to the result of processing that event.
	PDUs map[string]PDUResult `json:"pdus"`
}

// A PDUResult is the result of processing a matrix room event.
type PDUResult struct {
	// If not empty then this is a human readable description of a problem
	// encountered processing an event.
	Error string `json:"error,omitempty"`
}

// A StateIDsResponse is the content of a response to GET /_matrix/federation/v1/state_ids/{roomID}/{eventID}
type StateIDsResponse struct {
	// A list of state event IDs for the state of the room before the requested event.
	StateEventIDs []string `json:"pdu_ids"`
	// A list of event IDs needed to authenticate the state events.
	AuthEventIDs []string `json:"auth_chain_ids"`
}

// A StateResponse is the content of a response to GET /_matrix/federation/v1/state/{roomID}/{eventID}
type StateResponse struct {
	// A list of events giving the state of the room before the request event.
	StateEvents []Event `json:"pdus"`
	// A list of events needed to authenticate the state events.
	AuthEvents []Event `json:"auth_chain"`
}

// A MakeJoinResponse is the content of a response to GET /_matrix/federation/v1/make_join/{roomID}/{userID}
type MakeJoinResponse struct {
	JoinEvent Event `json:"event"`
}

// A SendJoinRequest is the content of a request to PUT /_matrix/federation/v1/send_join/{roomID}/{eventID}
type SendJoinRequest Event

// A SendJoinResponse is the content of a response to PUT /_matrix/federation/v1/send_join/{roomID}/{eventID}
type SendJoinResponse StateResponse

// MarshalJSON implements json.Marshaller
func (r SendJoinResponse) MarshalJSON() ([]byte, error) {
	// SendJoinResponses contain the same data as a StateResponse but are
	// formatted slightly differently on the wire:
	//  1) The "pdus" field is renamed to "state".
	//  2) The object is placed as the second element of a two element list
	//     where the first element is the constant integer 200.
	//
	//
	// So a state response of:
	//
	//		{"pdus": x, "auth_chain": y}
	//
	// Becomes:
	//
	//      [200, {"state": x, "auth_chain": y}]
	//
	// (This protocol oddity is the result of a typo in the synapse matrix
	//  server, and is preserved to maintain compatibility.)

	return json.Marshal([]interface{}{200, sendJoinResponseFields{
		r.StateEvents, r.AuthEvents,
	}})
}

// UnmarshalJSON implements json.Unmarshaller
func (r *SendJoinResponse) UnmarshalJSON(data []byte) error {
	var tuple []rawJSON
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) != 2 {
		return fmt.Errorf("gomatrixserverlib: invalid send join response, invalid length: %d != 2", len(tuple))
	}
	var fields sendJoinResponseFields
	if err := json.Unmarshal(tuple[1], &fields); err != nil {
		return err
	}
	r.StateEvents = fields.StateEvents
	r.AuthEvents = fields.AuthEvents
	return nil
}

type sendJoinResponseFields struct {
	StateEvents []Event `json:"state"`
	AuthEvents  []Event `json:"auth_chain"`
}
