// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pdu

import (
	"encoding/json"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib"
)

type Event interface {
	GetRoomID() string
	GetEventID() string
	Version() gomatrixserverlib.RoomVersion
	GetType() string
	Verify() error
	Redact() error
}

// V1 represents a JSON marshal-able Matrix federation event, for room version 1.
type V1 struct {
	RoomID         string                             `json:"room_id"`
	Sender         string                             `json:"sender"`
	Type           string                             `json:"type"`
	StateKey       *string                            `json:"state_key"`
	Content        json.RawMessage                    `json:"content"`
	Redacts        string                             `json:"redacts"`
	Depth          int64                              `json:"depth"`
	Unsigned       json.RawMessage                    `json:"unsigned"`
	OriginServerTS gomatrixserverlib.Timestamp        `json:"origin_server_ts"`
	EventID        string                             `json:"event_id,omitempty"`
	PrevEvents     []gomatrixserverlib.EventReference `json:"prev_events"`
	AuthEvents     []gomatrixserverlib.EventReference `json:"auth_events"`
	Hashes         gomatrixserverlib.HashValues       `json:"hashes"`
}

func (v *V1) GetRoomID() string                      { return v.RoomID }
func (v *V1) GetEventID() string                     { return v.EventID }
func (v *V1) Version() gomatrixserverlib.RoomVersion { return gomatrixserverlib.RoomVersionV1 }
func (v *V1) GetType() string                        { return v.Type }

// Implements the redaction algorithm v1
func (v *V1) Redact() error {
	return nil // TODO
}

func (v *V1) Verify() error {
	// 1. Is a valid event, otherwise it is dropped. For an event to be valid, it must contain a room_id,
	// and it must comply with the event format of that room version.
	if v.RoomID == "" {
		// NB: this event already complies with the event format as it is deserialised already.
		// We expect json.Unmarshal errors to have been handled prior to calling Verify.
		return fmt.Errorf("PDU stage 1 validation failed: missing room_id")
	}

	// 2. Passes signature checks, otherwise it is dropped.
	// TODO Call new VerifySignatureV1 function

	// 3. Passes hash checks, otherwise it is redacted before being processed further.
	// TODO Call VerifyHashV1 function

	// 4. Passes authorization rules based on the event’s auth events, otherwise it is rejected.
	// TODO map AuthEvents to an AuthEventProvider, then call AllowedV1()

	// 5. Passes authorization rules based on the state before the event, otherwise it is rejected.
	// TODO call StateNeeded and provide PrevEvents then call something which can get an AuthEventProvider, then call AllowedV1()
	// XXX how to handle /send_join responses which provide the complete state? The prev_events are useless in that scenario.

	// 6. Passes authorization rules based on the current state of the room, otherwise it is “soft failed”.
	// TODO call StateNeeded and signal current state somehow then call something which can get an AuthEventProvider, then call AllowedV1()
	return nil
}
