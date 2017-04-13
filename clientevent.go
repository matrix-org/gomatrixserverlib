/* Copyright 2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

import (
	"encoding/json"
)

// ClientEvent is an event which is fit for consumption by clients, in accordance with the specification.
type ClientEvent struct {
	Content        json.RawMessage `json:"content"`
	Sender         string          `json:"sender"`
	Type           string          `json:"type"`
	StateKey       *string         `json:"state_key,omitempty"`
	Unsigned       json.RawMessage `json:"unsigned,omitempty"`
	OriginServerTS int64           `json:"origin_server_ts"`
	EventID        string          `json:"event_id"`
}

// ToClientEvents converts server events to client events
func ToClientEvents(serverEvs []Event) []ClientEvent {
	evs := make([]ClientEvent, len(serverEvs))
	for i, se := range serverEvs {
		evs[i] = ToClientEvent(se)
	}
	return evs
}

// ToClientEvent converts a single server event to a client event
func ToClientEvent(se Event) ClientEvent {
	return ClientEvent{
		Content:        json.RawMessage(se.Content()),
		Sender:         se.Sender(),
		Type:           se.Type(),
		StateKey:       se.StateKey(),
		Unsigned:       json.RawMessage(se.Unsigned()),
		OriginServerTS: se.OriginServerTS(),
		EventID:        se.EventID(),
	}
}
