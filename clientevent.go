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

// ClientEvent is an event which is fit for consumption by clients, in accordance with the specification.
type ClientEvent struct {
	Content        rawJSON `json:"content"`
	EventID        string  `json:"event_id"`
	OriginServerTS int64   `json:"origin_server_ts"`
	// RoomID is omitted on /sync responses
	RoomID   string  `json:"room_id,omitempty"`
	Sender   string  `json:"sender"`
	StateKey *string `json:"state_key,omitempty"`
	Type     string  `json:"type"`
	Unsigned rawJSON `json:"unsigned,omitempty"`
}

// ToClientEvents converts server events to client events. If omitRoomIDs is true, the room_id will not be
// set on the resulting events.
func ToClientEvents(serverEvs []Event, omitRoomIDs bool) []ClientEvent {
	evs := make([]ClientEvent, len(serverEvs))
	for i, se := range serverEvs {
		evs[i] = ToClientEvent(se, omitRoomIDs)
	}
	return evs
}

// ToClientEvent converts a single server event to a client event. If omitRoomID is true, the room_id will
// not be populated.
func ToClientEvent(se Event, omitRoomID bool) ClientEvent {
	ce := ClientEvent{
		Content:        rawJSON(se.Content()),
		Sender:         se.Sender(),
		Type:           se.Type(),
		StateKey:       se.StateKey(),
		Unsigned:       rawJSON(se.Unsigned()),
		OriginServerTS: se.OriginServerTS(),
		EventID:        se.EventID(),
	}
	if !omitRoomID {
		ce.RoomID = se.RoomID()
	}
	return ce
}
