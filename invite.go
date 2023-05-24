// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gomatrixserverlib

import (
	"context"
	"encoding/json"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

type RoomQuerier interface {
	IsKnownRoom(ctx context.Context, roomID spec.RoomID) (bool, error)
}

type StateQuerier interface {
	GetAuthEvents(ctx context.Context, event PDU) (AuthEventProvider, error)
	GetState(ctx context.Context, roomID spec.RoomID, stateWanted []StateKeyTuple) ([]PDU, error)
}

type FederatedInviteClient interface {
	SendInvite(ctx context.Context, event PDU, strippedState []InviteStrippedState) (PDU, error)
}

// InviteStrippedState is a cut-down set of fields from room state
// events that allow the invited server to identify the room.
type InviteStrippedState struct {
	fields struct {
		Content  spec.RawJSON `json:"content"`
		StateKey *string      `json:"state_key"`
		Type     string       `json:"type"`
		Sender   string       `json:"sender"`
	}
}

// NewInviteStrippedState creates a stripped state event from a
// regular state event.
func NewInviteStrippedState(event PDU) (ss InviteStrippedState) {
	ss.fields.Content = event.Content()
	ss.fields.StateKey = event.StateKey()
	ss.fields.Type = event.Type()
	ss.fields.Sender = event.Sender()
	return
}

// MarshalJSON implements json.Marshaller
func (i InviteStrippedState) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteStrippedState) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &i.fields)
}

// Content returns the content of the stripped state.
func (i *InviteStrippedState) Content() spec.RawJSON {
	return i.fields.Content
}

// StateKey returns the state key of the stripped state.
func (i *InviteStrippedState) StateKey() *string {
	return i.fields.StateKey
}

// Type returns the type of the stripped state.
func (i *InviteStrippedState) Type() string {
	return i.fields.Type
}

// Sender returns the sender of the stripped state.
func (i *InviteStrippedState) Sender() string {
	return i.fields.Sender
}

func GenerateStrippedState(
	ctx context.Context, roomID spec.RoomID, stateWanted []StateKeyTuple, inviteEvent PDU, stateQuerier StateQuerier,
) ([]InviteStrippedState, error) {
	stateEvents, err := stateQuerier.GetState(ctx, roomID, stateWanted)
	if err != nil {
		return nil, err
	}
	if stateEvents != nil {
		inviteState := []InviteStrippedState{
			NewInviteStrippedState(inviteEvent),
		}
		stateEvents = append(stateEvents, inviteEvent)
		for _, event := range stateEvents {
			inviteState = append(inviteState, NewInviteStrippedState(event))
		}
		return inviteState, nil
	}
	return nil, nil
}
