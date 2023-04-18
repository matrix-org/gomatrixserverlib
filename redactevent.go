/* Copyright 2016-2017 Vector Creations Ltd
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

	"github.com/matrix-org/gomatrixserverlib/spec"
)

// RedactEventJSON strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event.
func RedactEventJSON(eventJSON []byte, roomVersion RoomVersion) ([]byte, error) {

	// createContent keeps the fields needed in a m.room.create event.
	// Create events need to keep the creator.
	// (In an ideal world they would keep the m.federate flag see matrix-org/synapse#1831)
	type createContent struct {
		Creator spec.RawJSON `json:"creator,omitempty"`
	}

	// joinRulesContent keeps the fields needed in a m.room.join_rules event.
	// Join rules events need to keep the join_rule key.
	type joinRulesContent struct {
		JoinRule spec.RawJSON `json:"join_rule,omitempty"`
		Allow    spec.RawJSON `json:"allow,omitempty"`
	}

	// powerLevelContent keeps the fields needed in a m.room.power_levels event.
	// Power level events need to keep all the levels.
	type powerLevelContent struct {
		Users         spec.RawJSON `json:"users,omitempty"`
		UsersDefault  spec.RawJSON `json:"users_default,omitempty"`
		Events        spec.RawJSON `json:"events,omitempty"`
		EventsDefault spec.RawJSON `json:"events_default,omitempty"`
		StateDefault  spec.RawJSON `json:"state_default,omitempty"`
		Ban           spec.RawJSON `json:"ban,omitempty"`
		Kick          spec.RawJSON `json:"kick,omitempty"`
		Redact        spec.RawJSON `json:"redact,omitempty"`
	}

	// memberContent keeps the fields needed in a m.room.member event.
	// Member events keep the membership.
	// (In an ideal world they would keep the third_party_invite see matrix-org/synapse#1831)
	type memberContent struct {
		Membership    spec.RawJSON `json:"membership,omitempty"`
		AuthorisedVia string       `json:"join_authorised_via_users_server,omitempty"`
	}

	// aliasesContent keeps the fields needed in a m.room.aliases event.
	// TODO: Alias events probably don't need to keep the aliases key, but we need to match synapse here.
	type aliasesContent struct {
		Aliases spec.RawJSON `json:"aliases,omitempty"`
	}

	// historyVisibilityContent keeps the fields needed in a m.room.history_visibility event
	// History visibility events need to keep the history_visibility key.
	type historyVisibilityContent struct {
		HistoryVisibility spec.RawJSON `json:"history_visibility,omitempty"`
	}

	// allContent keeps the union of all the content fields needed across all the event types.
	// All the content JSON keys we are keeping are distinct across the different event types.
	type allContent struct {
		createContent
		joinRulesContent
		powerLevelContent
		memberContent
		aliasesContent
		historyVisibilityContent
	}

	// eventFields keeps the top level keys needed by all event types.
	// (In an ideal world they would include the "redacts" key for m.room.redaction events, see matrix-org/synapse#1831)
	// See https://github.com/matrix-org/synapse/blob/v0.18.7/synapse/events/utils.py#L42-L56 for the list of fields
	type eventFields struct {
		EventID        spec.RawJSON `json:"event_id,omitempty"`
		Sender         spec.RawJSON `json:"sender,omitempty"`
		RoomID         spec.RawJSON `json:"room_id,omitempty"`
		Hashes         spec.RawJSON `json:"hashes,omitempty"`
		Signatures     spec.RawJSON `json:"signatures,omitempty"`
		Content        allContent   `json:"content"`
		Type           string       `json:"type"`
		StateKey       spec.RawJSON `json:"state_key,omitempty"`
		Depth          spec.RawJSON `json:"depth,omitempty"`
		PrevEvents     spec.RawJSON `json:"prev_events,omitempty"`
		PrevState      spec.RawJSON `json:"prev_state,omitempty"`
		AuthEvents     spec.RawJSON `json:"auth_events,omitempty"`
		Origin         spec.RawJSON `json:"origin,omitempty"`
		OriginServerTS spec.RawJSON `json:"origin_server_ts,omitempty"`
		Membership     spec.RawJSON `json:"membership,omitempty"`
	}

	var event eventFields
	// Unmarshalling into a struct will discard any extra fields from the event.
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}
	var newContent allContent
	// Copy the content fields that we should keep for the event type.
	// By default we copy nothing leaving the content object empty.
	switch event.Type {
	case MRoomCreate:
		newContent.createContent = event.Content.createContent
	case MRoomMember:
		newContent.memberContent = event.Content.memberContent
		if algo, err := roomVersion.RedactionAlgorithm(); err != nil {
			return nil, err
		} else if algo < RedactionAlgorithmV4 {
			// We only stopped redacting the 'join_authorised_via_users_server'
			// key in room version 9, so if the algorithm used is from an older
			// room version, we should ensure this field is redacted.
			newContent.memberContent.AuthorisedVia = ""
		}
	case MRoomJoinRules:
		newContent.joinRulesContent = event.Content.joinRulesContent
		if algo, err := roomVersion.RedactionAlgorithm(); err != nil {
			return nil, err
		} else if algo < RedactionAlgorithmV3 {
			// We only stopped redacting the 'allow' key in room version 8,
			// so if the algorithm used is from an older room version, we
			// should ensure this field is redacted.
			newContent.joinRulesContent.Allow = nil
		}
	case MRoomPowerLevels:
		newContent.powerLevelContent = event.Content.powerLevelContent
	case MRoomHistoryVisibility:
		newContent.historyVisibilityContent = event.Content.historyVisibilityContent
	case MRoomAliases:
		if algo, err := roomVersion.RedactionAlgorithm(); err != nil {
			return nil, err
		} else if algo == RedactionAlgorithmV1 {
			newContent.aliasesContent = event.Content.aliasesContent
		}
	}
	// Replace the content with our new filtered content.
	// This will zero out any keys that weren't copied in the switch statement above.
	event.Content = newContent
	// Return the redacted event encoded as JSON.
	return json.Marshal(&event)
}
