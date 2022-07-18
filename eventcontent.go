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
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// CreateContent is the JSON content of a m.room.create event along with
// the top level keys needed for auth.
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-create for descriptions of the fields.
type CreateContent struct {
	// We need the domain of the create event when checking federatability.
	senderDomain string
	// We need the roomID to check that events are in the same room as the create event.
	roomID string
	// We need the eventID to check the first join event in the room.
	eventID string
	// The "m.federate" flag tells us whether the room can be federated to other servers.
	Federate *bool `json:"m.federate,omitempty"`
	// The creator of the room tells us what the default power levels are.
	Creator string `json:"creator"`
	// The version of the room. Should be treated as "1" when the key doesn't exist.
	RoomVersion *RoomVersion `json:"room_version,omitempty"`
	// The predecessor of the room.
	Predecessor PreviousRoom `json:"predecessor,omitempty"`
}

// PreviousRoom is the "Previous Room" structure defined at https://matrix.org/docs/spec/client_server/r0.5.0#m-room-create
type PreviousRoom struct {
	RoomID  string `json:"room_id"`
	EventID string `json:"event_id"`
}

// NewCreateContentFromAuthEvents loads the create event content from the create event in the
// auth events.
func NewCreateContentFromAuthEvents(authEvents AuthEventProvider) (c CreateContent, err error) {
	var createEvent *Event
	if createEvent, err = authEvents.Create(); err != nil {
		return
	}
	if createEvent == nil {
		err = errorf("missing create event")
		return
	}
	if err = json.Unmarshal(createEvent.Content(), &c); err != nil {
		err = errorf("unparsable create event content: %s", err.Error())
		return
	}
	c.roomID = createEvent.RoomID()
	c.eventID = createEvent.EventID()
	if c.senderDomain, err = domainFromID(createEvent.Sender()); err != nil {
		return
	}
	return
}

// DomainAllowed checks whether the domain is allowed in the room by the
// "m.federate" flag.
func (c *CreateContent) DomainAllowed(domain string) error {
	if domain == c.senderDomain {
		// If the domain matches the domain of the create event then the event
		// is always allowed regardless of the value of the "m.federate" flag.
		return nil
	}
	if c.Federate == nil || *c.Federate {
		// The m.federate field defaults to true.
		// If the domains are different then event is only allowed if the
		// "m.federate" flag is absent or true.
		return nil
	}
	return errorf("room is unfederatable")
}

// UserIDAllowed checks whether the domain part of the user ID is allowed in
// the room by the "m.federate" flag.
func (c *CreateContent) UserIDAllowed(id string) error {
	domain, err := domainFromID(id)
	if err != nil {
		return err
	}
	return c.DomainAllowed(domain)
}

// domainFromID returns everything after the first ":" character to extract
// the domain part of a matrix ID.
func domainFromID(id string) (string, error) {
	// IDs have the format: SIGIL LOCALPART ":" DOMAIN
	// Split on the first ":" character since the domain can contain ":"
	// characters.
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		// The ID must have a ":" character.
		return "", errorf("invalid ID: %q", id)
	}
	// Return everything after the first ":" character.
	return parts[1], nil
}

// MemberContent is the JSON content of a m.room.member event needed for auth checks.
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-member for descriptions of the fields.
type MemberContent struct {
	// We use the membership key in order to check if the user is in the room.
	Membership  string `json:"membership"`
	DisplayName string `json:"displayname,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	Reason      string `json:"reason,omitempty"`
	IsDirect    bool   `json:"is_direct,omitempty"`
	// We use the third_party_invite key to special case thirdparty invites.
	ThirdPartyInvite *MemberThirdPartyInvite `json:"third_party_invite,omitempty"`
	// Restricted join rules require a user with invite permission to be nominated,
	// so that their membership can be included in the auth events.
	AuthorisedVia string `json:"join_authorised_via_users_server,omitempty"`
}

// MemberThirdPartyInvite is the "Invite" structure defined at http://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-member
type MemberThirdPartyInvite struct {
	DisplayName string                       `json:"display_name"`
	Signed      MemberThirdPartyInviteSigned `json:"signed"`
}

// MemberThirdPartyInviteSigned is the "signed" structure defined at http://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-member
type MemberThirdPartyInviteSigned struct {
	MXID       string                       `json:"mxid"`
	Signatures map[string]map[string]string `json:"signatures"`
	Token      string                       `json:"token"`
}

// NewMemberContentFromAuthEvents loads the member content from the member event for the user ID in the auth events.
// Returns an error if there was an error loading the member event or parsing the event content.
func NewMemberContentFromAuthEvents(authEvents AuthEventProvider, userID string) (c MemberContent, err error) {
	var memberEvent *Event
	if memberEvent, err = authEvents.Member(userID); err != nil {
		return
	}
	if memberEvent == nil {
		// If there isn't a member event then the membership for the user
		// defaults to leave.
		c.Membership = Leave
		return
	}
	return NewMemberContentFromEvent(memberEvent)
}

// NewMemberContentFromEvent parse the member content from an event.
// Returns an error if the content couldn't be parsed.
func NewMemberContentFromEvent(event *Event) (c MemberContent, err error) {
	if err = json.Unmarshal(event.Content(), &c); err != nil {
		var partial membershipContent
		if err = json.Unmarshal(event.Content(), &partial); err != nil {
			err = errorf("unparsable member event content: %s", err.Error())
			return
		}
		c.Membership = partial.Membership
		c.ThirdPartyInvite = partial.ThirdPartyInvite
	}
	return
}

// ThirdPartyInviteContent is the JSON content of a m.room.third_party_invite event needed for auth checks.
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-third-party-invite for descriptions of the fields.
type ThirdPartyInviteContent struct {
	DisplayName    string `json:"display_name"`
	KeyValidityURL string `json:"key_validity_url"`
	PublicKey      string `json:"public_key"`
	// Public keys are used to verify the signature of a m.room.member event that
	// came from a m.room.third_party_invite event
	PublicKeys []PublicKey `json:"public_keys"`
}

// PublicKey is the "PublicKeys" structure defined at https://matrix.org/docs/spec/client_server/r0.5.0#m-room-third-party-invite
type PublicKey struct {
	PublicKey      Base64Bytes `json:"public_key"`
	KeyValidityURL string      `json:"key_validity_url"`
}

// NewThirdPartyInviteContentFromAuthEvents loads the third party invite content from the third party invite event for the state key (token) in the auth events.
// Returns an error if there was an error loading the third party invite event or parsing the event content.
func NewThirdPartyInviteContentFromAuthEvents(authEvents AuthEventProvider, token string) (t ThirdPartyInviteContent, err error) {
	var thirdPartyInviteEvent *Event
	if thirdPartyInviteEvent, err = authEvents.ThirdPartyInvite(token); err != nil {
		return
	}
	if thirdPartyInviteEvent == nil {
		// If there isn't a third_party_invite event, then we return with an error
		err = errorf("Couldn't find third party invite event")
		return
	}
	if err = json.Unmarshal(thirdPartyInviteEvent.Content(), &t); err != nil {
		err = errorf("unparsable third party invite event content: %s", err.Error())
	}
	return
}

// HistoryVisibilityContent is the JSON content of a m.room.history_visibility event.
// See https://matrix.org/docs/spec/client_server/r0.6.0#room-history-visibility for descriptions of the fields.
type HistoryVisibilityContent struct {
	HistoryVisibility HistoryVisibility `json:"history_visibility"`
}

type HistoryVisibility string

const (
	HistoryVisibilityWorldReadable HistoryVisibility = "world_readable"
	HistoryVisibilityShared        HistoryVisibility = "shared"
	HistoryVisibilityInvited       HistoryVisibility = "invited"
	HistoryVisibilityJoined        HistoryVisibility = "joined"
)

// Scan implements sql.Scanner
func (h *HistoryVisibility) Scan(src interface{}) error {
	switch v := src.(type) {
	case int64:
		s, ok := hisVisIntToStringMapping[uint8(v)]
		if !ok { // history visibility is unknown, default to shared
			*h = HistoryVisibilityShared
			return nil
		}
		*h = s
		return nil
	case float64:
		s, ok := hisVisIntToStringMapping[uint8(v)]
		if !ok { // history visibility is unknown, default to shared
			*h = HistoryVisibilityShared
			return nil
		}
		*h = s
		return nil
	default:
		return fmt.Errorf("unknown source type: %T for HistoryVisibilty", src)
	}
}

// Value implements sql.Valuer
func (h HistoryVisibility) Value() (driver.Value, error) {
	v, ok := hisVisStringToIntMapping[h]
	if !ok {
		return int64(hisVisStringToIntMapping[HistoryVisibilityShared]), nil
	}
	return int64(v), nil
}

var hisVisStringToIntMapping = map[HistoryVisibility]uint8{
	HistoryVisibilityWorldReadable: 1, // Starting at 1, to avoid confusions with Go default values
	HistoryVisibilityShared:        2,
	HistoryVisibilityInvited:       3,
	HistoryVisibilityJoined:        4,
}

var hisVisIntToStringMapping = map[uint8]HistoryVisibility{
	1: HistoryVisibilityWorldReadable, // Starting at 1, to avoid confusions with Go default values
	2: HistoryVisibilityShared,
	3: HistoryVisibilityInvited,
	4: HistoryVisibilityJoined,
}

// JoinRuleContent is the JSON content of a m.room.join_rules event needed for auth checks.
// See  https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-join-rules for descriptions of the fields.
type JoinRuleContent struct {
	// We use the join_rule key to check whether join m.room.member events are allowed.
	JoinRule string                     `json:"join_rule"`
	Allow    []JoinRuleContentAllowRule `json:"allow,omitempty"`
}

type JoinRuleContentAllowRule struct {
	Type   string `json:"type"`
	RoomID string `json:"room_id"`
}

// NewJoinRuleContentFromAuthEvents loads the join rule content from the join rules event in the auth event.
// Returns an error if there was an error loading the join rule event or parsing the content.
func NewJoinRuleContentFromAuthEvents(authEvents AuthEventProvider) (c JoinRuleContent, err error) {
	// Start off with "invite" as the default. Hopefully the unmarshal
	// step later will replace it with a better value.
	c.JoinRule = Invite
	// Then see if the specified join event contains something better.
	joinRulesEvent, err := authEvents.JoinRules()
	if err != nil {
		return
	}
	if joinRulesEvent == nil {
		return
	}
	if err = json.Unmarshal(joinRulesEvent.Content(), &c); err != nil {
		err = errorf("unparsable join_rules event content: %s", err.Error())
		return
	}
	return
}

// PowerLevelContent is the JSON content of a m.room.power_levels event needed for auth checks.
// Typically the user calls NewPowerLevelContentFromAuthEvents instead of
// unmarshalling the content directly from JSON so defaults can be applied.
// However, the JSON key names are still preserved so it's possible to marshal
// the struct into JSON easily.
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-power-levels for descriptions of the fields.
type PowerLevelContent struct {
	Ban           int64            `json:"ban"`
	Invite        int64            `json:"invite"`
	Kick          int64            `json:"kick"`
	Redact        int64            `json:"redact"`
	Users         map[string]int64 `json:"users"`
	UsersDefault  int64            `json:"users_default"`
	Events        map[string]int64 `json:"events"`
	EventsDefault int64            `json:"events_default"`
	StateDefault  int64            `json:"state_default"`
	Notifications map[string]int64 `json:"notifications"`
}

// UserLevel returns the power level a user has in the room.
func (c *PowerLevelContent) UserLevel(userID string) int64 {
	level, ok := c.Users[userID]
	if ok {
		return level
	}
	return c.UsersDefault
}

// EventLevel returns the power level needed to send an event in the room.
func (c *PowerLevelContent) EventLevel(eventType string, isState bool) int64 {
	if eventType == MRoomThirdPartyInvite {
		// Special case third_party_invite events to have the same level as
		// m.room.member invite events.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L182
		return c.Invite
	}
	level, ok := c.Events[eventType]
	if ok {
		return level
	}
	if isState {
		return c.StateDefault
	}
	return c.EventsDefault
}

// UserLevel returns the power level a user has in the room.
func (c *PowerLevelContent) NotificationLevel(notification string) int64 {
	level, ok := c.Notifications[notification]
	if ok {
		return level
	}
	// https://matrix.org/docs/spec/client_server/r0.6.1#m-room-power-levels
	// room	integer	The level required to trigger an @room notification. Defaults to 50 if unspecified.
	return 50
}

// NewPowerLevelContentFromAuthEvents loads the power level content from the
// power level event in the auth events or returns the default values if there
// is no power level event.
func NewPowerLevelContentFromAuthEvents(authEvents AuthEventProvider, creatorUserID string) (c PowerLevelContent, err error) {
	powerLevelsEvent, err := authEvents.PowerLevels()
	if err != nil {
		return
	}
	if powerLevelsEvent != nil {
		return NewPowerLevelContentFromEvent(powerLevelsEvent)
	}

	// If there are no power levels then fall back to defaults.
	c.Defaults()
	// If there is no power level event then the creator gets level 100
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L569
	// If we want users to be able to set PLs > 100 with power_level_content_override
	// then we need to set the upper bound: maximum allowable JSON value is (2^53)-1.
	c.Users = map[string]int64{creatorUserID: 9007199254740991}
	// If there is no power level event then the state_default is level 50
	// https://github.com/matrix-org/synapse/blob/v1.38.0/synapse/event_auth.py#L437
	// Previously it was 0, but this was changed in:
	// https://github.com/matrix-org/synapse/commit/5c9afd6f80cf04367fe9b02c396af9f85e02a611
	c.StateDefault = 50
	return
}

// Defaults sets the power levels to their default values.
// See https://spec.matrix.org/v1.1/client-server-api/#mroompower_levels for defaults.
func (c *PowerLevelContent) Defaults() {
	c.Invite = 50
	c.Ban = 50
	c.Kick = 50
	c.Redact = 50
	c.UsersDefault = 0
	c.EventsDefault = 0
	c.StateDefault = 50
	c.Notifications = map[string]int64{
		"room": 50,
	}
}

// NewPowerLevelContentFromEvent loads the power level content from an event.
func NewPowerLevelContentFromEvent(event *Event) (c PowerLevelContent, err error) {
	// Set the levels to their default values.
	c.Defaults()

	var strict bool
	if strict, err = event.roomVersion.RequireIntegerPowerLevels(); err != nil {
		return
	} else if strict {
		// Unmarshal directly to PowerLevelContent, since that will kick up an
		// error if one of the power levels isn't an int64.
		if err = json.Unmarshal(event.Content(), &c); err != nil {
			err = errorf("unparsable power_levels event content: %s", err.Error())
			return
		}
	} else {
		// We can't extract the JSON directly to the powerLevelContent because we
		// need to convert string values to int values.
		var content struct {
			InviteLevel        levelJSONValue            `json:"invite"`
			BanLevel           levelJSONValue            `json:"ban"`
			KickLevel          levelJSONValue            `json:"kick"`
			RedactLevel        levelJSONValue            `json:"redact"`
			UserLevels         map[string]levelJSONValue `json:"users"`
			UsersDefaultLevel  levelJSONValue            `json:"users_default"`
			EventLevels        map[string]levelJSONValue `json:"events"`
			StateDefaultLevel  levelJSONValue            `json:"state_default"`
			EventDefaultLevel  levelJSONValue            `json:"event_default"`
			NotificationLevels map[string]levelJSONValue `json:"notifications"`
		}
		if err = json.Unmarshal(event.Content(), &content); err != nil {
			err = errorf("unparsable power_levels event content: %s", err.Error())
			return
		}

		// Update the levels with the values that are present in the event content.
		content.InviteLevel.assignIfExists(&c.Invite)
		content.BanLevel.assignIfExists(&c.Ban)
		content.KickLevel.assignIfExists(&c.Kick)
		content.RedactLevel.assignIfExists(&c.Redact)
		content.UsersDefaultLevel.assignIfExists(&c.UsersDefault)
		content.StateDefaultLevel.assignIfExists(&c.StateDefault)
		content.EventDefaultLevel.assignIfExists(&c.EventsDefault)

		for k, v := range content.UserLevels {
			if c.Users == nil {
				c.Users = make(map[string]int64)
			}
			c.Users[k] = v.value
		}

		for k, v := range content.EventLevels {
			if c.Events == nil {
				c.Events = make(map[string]int64)
			}
			c.Events[k] = v.value
		}

		for k, v := range content.NotificationLevels {
			if c.Notifications == nil {
				c.Notifications = make(map[string]int64)
			}
			c.Notifications[k] = v.value
		}
	}

	return
}

// A levelJSONValue is used for unmarshalling power levels from JSON.
// It is intended to replicate the effects of x = int(content["key"]) in python.
type levelJSONValue struct {
	// Was a value loaded from the JSON?
	exists bool
	// The integer value of the power level.
	value int64
}

func (v *levelJSONValue) UnmarshalJSON(data []byte) error {
	var stringValue string
	var int64Value int64
	var floatValue float64
	var err error

	// First try to unmarshal as an int64.
	if int64Value, err = strconv.ParseInt(string(data), 10, 64); err != nil {
		// If unmarshalling as an int64 fails try as a string.
		if err = json.Unmarshal(data, &stringValue); err != nil {
			// If unmarshalling as a string fails try as a float.
			if floatValue, err = strconv.ParseFloat(string(data), 64); err != nil {
				return err
			}
			int64Value = int64(floatValue)
		} else {
			// If we managed to get a string, try parsing the string as an int.
			int64Value, err = strconv.ParseInt(strings.TrimSpace(stringValue), 10, 64)
			if err != nil {
				return err
			}
		}
	}
	v.exists = true
	v.value = int64Value
	return nil
}

// assign the power level if a value was present in the JSON.
func (v *levelJSONValue) assignIfExists(to *int64) {
	if v.exists {
		*to = v.value
	}
}

// Check if the user ID is a valid user ID.
func isValidUserID(userID string) bool {
	// TODO: Do we want to add anymore checks beyond checking the sigil and that it has a domain part?
	return userID[0] == '@' && strings.IndexByte(userID, ':') != -1
}
