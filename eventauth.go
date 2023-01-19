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
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/matrix-org/util"
)

const (
	// Join is the string constant "join"
	Join = "join"
	// Ban is the string constant "ban"
	Ban = "ban"
	// Leave is the string constant "leave"
	Leave = "leave"
	// Invite is the string constant "invite"
	Invite = "invite"
	// Knock is the string constant "knock"
	Knock = "knock"
	// Restricted is the string constant "restricted"
	Restricted = "restricted"
	// NOTSPEC: Restricted is the string constant "knock_restricted" (MSC3787)
	// REVIEW: the MSC is merged though... so is this specced? Idk.
	KnockRestricted = "knock_restricted"
	// NOTSPEC: Peek is the string constant "peek" (MSC2753, used as the label in the sync block)
	Peek = "peek"
	// Public is the string constant "public"
	Public = "public"
	// WorldReadable is the string constant "world_readable"
	WorldReadable = "world_readable"
	// MRoomCreate https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-create
	MRoomCreate = "m.room.create"
	// MRoomJoinRules https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-join-rules
	MRoomJoinRules = "m.room.join_rules"
	// MRoomPowerLevels https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-power-levels
	MRoomPowerLevels = "m.room.power_levels"
	// MRoomName https://matrix.org/docs/spec/client_server/r0.6.0#m-room-name
	MRoomName = "m.room.name"
	// MRoomTopic https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-topic
	MRoomTopic = "m.room.topic"
	// MRoomAvatar https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-avatar
	MRoomAvatar = "m.room.avatar"
	// MRoomMember https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-member
	MRoomMember = "m.room.member"
	// MRoomThirdPartyInvite https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-third-party-invite
	MRoomThirdPartyInvite = "m.room.third_party_invite"
	// MRoomAliases https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-aliases
	MRoomAliases = "m.room.aliases"
	// MRoomCanonicalAlias https://matrix.org/docs/spec/client_server/r0.6.0#m-room-canonical-alias
	MRoomCanonicalAlias = "m.room.canonical_alias"
	// MRoomHistoryVisibility https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-history-visibility
	MRoomHistoryVisibility = "m.room.history_visibility"
	// MRoomGuestAccess https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-guest-access
	MRoomGuestAccess = "m.room.guest_access"
	// MRoomEncryption https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-encryption
	MRoomEncryption = "m.room.encryption"
	// MRoomRedaction https://matrix.org/docs/spec/client_server/r0.2.0.html#id21
	MRoomRedaction = "m.room.redaction"
	// MTyping https://matrix.org/docs/spec/client_server/r0.3.0.html#m-typing
	MTyping = "m.typing"
	// MDirectToDevice https://matrix.org/docs/spec/server_server/r0.1.3#send-to-device-messaging
	MDirectToDevice = "m.direct_to_device"
	// MDeviceListUpdate https://matrix.org/docs/spec/server_server/latest#m-device-list-update-schema
	MDeviceListUpdate = "m.device_list_update"
	// MReceipt https://matrix.org/docs/spec/server_server/r0.1.4#receipts
	MReceipt = "m.receipt"
	// MPresence https://matrix.org/docs/spec/server_server/latest#m-presence-schema
	MPresence = "m.presence"
	// MRoomMembership https://github.com/matrix-org/matrix-doc/blob/clokep/restricted-rooms/proposals/3083-restricted-rooms.md
	MRoomMembership = "m.room_membership"
)

// StateNeeded lists the event types and state_keys needed to authenticate an event.
type StateNeeded struct {
	// Is the m.room.create event needed to auth the event.
	Create bool
	// Is the m.room.join_rules event needed to auth the event.
	JoinRules bool
	// Is the m.room.power_levels event needed to auth the event.
	PowerLevels bool
	// List of m.room.member state_keys needed to auth the event
	Member []string
	// List of m.room.third_party_invite state_keys
	ThirdPartyInvite []string
}

// Tuples returns the needed state key tuples for performing auth on an event.
func (s StateNeeded) Tuples() (res []StateKeyTuple) {
	if s.Create {
		res = append(res, StateKeyTuple{MRoomCreate, ""})
	}
	if s.JoinRules {
		res = append(res, StateKeyTuple{MRoomJoinRules, ""})
	}
	if s.PowerLevels {
		res = append(res, StateKeyTuple{MRoomPowerLevels, ""})
	}
	for _, userID := range s.Member {
		res = append(res, StateKeyTuple{MRoomMember, userID})
	}
	for _, token := range s.ThirdPartyInvite {
		res = append(res, StateKeyTuple{MRoomThirdPartyInvite, token})
	}
	return
}

// AuthEventReferences returns the auth_events references for the StateNeeded. Returns an error if the
// provider returns an error. If an event is missing from the provider but is required in StateNeeded, it
// is skipped over: no error is returned.
func (s StateNeeded) AuthEventReferences(provider AuthEventProvider) (refs []EventReference, err error) { // nolint: gocyclo
	refs = []EventReference{}
	var e *Event
	if s.Create {
		if e, err = provider.Create(); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventReference())
		}
	}
	if s.JoinRules {
		if e, err = provider.JoinRules(); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventReference())
		}
	}
	if s.PowerLevels {
		if e, err = provider.PowerLevels(); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventReference())
		}
	}
	for _, userID := range s.Member {
		if e, err = provider.Member(userID); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventReference())
		}
	}
	for _, token := range s.ThirdPartyInvite {
		if e, err = provider.ThirdPartyInvite(token); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventReference())
		}
	}
	return
}

// The minimum amount of information we need to accumulate state for a membership event.
type membershipContent struct {
	Membership string `json:"membership"`
	// We use the third_party_invite key to special case thirdparty invites.
	ThirdPartyInvite *MemberThirdPartyInvite `json:"third_party_invite,omitempty"`
	// The user that authorised the join, in the case that the restricted join
	// rule is in effect.
	AuthorizedVia string `json:"join_authorised_via_users_server,omitempty"`
}

// StateNeededForEventBuilder returns the event types and state_keys needed to authenticate the
// event being built. These events should be put under 'auth_events' for the event being built.
// Returns an error if the state needed could not be calculated with the given builder, e.g
// if there is a m.room.member without a membership key.
func StateNeededForEventBuilder(builder *EventBuilder) (result StateNeeded, err error) {
	// Extract the 'content' object from the event if it is m.room.member as we need to know 'membership'
	var content *membershipContent
	if builder.Type == MRoomMember {
		if err = json.Unmarshal(builder.Content, &content); err != nil {
			err = errorf("unparsable member event content: %s", err.Error())
			return
		}
	}
	err = accumulateStateNeeded(&result, builder.Type, builder.Sender, builder.StateKey, content)
	result.Member = util.UniqueStrings(result.Member)
	result.ThirdPartyInvite = util.UniqueStrings(result.ThirdPartyInvite)
	return
}

// StateNeededForAuth returns the event types and state_keys needed to authenticate an event.
// This takes a list of events to facilitate bulk processing when doing auth checks as part of state conflict resolution.
func StateNeededForAuth(events []*Event) (result StateNeeded) {
	for _, event := range events {
		// Extract the 'content' object from the event if it is m.room.member as we need to know 'membership'
		var content *membershipContent
		if event.Type() == MRoomMember {
			_ = json.Unmarshal(event.Content(), &content)
		}
		// Ignore errors when accumulating state needed.
		// The event will be rejected when the actual checks encounter the same error.
		_ = accumulateStateNeeded(&result, event.Type(), event.Sender(), event.StateKey(), content)
	}

	// Deduplicate the state keys.
	result.Member = util.UniqueStrings(result.Member)
	result.ThirdPartyInvite = util.UniqueStrings(result.ThirdPartyInvite)
	return
}

func accumulateStateNeeded(result *StateNeeded, eventType, sender string, stateKey *string, content *membershipContent) (err error) {
	switch eventType {
	case MRoomCreate:
		// The create event doesn't require any state to authenticate.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L123
	case MRoomAliases:
		// Alias events need:
		//  * The create event.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L128
		// Alias events need no further authentication.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L160
		result.Create = true
	case MRoomMember:
		// Member events need:
		//  * The previous membership of the target.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L355
		//  * The current membership state of the sender.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L348
		//  * The join rules for the room if the event is a join event.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L361
		//  * The power levels for the room.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L370
		//  * And optionally may require a m.third_party_invite event
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L393
		//  * If using a restricted join rule, we should also include the membership event
		//    of the user nominated in the `join_authorised_via_users_server` key
		//    https://github.com/matrix-org/matrix-doc/blob/clokep/restricted-rooms/proposals/3083-restricted-rooms.md
		if content == nil {
			err = errorf("missing memberContent for m.room.member event")
			return
		}
		result.Create = true
		result.PowerLevels = true
		if stateKey != nil {
			result.Member = append(result.Member, sender, *stateKey)
		}
		if content.Membership == Join || content.Membership == Knock || content.Membership == Invite {
			result.JoinRules = true
		}
		if content.ThirdPartyInvite != nil {
			token, tokErr := thirdPartyInviteToken(content.ThirdPartyInvite)
			if tokErr != nil {
				err = errorf("could not get third-party token: %s", tokErr)
				return
			}
			result.ThirdPartyInvite = append(result.ThirdPartyInvite, token)
		}
		if content.AuthorizedVia != "" {
			result.Member = append(result.Member, content.AuthorizedVia)
		}
	default:
		// All other events need:
		//  * The membership of the sender.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L177
		//  * The power levels for the room.
		//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L196
		result.Create = true
		result.PowerLevels = true
		result.Member = append(result.Member, sender)
	}
	return
}

// thirdPartyInviteToken extracts the token from the third_party_invite.
func thirdPartyInviteToken(thirdPartyInvite *MemberThirdPartyInvite) (string, error) {
	if thirdPartyInvite.Signed.Token == "" {
		return "", fmt.Errorf("missing 'third_party_invite.signed.token' JSON key")
	}
	return thirdPartyInvite.Signed.Token, nil
}

// AuthEventProvider provides auth_events for the authentication checks.
type AuthEventProvider interface {
	// Create returns the m.room.create event for the room or nil if there isn't a m.room.create event.
	Create() (*Event, error)
	// JoinRules returns the m.room.join_rules event for the room or nil if there isn't a m.room.join_rules event.
	JoinRules() (*Event, error)
	// PowerLevels returns the m.room.power_levels event for the room or nil if there isn't a m.room.power_levels event.
	PowerLevels() (*Event, error)
	// Member returns the m.room.member event for the given user_id state_key or nil if there isn't a m.room.member event.
	Member(stateKey string) (*Event, error)
	// ThirdPartyInvite returns the m.room.third_party_invite event for the
	// given state_key or nil if there isn't a m.room.third_party_invite event
	ThirdPartyInvite(stateKey string) (*Event, error)
	// Valid verifies that all auth events are from the same room.
	Valid() bool
}

// AuthEvents is an implementation of AuthEventProvider backed by a map.
type AuthEvents struct {
	events  map[StateKeyTuple]*Event
	roomIDs map[string]struct{}
}

// Valid verifies that all auth events are from the same room.
func (a *AuthEvents) Valid() bool {
	return len(a.roomIDs) <= 1
}

// AddEvent adds an event to the provider. If an event already existed for the (type, state_key) then
// the event is replaced with the new event. Only returns an error if the event is not a state event.
func (a *AuthEvents) AddEvent(event *Event) error {
	if event.StateKey() == nil {
		return fmt.Errorf("AddEvent: event %q does not have a state key", event.Type())
	}
	a.roomIDs[event.RoomID()] = struct{}{}
	a.events[StateKeyTuple{event.Type(), *event.StateKey()}] = event
	return nil
}

// Create implements AuthEventProvider
func (a *AuthEvents) Create() (*Event, error) {
	return a.events[StateKeyTuple{MRoomCreate, ""}], nil
}

// JoinRules implements AuthEventProvider
func (a *AuthEvents) JoinRules() (*Event, error) {
	return a.events[StateKeyTuple{MRoomJoinRules, ""}], nil
}

// PowerLevels implements AuthEventProvider
func (a *AuthEvents) PowerLevels() (*Event, error) {
	return a.events[StateKeyTuple{MRoomPowerLevels, ""}], nil
}

// Member implements AuthEventProvider
func (a *AuthEvents) Member(stateKey string) (*Event, error) {
	return a.events[StateKeyTuple{MRoomMember, stateKey}], nil
}

// ThirdPartyInvite implements AuthEventProvider
func (a *AuthEvents) ThirdPartyInvite(stateKey string) (*Event, error) {
	return a.events[StateKeyTuple{MRoomThirdPartyInvite, stateKey}], nil
}

// Clear removes all entries from the AuthEventProvider.
func (a *AuthEvents) Clear() {
	for k := range a.events {
		delete(a.events, k)
	}
}

// NewAuthEvents returns an AuthEventProvider backed by the given events. New events can be added by
// calling AddEvent().
func NewAuthEvents(events []*Event) AuthEvents {
	a := AuthEvents{
		events:  make(map[StateKeyTuple]*Event, len(events)),
		roomIDs: make(map[string]struct{}),
	}
	for _, e := range events {
		a.AddEvent(e) // nolint: errcheck
	}
	return a
}

// A NotAllowed error is returned if an event does not pass the auth checks.
type NotAllowed struct {
	Message string
}

func (a *NotAllowed) Error() string {
	return "eventauth: " + a.Message
}

func errorf(message string, args ...interface{}) error {
	return &NotAllowed{Message: fmt.Sprintf(message, args...)}
}

// allowerContext allows auth checks to be run using cached create,
// power level and join rule events. This can help when authing a large
// state set for a specific room.
type allowerContext struct {
	// The auth event provider. This must be set.
	provider AuthEventProvider

	// Event references used to see when we need to update.
	createEvent      *Event // The m.room.create event for the room.
	powerLevelsEvent *Event // The m.room.power_levels event for the room.
	joinRuleEvent    *Event // The m.room.join_rules event for the room.

	// Event contents used for quick lookup.
	create      CreateContent     // The m.room.create content for the room.
	powerLevels PowerLevelContent // The m.room.power_levels content for the room.
	joinRule    JoinRuleContent   // The m.room.join_rules content for the room.
}

func newAllowerContext(provider AuthEventProvider) *allowerContext {
	a := &allowerContext{}
	a.update(provider)
	return a
}

// update updates the auth event provider with new event contents.
// It will wipe the state if a new provider is given. If the same provider
// is given then it will only unmarshal event contents if the provided events
// have changed, to reduce allocations in state resolution.
func (a *allowerContext) update(provider AuthEventProvider) {
	if provider != a.provider {
		a.provider = provider
		a.createEvent, a.powerLevelsEvent, a.joinRuleEvent = nil, nil, nil
	}
	if e, _ := provider.Create(); a.createEvent == nil || a.createEvent != e {
		if c, err := NewCreateContentFromAuthEvents(provider); err == nil {
			a.createEvent = e
			a.create = c
		}
	}
	if e, _ := provider.PowerLevels(); a.powerLevelsEvent == nil || a.powerLevelsEvent != e {
		if p, err := NewPowerLevelContentFromAuthEvents(provider, a.create.Creator); err == nil {
			a.powerLevelsEvent = e
			a.powerLevels = p
		}
	}
	if e, _ := provider.JoinRules(); a.joinRuleEvent == nil || a.joinRuleEvent != e {
		if j, err := NewJoinRuleContentFromAuthEvents(provider); err == nil {
			a.joinRuleEvent, _ = provider.JoinRules()
			a.joinRule = j
		}
	}
}

// Allowed checks whether an event is allowed by the auth events, using the
// create, power level and join events from the allowerContext. This is a
// quick path designed to speed up state resolution.
// It returns a NotAllowed error if the event is not allowed.
// If there was an error loading the auth events then it returns that error.
func (a *allowerContext) allowed(event *Event) error {
	switch event.Type() {
	case MRoomCreate:
		return a.createEventAllowed(event)
	case MRoomAliases:
		return a.aliasEventAllowed(event)
	case MRoomMember:
		return a.memberEventAllowed(event)
	case MRoomPowerLevels:
		return a.powerLevelsEventAllowed(event)
	case MRoomRedaction:
		return a.redactEventAllowed(event)
	default:
		return a.defaultEventAllowed(event)
	}
}

// Allowed checks whether an event is allowed by the auth events.
// It returns a NotAllowed error if the event is not allowed.
// If there was an error loading the auth events then it returns that error.
func Allowed(event *Event, authEvents AuthEventProvider) error {
	if !authEvents.Valid() {
		return errorf("authEvents contains events from different rooms")
	}
	return newAllowerContext(authEvents).allowed(event)
}

// createEventAllowed checks whether the m.room.create event is allowed.
// It returns an error if the event is not allowed.
func (a *allowerContext) createEventAllowed(event *Event) error {
	if !event.StateKeyEquals("") {
		return errorf("create event state key is not empty: %v", event.StateKey())
	}
	if len(event.PrevEvents()) > 0 {
		return errorf("create event must be the first event in the room: found %d prev_events", len(event.PrevEvents()))
	}
	roomIDDomain, err := domainFromID(event.RoomID())
	if err != nil {
		return err
	}
	senderDomain, err := domainFromID(event.Sender())
	if err != nil {
		return err
	}
	if senderDomain != roomIDDomain {
		return errorf("create event room ID domain does not match sender: %q != %q", roomIDDomain, senderDomain)
	}
	c := struct {
		Creator     *string      `json:"creator"`
		RoomVersion *RoomVersion `json:"room_version"`
	}{}
	if err := json.Unmarshal(event.Content(), &c); err != nil {
		return errorf("create event has invalid content: %s", err.Error())
	}
	if c.Creator == nil {
		return errorf("create event has no creator field")
	}
	if c.RoomVersion != nil {
		if _, err := c.RoomVersion.EventFormat(); err != nil {
			return errorf("create event has unrecognised room version %q", *c.RoomVersion)
		}
	}
	return nil
}

// memberEventAllowed checks whether the m.room.member event is allowed.
// Membership events have different authentication rules to ordinary events.
func (a *allowerContext) memberEventAllowed(event *Event) error {
	allower, err := a.newMembershipAllower(a.provider, event)
	if err != nil {
		return err
	}
	return allower.membershipAllowed(event)
}

// aliasEventAllowed checks whether the m.room.aliases event is allowed.
// Alias events have different authentication rules to ordinary events.
func (a *allowerContext) aliasEventAllowed(event *Event) error {
	// The alias events have different auth rules to ordinary events.
	// In particular we allow any server to send a m.room.aliases event without checking if the sender is in the room.
	// This allows server admins to update the m.room.aliases event for their server when they change the aliases on their server.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L143-L160

	senderDomain, err := domainFromID(event.Sender())
	if err != nil {
		return err
	}

	if event.RoomID() != a.create.roomID {
		return errorf(
			"create event has different roomID: %q (%s) != %q (%s)",
			event.RoomID(), event.EventID(), a.create.roomID, a.create.eventID,
		)
	}

	// Check that server is allowed in the room by the m.room.federate flag.
	if err := a.create.DomainAllowed(senderDomain); err != nil {
		return err
	}

	// Check that event is a state event.
	// Check that the state key matches the server sending this event.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L158
	if !event.StateKeyEquals(senderDomain) {
		return errorf("alias state_key does not match sender domain, %q != %q", senderDomain, *event.StateKey())
	}

	return nil
}

// powerLevelsEventAllowed checks whether the m.room.power_levels event is allowed.
// It returns an error if the event is not allowed or if there was a problem
// loading the auth events needed.
func (a *allowerContext) powerLevelsEventAllowed(event *Event) error {
	allower, err := a.newEventAllower(event.Sender())
	if err != nil {
		return err
	}

	// power level events must pass the default checks.
	// These checks will catch if the user has a high enough level to set a m.room.power_levels state event.
	if err = allower.commonChecks(event); err != nil {
		return err
	}

	// Parse the power levels.
	newPowerLevels, err := NewPowerLevelContentFromEvent(event)
	if err != nil {
		return err
	}

	// Check that the user levels are all valid user IDs
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1063
	for userID := range newPowerLevels.Users {
		if !isValidUserID(userID) {
			return errorf("Not a valid user ID: %q", userID)
		}
	}

	// Grab the old levels so that we can compare new the levels against them.
	oldPowerLevels := a.powerLevels
	senderLevel := oldPowerLevels.UserLevel(event.Sender())

	// Check that the changes in event levels are allowed.
	if err = checkEventLevels(senderLevel, oldPowerLevels, newPowerLevels); err != nil {
		return err
	}

	// Check that the changes in notification levels are allowed.
	if notifs, err := event.roomVersion.PowerLevelsIncludeNotifications(); err == nil && notifs {
		if err = checkNotificationLevels(senderLevel, oldPowerLevels, newPowerLevels); err != nil {
			return err
		}
	}

	// Check that the changes in user levels are allowed.
	return checkUserLevels(senderLevel, event.Sender(), oldPowerLevels, newPowerLevels)
}

// checkEventLevels checks that the changes in event levels are allowed.
func checkEventLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	type levelPair struct {
		old int64
		new int64
	}
	// Build a list of event levels to check.
	// This differs slightly in behaviour from the code in synapse because it will use the
	// default value if a level is not present in one of the old or new events.

	// First add all the named levels.
	levelChecks := []levelPair{
		{oldPowerLevels.Ban, newPowerLevels.Ban},
		{oldPowerLevels.Invite, newPowerLevels.Invite},
		{oldPowerLevels.Kick, newPowerLevels.Kick},
		{oldPowerLevels.Redact, newPowerLevels.Redact},
		{oldPowerLevels.StateDefault, newPowerLevels.StateDefault},
		{oldPowerLevels.EventsDefault, newPowerLevels.EventsDefault},
	}

	// Then add checks for each event key in the new levels.
	// We use the default values for non-state events when applying the checks.
	// TODO: the per event levels do not distinguish between state and non-state events.
	// However the default values do make that distinction. We may want to change this.
	// For example if there is an entry for "my.custom.type" events it sets the level
	// for sending the event with and without a "state_key". But if there is no entry
	// for "my.custom.type it will use the state default when sent with a "state_key"
	// and will use the event default when sent without.
	const (
		isStateEvent = false
	)
	for eventType := range newPowerLevels.Events {
		levelChecks = append(levelChecks, levelPair{
			oldPowerLevels.EventLevel(eventType, isStateEvent),
			newPowerLevels.EventLevel(eventType, isStateEvent),
		})
	}

	// Then add checks for each event key in the old levels.
	// Some of these will be duplicates of the ones added using the keys from
	// the new levels. But it doesn't hurt to run the checks twice for the same level.
	for eventType := range oldPowerLevels.Events {
		levelChecks = append(levelChecks, levelPair{
			oldPowerLevels.EventLevel(eventType, isStateEvent),
			newPowerLevels.EventLevel(eventType, isStateEvent),
		})
	}

	// Check each of the levels in the list.
	for _, level := range levelChecks {
		// Check if the level is being changed.
		if level.old == level.new {
			// Levels are always allowed to stay the same.
			continue
		}

		// Users are allowed to change the level for an event if:
		//   * the old level was less than or equal to their own
		//   * the new level was less than or equal to their own
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1134

		// Check if the user is trying to set any of the levels to above their own.
		if senderLevel < level.new {
			return errorf(
				"sender with level %d is not allowed to change level from %d to %d"+
					" because the new level is above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}

		// Check if the user is trying to set a level that was above their own.
		if senderLevel < level.old {
			return errorf(
				"sender with level %d is not allowed to change level from %d to %d"+
					" because the current level is above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}
	}

	return nil
}

// checkUserLevels checks that the changes in user levels are allowed.
func checkUserLevels(senderLevel int64, senderID string, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	type levelPair struct {
		old int64
		new int64
	}

	// Build a list of user levels to check.
	userLevelChecks := map[string]levelPair{}
	for userID := range newPowerLevels.Users {
		userLevelChecks[userID] = levelPair{
			old: oldPowerLevels.UserLevel(userID),
			new: newPowerLevels.UserLevel(userID),
		}
	}

	// also add old levels to check for e.g. deletions
	for userID := range oldPowerLevels.Users {
		userLevelChecks[userID] = levelPair{
			old: oldPowerLevels.UserLevel(userID),
			new: newPowerLevels.UserLevel(userID),
		}
	}

	// Check each of the levels in the list.
	for userID, level := range userLevelChecks {
		// Check if the level is being changed.
		if level.old == level.new {
			// Levels are always allowed to stay the same.
			continue
		}

		// Users are allowed to change the level of other users if:
		//   * the old level was less than their own
		//   * the new level was less than or equal to their own
		// They are allowed to change their own level if:
		//   * the new level was less than or equal to their own
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1126-L1127
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1134

		// Check if the user is trying to set any of the levels to above their own.
		if senderLevel < level.new {
			return errorf(
				"sender %q with level %d is not allowed change user %q level from %d to %d"+
					" because the new level is above the level of the sender",
				senderID, senderLevel, userID, level.old, level.new,
			)
		}

		// Check if the user is changing their own user level.
		if userID == senderID {
			// Users are always allowed to reduce their own user level.
			// We know that the user is reducing their level because of the previous checks.
			continue
		}

		// Check if the user is changing the level that was above or the same as their own.
		if senderLevel <= level.old {
			return errorf(
				"sender %q with level %d is not allowed to change user %q level from %d to %d"+
					" because the old level is equal to or above the level of the sender",
				senderID, senderLevel, userID, level.old, level.new,
			)
		}
	}

	return nil
}

// checkNotificationLevels checks that the changes in notification levels are allowed.
func checkNotificationLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	type levelPair struct {
		old    int64
		new    int64
		userID string
	}
	notificationLevelChecks := []levelPair{}

	// Then add checks for each notification key in the new levels.
	for notification := range newPowerLevels.Notifications {
		notificationLevelChecks = append(notificationLevelChecks, levelPair{
			oldPowerLevels.NotificationLevel(notification),
			newPowerLevels.NotificationLevel(notification),
			notification,
		})
	}

	// Then add checks for each notification key in the old levels.
	// Some of these will be duplicates of the ones added using the keys from
	// the new levels. But it doesn't hurt to run the checks twice for the same level.
	for notification := range oldPowerLevels.Notifications {
		notificationLevelChecks = append(notificationLevelChecks, levelPair{
			oldPowerLevels.NotificationLevel(notification),
			newPowerLevels.NotificationLevel(notification),
			notification,
		})
	}

	// Check each of the levels in the list.
	for _, level := range notificationLevelChecks {
		// Check if the level is being changed.
		if level.old == level.new {
			// Levels are always allowed to stay the same.
			continue
		}

		// Users are allowed to change the notification level if:
		//   * If the current value is less than or equal to the `sender`'s current power level
		//   * If the new value is less than or equal to the `sender`'s current power level
		// https://matrix.org/docs/spec/rooms/v6#authorization-rules-for-events

		// Check if the user is trying to set any of the levels to above their own.
		if senderLevel < level.new {
			return errorf(
				"sender with level %d is not allowed change notification level from %d to %d"+
					" because the new level is above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}

		// Check if the user is changing the level that was above or the same as their own.
		if senderLevel <= level.old {
			return errorf(
				"sender with level %d is not allowed to change notification level from %d to %d"+
					" because the old level is equal to or above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}
	}

	return nil
}

// redactEventAllowed checks whether the m.room.redaction event is allowed to
// enter the DAG of a room. Note that for v1, v2 rooms, this doesn't check if
// the redactor is the sender of the redacted event, and for rooms >= v3, this
// doesn't provide substantial checks other than some basic checks (e.g.
// membership) on the event.
// It returns an error if the event is not allowed or if there was a problem
// loading the auth events needed.
func (a *allowerContext) redactEventAllowed(event *Event) error {
	allower, err := a.newEventAllower(event.Sender())
	if err != nil {
		return err
	}

	// redact events must pass the default checks,
	if err = allower.commonChecks(event); err != nil {
		return err
	}

	roomVersion := allower.create.RoomVersion
	if roomVersion != nil && *roomVersion != "1" && *roomVersion != "2" {
		// We always accept redaction events into the DAG for rooms >= v3 after the
		// very basic checks.
		return nil
	}

	sender := event.Sender()
	senderDomain, err := domainFromID(sender)
	if err != nil {
		return err
	}

	redactDomain, err := domainFromID(event.Redacts())
	if err != nil {
		return err
	}

	// Servers are always allowed to redact their own messages.
	// This is so that users can redact their own messages, but since
	// we don't know which user ID sent the message being redacted
	// the only check we can do is to compare the domains of the
	// sender and the redacted event.
	// We leave it up to the sending server to implement the additional checks
	// to ensure that only events that should be redacted are redacted.
	if senderDomain == redactDomain {
		return nil
	}

	// Otherwise the sender must have enough power.
	// This allows room admins and ops to redact messages sent by other servers.
	senderLevel := allower.powerLevels.UserLevel(sender)
	redactLevel := allower.powerLevels.Redact
	if senderLevel >= redactLevel {
		return nil
	}

	return errorf(
		"%q is not allowed to redact message from %q. %d < %d",
		sender, redactDomain, senderLevel, redactLevel,
	)
}

// defaultEventAllowed checks whether the event is allowed by the default
// checks for events.
// It returns an error if the event is not allowed or if there was a
// problem loading the auth events needed.
func (a *allowerContext) defaultEventAllowed(event *Event) error {
	allower, err := a.newEventAllower(event.Sender())
	if err != nil {
		return err
	}
	return allower.commonChecks(event)
}

// An eventAllower has the information needed to authorise all events types
// other than m.room.create, m.room.member and m.room.aliases which are special.
type eventAllower struct {
	*allowerContext
	// The content of the m.room.member event for the sender.
	member MemberContent
}

// newEventAllower loads the information needed to authorise an event sent
// by a given user ID from the auth events.
func (a *allowerContext) newEventAllower(senderID string) (e eventAllower, err error) {
	e.allowerContext = a
	if e.member, err = NewMemberContentFromAuthEvents(a.provider, senderID); err != nil {
		return
	}
	return
}

// commonChecks does the checks that are applied to all events types other than
// m.room.create, m.room.member, or m.room.alias.
func (e *eventAllower) commonChecks(event *Event) error {
	if event.RoomID() != e.create.roomID {
		return errorf(
			"create event has different roomID: %q (%s) != %q (%s)",
			event.RoomID(), event.EventID(), e.create.roomID, e.create.eventID,
		)
	}

	sender := event.Sender()
	stateKey := event.StateKey()

	if err := e.create.UserIDAllowed(sender); err != nil {
		return err
	}

	// Check that the sender is in the room.
	// Every event other than m.room.create, m.room.member and m.room.aliases require this.
	if e.member.Membership != Join {
		return errorf("sender %q not in room", sender)
	}

	senderLevel := e.powerLevels.UserLevel(sender)
	eventLevel := e.powerLevels.EventLevel(event.Type(), stateKey != nil)
	if senderLevel < eventLevel {
		return errorf(
			"sender %q is not allowed to send event. %d < %d",
			event.Sender(), senderLevel, eventLevel,
		)
	}

	// Check that all state_keys that begin with '@' are only updated by users
	// with that ID.
	if stateKey != nil && len(*stateKey) > 0 && (*stateKey)[0] == '@' {
		if *stateKey != sender {
			return errorf(
				"sender %q is not allowed to modify the state belonging to %q",
				sender, *stateKey,
			)
		}
	}

	// TODO: Implement other restrictions on state_keys required by the specification.
	// However as synapse doesn't implement those checks at the moment we'll hold off
	// so that checks between the two codebases don't diverge too much.

	return nil
}

// A membershipAllower has the information needed to authenticate a m.room.member event
type membershipAllower struct {
	*allowerContext
	roomVersion RoomVersion
	// The m.room.third_party_invite content referenced by this event.
	thirdPartyInvite ThirdPartyInviteContent
	// The user ID of the user whose membership is changing.
	targetID string
	// The user ID of the user who sent the membership event.
	senderID string
	// The membership of the user who sent the membership event.
	senderMember MemberContent
	// The previous membership of the user whose membership is changing.
	oldMember MemberContent
	// The new membership of the user if this event is accepted.
	newMember MemberContent
}

// newMembershipAllower loads the information needed to authenticate the m.room.member event
// from the auth events.
func (a *allowerContext) newMembershipAllower(authEvents AuthEventProvider, event *Event) (m membershipAllower, err error) { // nolint: gocyclo
	m.allowerContext = a
	m.roomVersion = event.roomVersion
	stateKey := event.StateKey()
	if stateKey == nil {
		err = errorf("m.room.member must be a state event")
		return
	}
	// TODO: Check that the IDs are valid user IDs.
	m.targetID = *stateKey
	m.senderID = event.Sender()
	if m.newMember, err = NewMemberContentFromEvent(event); err != nil {
		return
	}
	if m.oldMember, err = NewMemberContentFromAuthEvents(authEvents, m.targetID); err != nil {
		return
	}
	if m.senderMember, err = NewMemberContentFromAuthEvents(authEvents, m.senderID); err != nil {
		return
	}
	// If this event comes from a third_party_invite, we need to check it against the original event.
	if m.newMember.ThirdPartyInvite != nil {
		token := m.newMember.ThirdPartyInvite.Signed.Token
		if m.thirdPartyInvite, err = NewThirdPartyInviteContentFromAuthEvents(authEvents, token); err != nil {
			return
		}
	}
	return
}

// membershipAllowed checks whether the membership event is allowed
func (m *membershipAllower) membershipAllowed(event *Event) error { // nolint: gocyclo
	if m.create.roomID != event.RoomID() {
		return errorf(
			"create event has different roomID: %q (%s) != %q (%s)",
			event.RoomID(), event.EventID(), m.create.roomID, m.create.eventID,
		)
	}
	if err := m.create.UserIDAllowed(m.senderID); err != nil {
		return err
	}
	if err := m.create.UserIDAllowed(m.targetID); err != nil {
		return err
	}
	// Special case the first join event in the room to allow the creator to join.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L328
	if m.targetID == m.create.Creator &&
		m.newMember.Membership == Join &&
		m.senderID == m.targetID &&
		len(event.PrevEvents()) == 1 {

		// Grab the event ID of the previous event.
		prevEventID := event.PrevEvents()[0].EventID

		if prevEventID == m.create.eventID {
			// If this is the room creator joining the room directly after the
			// the create event, then allow.
			return nil
		}
		// Otherwise fall back to the normal checks.
	}

	if m.newMember.Membership == Invite && m.newMember.ThirdPartyInvite != nil {
		// Special case third party invites
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L393
		return m.membershipAllowedFromThirdPartyInvite()
	}

	if m.targetID == m.senderID {
		// If the state_key and the sender are the same then this is an attempt
		// by a user to update their own membership.
		return m.membershipAllowedSelf()
	}
	// Otherwise this is an attempt to modify the membership of somebody else.
	return m.membershipAllowedOther()
}

func (m *membershipAllower) membershipAllowedSelfForRestrictedJoin() error {
	// Special case for restricted room joins, where we will check if the membership
	// event is signed by one of the allowed servers in the join rule content.
	allowsRestricted, err := m.roomVersion.AllowRestrictedJoinsInEventAuth(m.joinRule.JoinRule)
	if err != nil {
		return err
	}
	if !allowsRestricted {
		return errorf("restricted joins are not supported in this room version")
	}

	// In the case that the user is already joined, invited or there is no
	// authorised via server, we should treat the join rule as if it's invite.
	if m.oldMember.Membership == Join || m.oldMember.Membership == Invite || m.newMember.AuthorisedVia == "" {
		m.joinRule.JoinRule = Invite
		return nil
	}

	// Otherwise, we have to work out if the server that produced the join was
	// authorised to do so. This requires the membership event to contain a
	// 'join_authorised_via_users_server' key, containing the user ID of a user
	// in the room that should have a suitable power level to issue invites.
	// If no such key is specified then we should reject the join.
	if _, _, err := SplitID('@', m.newMember.AuthorisedVia); err != nil {
		return errorf("the 'join_authorised_via_users_server' contains an invalid value %q", m.newMember.AuthorisedVia)
	}

	// If the nominated user ID is valid then there are two things that we
	// need to check. First of all, is the user joined to the room?
	otherMember, err := m.provider.Member(m.newMember.AuthorisedVia)
	if err != nil {
		return errorf("failed to find the membership event for 'join_authorised_via_users_server' user %q", m.newMember.AuthorisedVia)
	}
	if otherMember == nil {
		return errorf("failed to find the membership event for 'join_authorised_via_users_server' user %q", m.newMember.AuthorisedVia)
	}
	otherMembership, err := otherMember.Membership()
	if err != nil {
		return errorf("failed to find the membership status for 'join_authorised_via_users_server' user %q", m.newMember.AuthorisedVia)
	}
	if otherMembership != Join {
		return errorf("the nominated 'join_authorised_via_users_server' user %q is not joined to the room", m.newMember.AuthorisedVia)
	}

	// And secondly, does the user have the power to issue invites in the room?
	if pl := m.powerLevels.UserLevel(m.newMember.AuthorisedVia); pl < m.powerLevels.Invite {
		return errorf("the nominated 'join_authorised_via_users_server' user %q does not have permission to invite (%d < %d)", m.newMember.AuthorisedVia, pl, m.powerLevels.Invite)
	}

	// At this point all of the checks have proceeded, so continue as if
	// the room is a public room.
	m.joinRule.JoinRule = Public
	return nil
}

// membershipAllowedFronThirdPartyInvite determines if the member events is following
// up the third_party_invite event it claims.
func (m *membershipAllower) membershipAllowedFromThirdPartyInvite() error {
	// Check if the event's target matches with the Matrix ID provided by the
	// identity server.
	if m.targetID != m.newMember.ThirdPartyInvite.Signed.MXID {
		return errorf(
			"The invite target %s doesn't match with the Matrix ID provided by the identity server %s",
			m.targetID, m.newMember.ThirdPartyInvite.Signed.MXID,
		)
	}
	// Marshal the "signed" so it can be verified by VerifyJSON.
	marshalledSigned, err := json.Marshal(m.newMember.ThirdPartyInvite.Signed)
	if err != nil {
		return err
	}
	// Check each signature with each public key. If one signature could be
	// verified with one public key, accept the event.
	for _, publicKey := range m.thirdPartyInvite.PublicKeys {
		for domain, signatures := range m.newMember.ThirdPartyInvite.Signed.Signatures {
			for keyID := range signatures {
				if strings.HasPrefix(keyID, "ed25519") {
					if err = VerifyJSON(
						domain, KeyID(keyID),
						ed25519.PublicKey(publicKey.PublicKey),
						marshalledSigned,
					); err == nil {
						return nil
					}
				}
			}
		}
	}
	return errorf("Couldn't verify signature on third-party invite for %s", m.targetID)
}

// membershipAllowedSelf determines if the change made by the user to their own membership is allowed.
func (m *membershipAllower) membershipAllowedSelf() error { // nolint: gocyclo
	// NOTSPEC: Leave -> Leave is benign but not allowed according to the Matrix spec.
	// We allow this because of an issue regarding Synapse incorrectly accepting this event.
	if m.oldMember.Membership == Leave && m.newMember.Membership == Leave {
		return nil
	}

	switch m.newMember.Membership {
	case Knock:
		if m.joinRule.JoinRule != Knock && m.joinRule.JoinRule != KnockRestricted {
			return m.membershipFailed(
				"join rule %q does not allow knocking", m.joinRule.JoinRule,
			)
		}
		// A user that is not in the room is allowed to knock if the join
		// rules are "knock" and they are not already joined to, invited to
		// or banned from the room.
		// Spec: https://spec.matrix.org/unstable/rooms/v7/
		// MSC3787 extends this: the behaviour above is also permitted if the
		// join rules are "knock_restricted"
		// Spec: https://github.com/matrix-org/matrix-spec-proposals/pull/3787
		if supported, err := m.roomVersion.AllowKnockingInEventAuth(m.joinRule.JoinRule); err != nil {
			return fmt.Errorf("m.roomVersion.AllowKnockingInEventAuth: %w", err)
		} else if !supported {
			return m.membershipFailed(
				"room version %q does not support knocking on rooms with join rule %q",
				m.roomVersion,
				m.joinRule.JoinRule,
			)
		}
		switch m.oldMember.Membership {
		case Join, Invite, Ban:
			// The user is already joined, invited or banned, therefore they
			// can't knock.
			return m.membershipFailed(
				"sender is already joined/invited/banned",
			)
		default:
			// A non-joined, non-invited, non-banned user is allowed to knock.
			return nil
		}

	case Join:
		if m.oldMember.Membership == Leave && (m.joinRule.JoinRule == Restricted || m.joinRule.JoinRule == KnockRestricted) {
			if err := m.membershipAllowedSelfForRestrictedJoin(); err != nil {
				return err
			}
		}
		// A user that is not in the room is allowed to join if the room
		// join rules are "public".
		if m.oldMember.Membership == Leave && m.joinRule.JoinRule == Public {
			return nil
		}
		// An invited user is always allowed to join, regardless of the join rule
		if m.oldMember.Membership == Invite {
			return nil
		}
		// A joined user is allowed to update their join.
		if m.oldMember.Membership == Join {
			return nil
		}
		return m.membershipFailed(
			"join rule %q forbids it", m.joinRule.JoinRule,
		)

	case Leave:
		switch m.oldMember.Membership {
		case Join:
			// A joined user is allowed to leave the room.
			return nil
		case Invite:
			// An invited user can reject the invite.
			return nil
		case Knock:
			// A knocking user can cancel their knock.
			return nil
		default:
			return m.membershipFailed(
				"sender cannot leave from membership state %q",
				m.oldMember.Membership,
			)
		}

	case Invite, Ban:
		return m.membershipFailed(
			"sender cannot set their own membership to %q", m.newMember.Membership,
		)

	default:
		return m.membershipFailed(
			"membership %q is unknown", m.newMember.Membership,
		)
	}
}

// membershipAllowedOther determines if the user is allowed to change the membership of another user.
func (m *membershipAllower) membershipAllowedOther() error { // nolint: gocyclo
	senderLevel := m.powerLevels.UserLevel(m.senderID)
	targetLevel := m.powerLevels.UserLevel(m.targetID)

	// You may only modify the membership of another user if you are in the room.
	if m.senderMember.Membership != Join {
		return errorf("sender %q is not in the room", m.senderID)
	}

	switch m.newMember.Membership {
	case Ban:
		// A user may ban another user if their level is high enough
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L463
		if senderLevel >= m.powerLevels.Ban && senderLevel > targetLevel {
			return nil
		}
		return m.membershipFailed(
			"sender has insufficient power to ban (sender level %d, target level %d, ban level %d)",
			senderLevel, targetLevel, m.powerLevels.Ban,
		)

	case Leave:
		// A user may unban another user if their level is high enough.
		// This is doesn't require the same power_level checks as banning.
		// You can unban someone with higher power_level than you.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L451
		if m.oldMember.Membership == Ban {
			if senderLevel >= m.powerLevels.Ban {
				return nil
			}
			return m.membershipFailed(
				"sender has insufficient power to unban (sender level %d, ban level %d)",
				senderLevel, m.powerLevels.Ban,
			)
		}
		// A user may kick another user if their level is high enough.
		// TODO: You can kick a user that was already kicked, or has left the room, or was
		// never in the room in the first place. Do we want to allow these redundant kicks?
		if senderLevel >= m.powerLevels.Kick && senderLevel > targetLevel {
			return nil
		}
		return m.membershipFailed(
			"sender has insufficient power to kick (sender level %d, target level %d, kick level %d)",
			senderLevel, targetLevel, m.powerLevels.Kick,
		)

	case Invite:
		// A user may only invite another user if they have sufficient power
		// to do so.
		if senderLevel < m.powerLevels.Invite {
			return m.membershipFailed(
				"sender has insufficient power to invite (sender level %d, invite level %d)",
				senderLevel, m.powerLevels.Invite,
			)
		}

		switch m.oldMember.Membership {
		case Join, Ban:
			// A user may invite another user if they haven't joined or have
			// already joined and left before re-inviting.
			return m.membershipFailed(
				"target cannot be invited when their membership is %q",
				m.oldMember.Membership,
			)
		default:
			// A user may invite another user if they:
			// - haven't joined the room yet
			// - joined before but have since left
			// - were already invite
			// - were already knock
			return nil
		}

	case Knock, Join:
		return m.membershipFailed(
			"sender cannot set membership of another user to %q", m.newMember.Membership,
		)

	default:
		return m.membershipFailed(
			"membership %q is unknown", m.newMember.Membership,
		)
	}
}

// membershipFailed returns a error explaining why the membership change was disallowed.
func (m *membershipAllower) membershipFailed(format string, args ...interface{}) error {
	if m.senderID == m.targetID {
		return errorf(
			"%q is not allowed to change their membership from %q to %q as "+format,
			append([]interface{}{m.targetID, m.oldMember.Membership, m.newMember.Membership}, args...)...,
		)
	}

	return errorf(
		"%q is not allowed to change the membership of %q from %q to %q as "+format,
		append([]interface{}{m.senderID, m.targetID, m.oldMember.Membership, m.newMember.Membership}, args...)...,
	)
}
