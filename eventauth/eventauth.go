package eventauth

import (
	"encoding/json"
	"fmt"
	"sort"
)

// An Event has the fields necessary to authenticate a matrix event.
// It can be unmarshalled from the event JSON.
type Event struct {
	RoomID     string              `json:"room_id"`
	EventID    string              `json:"event_id"`
	Sender     string              `json:"sender"`
	Type       string              `json:"type"`
	StateKey   *string             `json:"state_key"`
	Content    json.RawMessage     `json:"content"`
	PrevEvents [][]json.RawMessage `json:"prev_events"`
	Redacts    string              `json:"redacts"`
}

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

// StateNeededForAuth returns the event types and state_keys needed to authenticate an event.
// This takes a list of events to facilitate bulk processsing when doing auth checks as part of state conflict resolution.
func StateNeededForAuth(events []Event) (result StateNeeded) {
	var members []string
	var thirdpartyinvites []string

	for _, event := range events {
		switch event.Type {
		case "m.room.create":
			// The create event doesn't require any state to authenticate.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L123
		case "m.room.aliases":
			// Alias events need:
			//  * The create event.
			//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L128
			// Alias events need no further authentication.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L160
			result.Create = true
		case "m.room.member":
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
			content, err := newMemberContentFromEvent(event)
			if err != nil {
				// If we hit an error decoding the content we ignore it here.
				// The event will be rejected when the actual checks encounter the same error.
				continue
			}
			result.Create = true
			result.PowerLevels = true
			if event.StateKey != nil {
				members = append(members, event.Sender, *event.StateKey)
			}
			if content.Membership == "join" {
				result.JoinRules = true
			}
			if content.ThirdPartyInvite != nil {
				token, err := thirdPartyInviteToken(content.ThirdPartyInvite)
				if err != nil {
					// If we hit an error decoding the content we ignore it here.
					// The event will be rejected when the actual checks encounter the same error.
					continue
				} else {
					thirdpartyinvites = append(thirdpartyinvites, token)
				}
			}

		default:
			// All other events need:
			//  * The membership of the sender.
			//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L177
			//  * The power levels for the room.
			//    https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L196
			result.Create = true
			result.PowerLevels = true
			members = append(members, event.Sender)
		}
	}

	// Deduplicate the state keys.
	sort.Strings(members)
	result.Member = members[:unique(sort.StringSlice(members))]
	sort.Strings(thirdpartyinvites)
	result.ThirdPartyInvite = thirdpartyinvites[:unique(sort.StringSlice(thirdpartyinvites))]
	return
}

// Remove duplicate items from a sorted list.
// Takes the same interface as sort.Sort
// Returns the length of the data without duplicates
// Uses the last occurance of a duplicate.
// O(n).
func unique(data sort.Interface) int {
	length := data.Len()
	if length == 0 {
		return 0
	}
	j := 0
	for i := 1; i < length; i++ {
		if data.Less(i-1, i) {
			data.Swap(i-1, j)
			j++
		}
	}
	data.Swap(length-1, j)
	return j + 1
}

// thirdPartyInviteToken extracts the token from the third_party_invite.
func thirdPartyInviteToken(thirdPartyInviteData json.RawMessage) (string, error) {
	var thirdPartyInvite struct {
		Signed struct {
			Token string `json:"token"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(thirdPartyInviteData, &thirdPartyInvite); err != nil {
		return "", err
	}
	if thirdPartyInvite.Signed.Token == "" {
		return "", fmt.Errorf("missing 'third_party_invite.signed.token' JSON key")
	}
	return thirdPartyInvite.Signed.Token, nil
}

// AuthEvents are the state events needed to authenticate an event.
type AuthEvents interface {
	// Create returns the m.room.create event for the room.
	Create() (*Event, error)
	// JoinRules returns the m.room.join_rules event for the room.
	JoinRules() (*Event, error)
	// PowerLevels returns the m.room.power_levels event for the room.
	PowerLevels() (*Event, error)
	// Member returns the m.room.member event for the given user_id state_key.
	Member(stateKey string) (*Event, error)
	// ThirdPartyInvite returns the m.room.third_party_invite event for the
	// given state_key.
	ThirdPartyInvite(stateKey string) (*Event, error)
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

// Allowed checks whether an event is allowed by the auth events.
// It returns a NotAllowed error if the event is not allowed.
// If there was an error loading the auth events then it returns that error.
func Allowed(event Event, authEvents AuthEvents) error {
	switch event.Type {
	case "m.room.create":
		return createEventAllowed(event)
	case "m.room.alias":
		return aliasEventAllowed(event, authEvents)
	case "m.room.member":
		return memberEventAllowed(event, authEvents)
	case "m.room.power_levels":
		return powerLevelsEventAllowed(event, authEvents)
	case "m.room.redact":
		return redactEventAllowed(event, authEvents)
	default:
		return defaultEventAllowed(event, authEvents)
	}
}

// createEventAllowed checks whether the m.room.create event is allowed.
// It returns an error if the event is not allowed.
func createEventAllowed(event Event) error {
	roomIDDomain, err := domainFromID(event.RoomID)
	if err != nil {
		return err
	}
	senderDomain, err := domainFromID(event.Sender)
	if err != nil {
		return err
	}
	if senderDomain != roomIDDomain {
		return errorf("create event room ID domain does not match sender: %q != %q", roomIDDomain, senderDomain)
	}
	if len(event.PrevEvents) > 0 {
		return errorf("create event must be the first event in the room: found %d prev_events", len(event.PrevEvents))
	}
	return nil
}

func memberEventAllowed(event Event, authEvents AuthEvents) error {
	panic("Not implemented")
}

func aliasEventAllowed(event Event, authEvents AuthEvents) error {
	panic("Not implemented")
}

func powerLevelsEventAllowed(event Event, authEvents AuthEvents) error {
	panic("Not implemented")
}

func redactEventAllowed(event Event, authEvents AuthEvents) error {
	panic("Not implemented")
}

// defaultEventAllowed checks whether the event is allowed by the default
// checks for events.
// It returns an error if the event is not allowed or if there was a
// problem loading the auth events needed.
func defaultEventAllowed(event Event, authEvents AuthEvents) error {
	allower, err := newEventAllower(authEvents, event.Sender)
	if err != nil {
		return err
	}

	return allower.commonChecks(event)
}

// An eventAllower has the information needed to authorise all events types
// other than m.room.create, m.room.member and m.room.alias which are special.
type eventAllower struct {
	// The content of the m.room.create.
	create createContent
	// The content of the m.room.member event for the sender.
	member memberContent
	// The content of the m.room.power_levels event for the room.
	powerLevels powerLevelContent
}

// newEventAllower loads the infromation needed to authorise an event sent
// by a given user ID from the auth events.
func newEventAllower(authEvents AuthEvents, senderID string) (e eventAllower, err error) {
	if e.create, err = newCreateContentFromAuthEvents(authEvents); err != nil {
		return
	}
	if e.member, err = newMemberContentFromAuthEvents(authEvents, senderID); err != nil {
		return
	}
	if e.powerLevels, err = newPowerLevelContentFromAuthEvents(authEvents, e.create.Creator); err != nil {
		return
	}
	return
}

// commonChecks does the checks that are applied to all events types other than
// m.room.create, m.room.member, or m.room.alias.
func (e *eventAllower) commonChecks(event Event) error {
	if event.RoomID != e.create.roomID {
		return errorf("create event has different roomID: %q != %q", event.RoomID, e.create.roomID)
	}

	if err := e.create.userIDAllowed(event.Sender); err != nil {
		return err
	}

	// Check that the sender is in the room.
	// Every event other than m.room.create, m.room.member and m.room.alias require this.
	if e.member.Membership != "join" {
		return errorf("sender %q not in room", event.Sender)
	}

	senderLevel := e.powerLevels.userLevel(event.Sender)
	eventLevel := e.powerLevels.eventLevel(event.Type, event.StateKey)
	if senderLevel < eventLevel {
		return errorf(
			"sender %q is not allowed to send event. %d < %d",
			event.Sender, senderLevel, eventLevel,
		)
	}

	if event.StateKey != nil && len(*event.StateKey) > 0 && (*event.StateKey)[0] == '@' {
		if *event.StateKey != event.Sender {
			return errorf(
				"sender %q is not allowed to modify the state belonging to %q",
				event.Sender, *event.StateKey,
			)
		}
	}

	return nil
}
