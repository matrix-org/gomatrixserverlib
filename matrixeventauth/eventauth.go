package matrixeventauth

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//
type Event struct {
	RoomID     string              `json:"room_id"`
	EventID    string              `json:"event_id"`
	Sender     string              `json:"sender"`
	Type       string              `json:"type"`
	StateKey   *string             `json:"state_key"`
	Content    json.RawMessage     `json:"content"`
	PrevEvents [][]json.RawMessage `json:"prev_events"`
}

// StateNeeded lists the state entries needed to authenticate an event.
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

func StateNeededForAuth(events []Event) (result StateNeeded) {
	var members []string
	var thirdpartyinvites []string

	for _, event := range events {
		switch event.Type {
		case "m.room.create":
			// The create event doesn't require any state to authenticate.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L123
			// All other events need the create event.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L128
		case "m.room.aliases":
			// Alias events need no further authentication.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L160
			result.Create = true
		case "m.room.member":
			// Member events need the previous membership of the target.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L355
			// The current membership state of the sender.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L348
			// The join rules for the room.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L361
			// The power levels for the room.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L370
			// And optionally may require a m.third_party_invite event
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L393
			result.Create = true
			result.PowerLevels = true
			result.JoinRules = true
			members = append(members, event.Sender, event.StateKey)
			thirdpartyinvites = needsThirdpartyInvite(thirdpartyinvites, event)
		default:
			// All other events need the membership of the sender.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L177
			// The power levels for the room.
			// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L196
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

type AuthEvents interface {
	Create() (*Event, error)
	JoinRules() (*Event, error)
	PowerLevels() (*Event, error)
	Member(stateKey string) (*Event, error)
	ThirdPartyInvite(stateKey string) (*Event, error)
}

type NotAllowed struct {
	Message string
}

func (a *NotAllowed) Error() string {
	return "matrixeventauth: " + a.Message
}

func errorf(message string, args ...interface{}) error {
	return &NotAllowed{Message: fmt.Sprintf(message, args...)}
}

func Allowed(event Event, authEvents AuthEvents) error {
	switch event.Type {
	case "m.room.create":
		return createAllowed(event, authEvents)
	case "m.room.alias":
		return aliasAllowed(event, authEvents)
	case "m.room.member":
		return memberAllowed(event, authEvents)
	case "m.room.thirdpartyinvite":
		return thirdPartyInviteAllowed(event, authEvents)
	case "m.room.power_levels":
		return powerLevelsAllowed(event, authEvents)
	default:
		return eventAllowed(event, authEvents)
	}
}

func createAllowed(event Event, authEvents AuthEvents) error {
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
	return nil
}

func aliasAllowed(event Event, authEvents AuthEvents) error {
	senderDomain, err := domainFromID(event.Sender)
	if err != nil {
		return err
	}
	create, err := createEvent(authEvents)
	if err != nil {
		return err
	}
	if err := create.domainAllowed(senderDomain); err != nil {
		return err
	}
	if event.StateKey == nil {
		return errorf("alias must be a state event")
	}
	if senderDomain != *event.StateKey {
		return errorf("alias state_key does not match sender domain, %q != %q", senderDomain, *event.StateKey)
	}
	return nil
}

func memberAllowed(event Event, authEvents AuthEvents) error {
	create, err := createEvent(authEvents)
	if err != nil {
		return err
	}
	senderDomain, err := domainFromID(event.Sender)
	if err != nil {
		return err
	}
	if err := create.domainAllowed(senderDomain); err != nil {
		return err
	}
	newMembership, thirdPartyInvite, err := membershipContent(event)
	if err != nil {
		return err
	}
	if event.StateKey == nil {
		return errorf("member must be a state event")
	}
	targetUserID := *event.StateKey

	if len(event.PrevEvents) == 1 &&
		newMembership == "join" &&
		create.Creator == targetUserID &&
		event.Sender == targetUserID {
		// Special case the first join event in the room.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L328
		if len(event.PrevEvents[0]) != 2 {
			return errorf("unparsable prev event")
		}
		var prevEvent string
		if err := json.Unmarshal(PrevEvents[0][0], &prevEvent); err != nil {
			return errorf("unparsable prev event")
		}
		if prevEvent == create.eventID {
			// If this is the room creator joining the room directly after the
			// the create event, then allow.
			return nil
		}
		// Otherwise fall through to the usual authentication process.
	}

	targetDomain, err := domainFromID(targetUserID)
	if err != nil {
		return err
	}
	if err := create.domainAllowed(targetDomain); err != nil {
		return err
	}

	if newMembership == "invite" && thirdPartyInvite != nil {
		// Special case third party invites
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L393
		panic(fmt.Errorf("ThirdPartyInvite not implemented"))

		// Otherwise fall through to the usual authentication process.
	}

	var m membershipAllower
	if err = m.setup(newMembership, targetUserID, event.Sender, authEvents); err != nil {
		return err
	}
	return m.membershipAllowed()
}

type membershipAllower struct {
	targetID         string
	senderID         string
	senderMembership string
	oldMembership    string
	newMembership    string
	joinRule         string
	powerLevels      powerLevelEventContent
}

func (m *membershipAllower) setup(newMembership, targetID, senderID, authEvents AuthEvents) error {
	m.targetID = targetID
	m.senderID = senderID
	m.newMembership = newMembership
	// Fetch the existing membership for the target
	var err error
	if m.oldMembership, err = membershipForUser(targetID, authEvents); err != nil {
		return err
	}
	// Fetch the membership of the sender
	if m.senderMembership, err = membershipForUser(senderID, authEvents); err != nil {
		return err
	}
	if m.powerLevels, err = powerLevelEvent(authEvents); err != nil {
		return err
	}
	if m.joinRule, err = joinRuleForRoom(authEvents); err != nil {
		return err
	}
	return nil
}

// membershipAllowed determines whether the membership change is allowed.
// The code is effectively a list of "if" statements using only "&&" to
// join the conditions. The conditions are ordered so that the sender is
// checked first, followed by the new state, followed by the old state,
// followed by power levels and join rules. For readability the common sender
// and new state checks are factored into nested "if" statements.
func (m *membershipAllower) membershipAllowed() error {
	senderLevel := powerLevels.userLevel(m.SenderID)
	targetLevel := powerLevels.userLevel(m.TargetID)

	if m.targetID == m.SenderID {
		if m.newMembership == "join" {
			// A user that is not in the room is allowed to join if the room
			// join rules are "public".
			if m.oldMembership == "leave" && m.joinRule == "public" {
				return nil
			}
			// An invited user is allowed to join if the join rules are "public"
			if m.oldMembership == "invite" && m.joinRule == "public" {
				return nil
			}
			// An invited user is allowed to join if the join rules are "invite"
			if m.oldMembership == "invite" && m.joinRule == "invite" {
				return nil
			}
			// A joined user is allowed to update their join.
			if m.oldMembership == "join" {
				return nil
			}
		}
		if m.newMembership == "leave" {
			// A joined user is allowed to leave the room.
			if m.oldMembership == "join" {
				return nil
			}
			// An invited user is allowed to reject an invite.
			if m.oldMembership == "invite" {
				return nil
			}
		}
	}
	if m.targetID != m.SenderID && m.senderMembership == "join" {
		if m.newMembership == "ban" {
			// A user may ban another user if their level is high enough
			if senderLevel >= powerLevels.banLevel &&
				senderLevel > targetLevel {
				return nil
			}
		}
		if m.newMembership == "leave" {
			// A user may unban another user if their level is high enough.
			if m.oldMembership == "ban" && senderLevel >= powerLevels.banLevel {
				return nil
			}
			// A user may kick another user if their level is high enough.
			if m.oldMembership != "ban" &&
				senderLevel >= powerLevels.kickLevel &&
				senderLevel > targetLevel {
				return nil
			}
		}
		if m.newMembership == "invite" {
			// A user may invite another user if the user has left the room.
			// and their level is high enough.
			if m.oldMembership == "leave" && senderLevel >= powerLevels.inviteLevel {
				return nil
			}
			// A user may re-invite a user.
			if m.oldMembership == "invite" && senderLevel >= powerLevels.inviteLevel {
				return nil
			}
		}
	}
	return m.membershipFailed()
}

// membershipFailed returns a error explaining why the membership change was disallowed.
func (m membershipAllower) membershipFailed() error {
	if m.senderID == m.targetID {
		return errorf(
			"%q is not allowed to change their membership from %q to %q",
			m.targetID, m.oldMembership, m.newMembership,
		)
	}

	if m.senderMembership != "join" {
		return errorf("sender %q is not in the room", m.senderID)
	}

	return errorf(
		"%q is not allowed to change the membership of %q from %q to %q",
		m.senderID, m.targetID, m.oldMembership, m.newMembership,
	)
}

func thirdPartyInviteAllowed(event Event, authEvents AuthEvents) error {

}

type powerLevelEventContent struct {
}

func powerLevelEvent(authEvents AuthEvents) (content powerLevelEventContent, err error) {
	panic(fmt.Errorf("Not implemented"))
	return
}

func (p powerLevelEventContent) userLevel(userID string) int {
	panic(fmt.Errorf("Not implemented"))
	return 0
}

func (p powerLevelEventContent) namedLevel(name string, defaultLevel int) int {
	panic(fmt.Errorf("Not implemented"))
	return 0
}

func joinRuleForRoom(authEvents AuthEvents) (string, error) {
	joinRulesEvent, err := authEvents.JoinRules()
	if err != nil {
		return "", err
	}
	if joinRulesEvent == nil {
		// Default to "invite"
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L368
		return "invite"
	}
	var content struct {
		JoinRule string `json:"join_rule"`
	}
	if err := json.Unmarshal(joinRulesEvent.Content, &content); err != nil {
		return errorf("unparsable join rules event content: %s", err.Error())
	}
	return content.JoinRule
}

func membershipForUser(authEvents AuthEvents, userID string) (string, error) {
	memberEvent, err := authEvents.Member(userID)
	if err != nil {
		return "", err
	}
	if memberEvent == nil {
		return "leave"
	}
	membership, _, err := memberContent(*memberEvent)
	return membership, err
}

func memberContent(event Event) (membership string, thirdPartyInvite []byte, err error) {
	var content struct {
		Membership       string          `json:"membership"`
		ThirdPartyInvite json.RawMessage `json:"third_party_invite"`
	}
	if err := json.Unmarshal(createEvent.Content, &content); err != nil {
		return "", nil, errorf("unparsable membership event content: %s", err.Error())
	}
	if content.Membership == "" {
		return "", nil, errorf("missing membership key")
	}
	return content.Membership, []byte(content.ThirdPartyInvite), nil
}

type createEventContent struct {
	eventID      string `json:"-"`
	senderDomain string `json:"-"`
	Federate     *bool  `json:"m.federate"`
	Creator      string `json:"creator"`
}

func createEvent(authEvents AuthEvents) (content createEventContent, err error) {
	createEvent, err := authEvents.Create()
	if err != nil {
		return
	}
	if createEvent == nil {
		err = errorf("missing create event")
		return
	}
	if err := json.Unmarshal(createEvent.Content, &content); err != nil {
		return errorf("unparsable create event content: %s", err.Error())
	}
	content.eventID = createEvent.EventID
	content.senderDomain, err = domainFromID(createEvent.Sender)
	return
}

func (c createEventContent) domainAllowed(domain string) error {
	if domain == c.createDomain {
		return nil
	}
	if content.Federate == nil || *content.Federate {
		return nil
	}
	return errorf("room is unfederatable")
}

func domainFromID(id string) (string, error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", errorf("invalid ID: %q", id)
	}
	return parts[1], nil
}

// Remove duplicate items from a sorted list.
// Takes the same interface as sort.Sort
// Returns the length of the date without duplicates
// Uses the last occurance of a duplicate.
// O(n).
func unique(data sort.Interface) int {
	length := data.Len()
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

func needsThirdpartyInvite(thirdpartyinvites []string, event Event) []string {
	var content struct {
		ThirdPartyInvite struct {
			Signed struct {
				Token string `json:"token"`
			} `json:"signed"`
		} `json:"third_party_invite"`
	}

	if err := json.Unmarshal(event.Content, &content); err != nil {
		// If the unmarshal fails then ignore the contents.
		// The event will be rejected by the auth checks when it fails to
		// unmarshal without needing to check for a third party invite token.
		return thirdpartyinvites
	}

	if content.ThirdPartyInvite.Signed.Token != "" {
		return append(thirdpartyinvites, content.ThirdPartyInvite.Signed.Token)
	}

	return thirdpartyinvites
}
