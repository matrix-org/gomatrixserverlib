package matrixeventauth

import (
	"bytes"
	"encoding/json"
)

type createContent struct {
	eventID      string `json:"-"`
	senderDomain string `json:"-"`
	Federate     *bool  `json:"m.federate"`
	Creator      string `json:"creator"`
}

func (c *createContent) load(authEvents AuthEvents) error {
	createEvent, err := authEvents.Create()
	if err != nil {
		return err
	}
	if createEvent == nil {
		return errorf("missing create event")
	}
	if err := json.Unmarshal(createEvent.Content, c); err != nil {
		return errorf("unparsable create event content: %s", err.Error())
	}
	c.eventID = createEvent.EventID
	if c.senderDomain, err = domainFromID(createEvent.Sender); err != nil {
		return err
	}
	return nil
}

func (c *createContent) domainAllowed(domain string) error {
	if domain == c.senderDomain {
		return nil
	}
	if content.Federate == nil || *content.Federate {
		return nil
	}
	return errorf("room is unfederatable")
}

func (c *createContent) idAllowed(id string) error {
	domain, err := domainFromID(id)
	if err != nil {
		return err
	}
	return c.domainAllowed(domain)
}

func domainFromID(id string) (string, error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", errorf("invalid ID: %q", id)
	}
	return parts[1], nil
}

type joinRuleContent struct {
	JoinRule string `json:"join_rule"`
}

func (c *joinRuleContent) load(authEvents AuthEvents) error {
	joinRulesEvent, err := authEvents.JoinRules()
	if err != nil {
		return err
	}
	if joinRulesEvent == nil {
		// Default to "invite"
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L368
		c.JoinRule = "invite"
		return nil
	}
	if err := json.Unmarshal(joinRulesEvent.Content, c); err != nil {
		return errorf("unparsable join_rules event content: %s", err.Error())
	}
	return nil
}

type powerLevelContent struct {
	banLevel          int64
	inviteLevel       int64
	kickLevel         int64
	userLevels        map[string]int64
	userDefaultLevel  int64
	eventLevels       map[string]int64
	eventDefaultLevel int64
	stateDefaultLevel int64
}

func (c *powerLevelContent) userLevel(userID string) int64 {
	level, ok := c.userLevels[userID]
	if ok {
		return level
	}
	return c.userDefaultLevel
}

func (c *powerLevelContent) eventLevel(eventType string, eventStateKey *string) int64 {
	if eventTupe == "m.room.third_party_invite" {
		// Special case third_party_invite events to have the same level as
		// m.room.member invite events.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L182
		return c.inviteLevel
	}
	level, ok := c.eventLevel(eventType)
	if ok {
		return level
	}
	if eventStateKey != nil {
		return c.stateDefaultLevel
	}
	return c.eventDefaultLevel
}

func (c *powerLevelContent) load(authEvents AuthEvents, creatorUserID string) error {
	powerLevelsEvent, err := authEvents.PowerLevels()
	if err != nil {
		return err
	}
	if powerLevelsEvent == nil {
		c.defaults()
		// If there is no power level event then the creator gets level 100
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L569
		c.userLevels = map[string]int64{creatorUserID: 100}
	}
	return c.parse(*powerLevelsEvent, creatorUserID)
}

func (c *powerLevelContent) defaults() {
	// Default invite level is 0.
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L426
	c.inviteLevel = 0
	// Default ban, kick and redacts levels are 50
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L376
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L456
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1041
	c.banLevel = 50
	c.kickLevel = 50
	c.redactLevel = 50
	// Default user level is 0
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L558
	c.userDefaultLevel = 0
	// Default event level is 0, Default state level is 50
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L987
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L991
	c.eventDefaultLevel = 0
	c.stateDefaultLevel = 50

}

func (c *powerLevelContent) parse(event Event) error {
	c.defaults()

	var content struct {
		InviteLevel       intValue            `json:"invite"`
		BanLevel          intValue            `json:"ban"`
		KickLevel         intValue            `json:"kick"`
		RedactLevel       intValue            `json:"redact"`
		UserLevels        map[string]intValue `json:"users"`
		UsersDefaultLevel intValue            `json:"users_default"`
		EventLevels       map[string]intValue `json:"events"`
		StateDefaultLevel intValue            `json:"state_default"`
		EventDefaultLevel intValue            `json:"event_default"`
	}
	if json.Unmarshal(event.Content, &content); err != nil {
		return errorf("unparsable power_levels event content: %s", err.Error())
	}

	content.InviteLevel.assignTo(&c.inviteLevel)
	content.BanLevel.assignTo(&c.banLevel)
	content.KickLevel.assignTo(&c.kickLevel)
	content.RedactLevel.assignTo(&c.redactLevel)
	content.UsersDefaultLevel.assignTo(&c.userDefaultLevel)
	content.StateDefaultLevel.assignTo(&c.stateDefaultLevel)
	content.EventDefaultLevel.assignTo(&c.eventDefaultLevel)

	for k, v := range content.UserLevels {
		if c.userLevels == nil {
			c.userLevels = make(map[string]int64)
		}
		c.userLevels[k] = v.value
	}

	for k, v := range content.EventLevels {
		if c.eventLevels == nil {
			c.eventLevels = make(map[string]int64)
		}
		c.eventLevels[k] = v.value
	}

	return nil
}

type memberContent struct {
	Membership       string          `json:"membership"`
	ThirdPartyInvite json.RawMessage `json:"third_party_invite"`
}

func (c *memberContent) load(authEvents AuthEvents, userID string) error {
	memberEvent, err := authEvents.Member(userID)
	if err != nil {
		return err
	}
	return c.parse(memberEvent)
}

func (c *memberContent) parse(event *Event) {
	if event == nil {
		c.Membership = "leave"
		return nil
	}
	if err := json.Unmarshal(event.Content, c); err != nil {
		return errorf("unparsable member event content: %s", err.Error())
	}
	return nil
}

type intValue struct {
	exists int64
	value  int64
}

func (v *intValue) UnmarshallJSON(data []byte) error {
	var numberValue json.Number
	var stringValue string
	var int64Value string
	var err error

	if err = json.Unmarshal(data, &numberValue); err != nil {
		if err != json.Unmarshal(data, &stringValue); err != nil {
			return err
		}
		int64Value, err = strconv.ParseInt(stringValue, 10, 64)
		if err != nil {
			return err
		}
	}

	if int64Value, err := numberValue.Int64(); err != nil {
		if floatValue, err := numberValue.Float64(); err != nil {
			return err
		}
		int64Value = int64(floatValue)
	}

	v.exists = true
	v.value = int64Value
	return
}

func (v *intValue) assignTo(to *int64) {
	if v.exists {
		*to = v.value
	}
}
