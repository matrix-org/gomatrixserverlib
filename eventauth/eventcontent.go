package eventauth

import (
	"encoding/json"
	"strconv"
	"strings"
)

// createContent is the JSON content of a m.room.create event along with
// the top level keys needed for auth.
type createContent struct {
	// We need the domain of the create event when checking federatability.
	senderDomain string
	// We need the roomID to check that events are in the same room as the create event.
	roomID string
	// The "m.federate" flag tells us whether the room can be federated to other servers.
	Federate *bool `json:"m.federate"`
	// The creator of the room tells us what the default power levels are.
	Creator string `json:"creator"`
}

// load the create event content from the create event in the auth events.
func (c *createContent) load(authEvents AuthEvents) error {
	createEvent, err := authEvents.Create()
	if err != nil {
		return err
	}
	if createEvent == nil {
		return errorf("missing create event")
	}
	if err = json.Unmarshal(createEvent.Content, c); err != nil {
		return errorf("unparsable create event content: %s", err.Error())
	}
	c.roomID = createEvent.RoomID
	if c.senderDomain, err = domainFromID(createEvent.Sender); err != nil {
		return err
	}
	return nil
}

// domainAllowed checks whether the domain is allowed in the room by the
// "m.federate" flag.
func (c *createContent) domainAllowed(domain string) error {
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

// userIDAllowed checks whether the domain part of the user ID is allowed in
// the room by the "m.federate" flag.
func (c *createContent) userIDAllowed(id string) error {
	domain, err := domainFromID(id)
	if err != nil {
		return err
	}
	return c.domainAllowed(domain)
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

// memberContent is the JSON content of a m.room.member event needed for
// for auth checks.
type memberContent struct {
	Membership       string          `json:"membership"`
	ThirdPartyInvite json.RawMessage `json:"third_party_invite"`
}

// Load the member content from the member event for the user ID.
// Returns an error if there was an error loading the member event or
// parsing the event content.
func (c *memberContent) load(authEvents AuthEvents, userID string) error {
	memberEvent, err := authEvents.Member(userID)
	if err != nil {
		return err
	}
	if memberEvent == nil {
		c.Membership = "leave"
		return nil
	}
	return c.parse(*memberEvent)
}

// Parse the member content of an event.
// Returns an error if the content couldn't be parsed.
func (c *memberContent) parse(event Event) error {
	if err := json.Unmarshal(event.Content, c); err != nil {
		return errorf("unparsable member event content: %s", err.Error())
	}
	return nil
}

// powerLevelContent is the JSON content of a m.room.power_levels event needed
// for auth checks.
type powerLevelContent struct {
	banLevel          int64
	inviteLevel       int64
	kickLevel         int64
	redactLevel       int64
	userLevels        map[string]int64
	userDefaultLevel  int64
	eventLevels       map[string]int64
	eventDefaultLevel int64
	stateDefaultLevel int64
}

// userLevel returns the power level a user has in the room.
func (c *powerLevelContent) userLevel(userID string) int64 {
	level, ok := c.userLevels[userID]
	if ok {
		return level
	}
	return c.userDefaultLevel
}

// eventLevel returns the power level needed to send an event in the room.
func (c *powerLevelContent) eventLevel(eventType string, eventStateKey *string) int64 {
	if eventType == "m.room.third_party_invite" {
		// Special case third_party_invite events to have the same level as
		// m.room.member invite events.
		// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L182
		return c.inviteLevel
	}
	level, ok := c.eventLevels[eventType]
	if ok {
		return level
	}
	if eventStateKey != nil {
		return c.stateDefaultLevel
	}
	return c.eventDefaultLevel
}

// load the power level content from the power level event in the auth events.
func (c *powerLevelContent) load(authEvents AuthEvents, creatorUserID string) error {
	powerLevelsEvent, err := authEvents.PowerLevels()
	if err != nil {
		return err
	}
	if powerLevelsEvent != nil {
		return c.parse(*powerLevelsEvent)
	}

	// If there are no power leves then fall back to defaults.
	c.defaults()
	// If there is no power level event then the creator gets level 100
	// https://github.com/matrix-org/synapse/blob/v0.18.5/synapse/api/auth.py#L569
	c.userLevels = map[string]int64{creatorUserID: 100}
	return nil
}

// defaults sets the power levels to their default values.
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

// parse the power level content from an event.
func (c *powerLevelContent) parse(event Event) error {
	// Set the levels to their default values.
	c.defaults()

	// We can't extract the JSON directly to the powerLevelContent because we
	// need to convert string values to int values.
	var content struct {
		InviteLevel       levelJSONValue            `json:"invite"`
		BanLevel          levelJSONValue            `json:"ban"`
		KickLevel         levelJSONValue            `json:"kick"`
		RedactLevel       levelJSONValue            `json:"redact"`
		UserLevels        map[string]levelJSONValue `json:"users"`
		UsersDefaultLevel levelJSONValue            `json:"users_default"`
		EventLevels       map[string]levelJSONValue `json:"events"`
		StateDefaultLevel levelJSONValue            `json:"state_default"`
		EventDefaultLevel levelJSONValue            `json:"event_default"`
	}
	if err := json.Unmarshal(event.Content, &content); err != nil {
		return errorf("unparsable power_levels event content: %s", err.Error())
	}

	// Update the levels with the values that are present in the event content.
	content.InviteLevel.assignIfExists(&c.inviteLevel)
	content.BanLevel.assignIfExists(&c.banLevel)
	content.KickLevel.assignIfExists(&c.kickLevel)
	content.RedactLevel.assignIfExists(&c.redactLevel)
	content.UsersDefaultLevel.assignIfExists(&c.userDefaultLevel)
	content.StateDefaultLevel.assignIfExists(&c.stateDefaultLevel)
	content.EventDefaultLevel.assignIfExists(&c.eventDefaultLevel)

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
	if err = json.Unmarshal(data, &int64Value); err != nil {
		// If unmarshalling as an int64 fails try as a string.
		if err = json.Unmarshal(data, &stringValue); err != nil {
			// If unmarshalling as a string fails try as a float.
			if err = json.Unmarshal(data, &floatValue); err != nil {
				return err
			}
			int64Value = int64(floatValue)
		} else {
			// If we managed to get a string, try parsing the string as an int.
			int64Value, err = strconv.ParseInt(stringValue, 10, 64)
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
