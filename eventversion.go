package gomatrixserverlib

import (
	"encoding/json"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

// RoomVersion refers to the room version for a specific room.
type RoomVersion string

// StateResAlgorithm refers to a version of the state resolution algorithm.
type StateResAlgorithm int

// EventFormat refers to the formatting of the event fields struct.
type EventFormat int

// EventIDFormat refers to the formatting used to generate new event IDs.
type EventIDFormat int

// RedactionAlgorithm refers to the redaction algorithm used in a room version.
type RedactionAlgorithm int

// JoinRulesPermittingKnockInEventAuth specifies which kinds of join_rule allow
// a room to be knocked upon.
type JoinRulesPermittingKnockInEventAuth int

// JoinRulesPermittingRestrictedJoinInEventAuth specifies which kinds of join_rule allow
// a room to be joined via a space.
type JoinRulesPermittingRestrictedJoinInEventAuth int

// Room version constants. These are strings because the version grammar
// allows for future expansion.
// https://matrix.org/docs/spec/#room-version-grammar
const (
	RoomVersionV1  RoomVersion = "1"
	RoomVersionV2  RoomVersion = "2"
	RoomVersionV3  RoomVersion = "3"
	RoomVersionV4  RoomVersion = "4"
	RoomVersionV5  RoomVersion = "5"
	RoomVersionV6  RoomVersion = "6"
	RoomVersionV7  RoomVersion = "7"
	RoomVersionV8  RoomVersion = "8"
	RoomVersionV9  RoomVersion = "9"
	RoomVersionV10 RoomVersion = "10"
)

// Event format constants.
const (
	EventFormatV1 EventFormat = iota + 1 // prev_events and auth_events as event references
	EventFormatV2                        // prev_events and auth_events as string array of event IDs
)

// Event ID format constants.
const (
	EventIDFormatV1 EventIDFormat = iota + 1 // randomised
	EventIDFormatV2                          // base64-encoded hash of event
	EventIDFormatV3                          // URL-safe base64-encoded hash of event
)

// State resolution constants.
const (
	StateResV1 StateResAlgorithm = iota + 1 // state resolution v1
	StateResV2                              // state resolution v2
)

// Redaction algorithm.
const (
	RedactionAlgorithmV1 RedactionAlgorithm = iota + 1 // default algorithm
	RedactionAlgorithmV2                               // no special meaning for m.room.aliases
	RedactionAlgorithmV3                               // protects join rules 'allow' key
	RedactionAlgorithmV4                               // protects membership 'join_authorised_via_users_server' key
)

// Which join_rules permit knocking?
const (
	KnocksForbidden        JoinRulesPermittingKnockInEventAuth = iota + 1 // no rooms can be knocked upon
	KnockOnly                                                             // rooms with join_rule "knock" can be knocked upon
	KnockOrKnockRestricted                                                // rooms with join_rule "knock" or "knock_restricted" can be knocked upon
)

// Which join_rules permit restricted joins?
const (
	NoRestrictedJoins           JoinRulesPermittingRestrictedJoinInEventAuth = iota + 1 // no rooms can be joined via a space
	RestrictedOnly                                                                      // rooms with join_rule "restricted" can be joined via a space
	RestrictedOrKnockRestricted                                                         // rooms with join_rule "restricted" or "knock_restricted" can be joined via a space
)

var roomVersionMeta = map[RoomVersion]RoomVersionDescription{
	RoomVersionV1: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV1,
		eventFormat:                     EventFormatV1,
		eventIDFormat:                   EventIDFormatV1,
		redactionAlgorithm:              RedactionAlgorithmV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV2: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV1,
		eventIDFormat:                   EventIDFormatV1,
		redactionAlgorithm:              RedactionAlgorithmV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV3: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV2,
		redactionAlgorithm:              RedactionAlgorithmV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV4: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV5: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV1,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV6: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV2,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV7: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV2,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV8: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV3,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: RestrictedOnly,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV9: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV4,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: RestrictedOnly,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV10: {
		Supported:                       true,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV4,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOrKnockRestricted,
		allowRestrictedJoinsInEventAuth: RestrictedOrKnockRestricted,
		requireIntegerPowerLevels:       true,
	},
	"org.matrix.msc3667": { // based on room version 7
		Supported:                       true,
		Stable:                          false,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV2,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       true,
	},
	"org.matrix.msc3787": { // roughly, the union of v7 and v9
		Supported:                       true,
		Stable:                          false,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              RedactionAlgorithmV4,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOrKnockRestricted,
		allowRestrictedJoinsInEventAuth: RestrictedOrKnockRestricted,
		requireIntegerPowerLevels:       false,
	},
}

// RoomVersions returns information about room versions currently
// implemented by this commit of gomatrixserverlib.
func RoomVersions() map[RoomVersion]RoomVersionDescription {
	return roomVersionMeta
}

// SupportedRoomVersions returns a map of descriptions for room
// versions that are marked as supported.
func SupportedRoomVersions() map[RoomVersion]RoomVersionDescription {
	versions := make(map[RoomVersion]RoomVersionDescription)
	for id, version := range RoomVersions() {
		if version.Supported {
			versions[id] = version
		}
	}
	return versions
}

// StableRoomVersions returns a map of descriptions for room
// versions that are marked as stable.
func StableRoomVersions() map[RoomVersion]RoomVersionDescription {
	versions := make(map[RoomVersion]RoomVersionDescription)
	for id, version := range RoomVersions() {
		if version.Supported && version.Stable {
			versions[id] = version
		}
	}
	return versions
}

// RoomVersionDescription contains information about a room version,
// namely whether it is marked as supported or stable in this server
// version, along with the state resolution algorithm, event ID etc
// formats used.
//
// A version is supported if the server has some support for rooms
// that are this version. A version is marked as stable or unstable
// in order to hint whether the version should be used to clients
// calling the /capabilities endpoint.
// https://matrix.org/docs/spec/client_server/r0.6.0#get-matrix-client-r0-capabilities
type RoomVersionDescription struct {
	stateResAlgorithm               StateResAlgorithm
	eventFormat                     EventFormat
	eventIDFormat                   EventIDFormat
	redactionAlgorithm              RedactionAlgorithm
	allowKnockingInEventAuth        JoinRulesPermittingKnockInEventAuth
	allowRestrictedJoinsInEventAuth JoinRulesPermittingRestrictedJoinInEventAuth
	enforceSignatureChecks          bool
	enforceCanonicalJSON            bool
	powerLevelsIncludeNotifications bool
	requireIntegerPowerLevels       bool
	Supported                       bool
	Stable                          bool
}

// StateResAlgorithm returns the state resolution for the given room version.
func (v RoomVersion) StateResAlgorithm() (StateResAlgorithm, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.stateResAlgorithm, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// EventFormat returns the event format for the given room version.
func (v RoomVersion) EventFormat() (EventFormat, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.eventFormat, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// EventIDFormat returns the event ID format for the given room version.
func (v RoomVersion) EventIDFormat() (EventIDFormat, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.eventIDFormat, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// RedactionAlgorithm returns the redaction algorithm for the given room version.
func (v RoomVersion) RedactionAlgorithm() (RedactionAlgorithm, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.redactionAlgorithm, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// StrictValidityChecking returns true if the given room version calls for
// strict signature checking (room version 5 and onward) or false otherwise.
func (v RoomVersion) StrictValidityChecking() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.enforceSignatureChecks, nil
	}
	return false, UnsupportedRoomVersionError{v}
}

// PowerLevelsIncludeNotifications returns true if the given room version calls
// for the power level checks to cover the `notifications` key or false otherwise.
func (v RoomVersion) PowerLevelsIncludeNotifications() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.powerLevelsIncludeNotifications, nil
	}
	return false, UnsupportedRoomVersionError{v}
}

// AllowKnockingInEventAuth returns true if the given room version and given
// join rule allows for the `knock` membership state or false otherwise.
func (v RoomVersion) AllowKnockingInEventAuth(joinRule string) (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		switch r.allowKnockingInEventAuth {
		case KnockOnly:
			return joinRule == spec.Knock, nil
		case KnockOrKnockRestricted:
			return (joinRule == spec.Knock || joinRule == spec.KnockRestricted), nil
		case KnocksForbidden:
			return false, nil
		}
	}
	return false, UnsupportedRoomVersionError{v}
}

// AllowRestrictedJoinsInEventAuth returns true if the given room version and
// join rule allows for memberships signed by servers in the restricted join rules.
func (v RoomVersion) AllowRestrictedJoinsInEventAuth(joinRule string) (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		switch r.allowRestrictedJoinsInEventAuth {
		case NoRestrictedJoins:
			return false, nil
		case RestrictedOnly:
			return joinRule == spec.Restricted, nil
		case RestrictedOrKnockRestricted:
			return (joinRule == spec.Restricted || joinRule == spec.KnockRestricted), nil
		}
	}
	return false, UnsupportedRoomVersionError{v}
}

// MayAllowRestrictedJoinsInEventAuth returns true if the given room version
// might allow for memberships signed by servers in the restricted join rules.
// (For an authoritative answer, the room's join rules must be known. If they
// are, use AllowRestrictedJoinsInEventAuth.)
func (v RoomVersion) MayAllowRestrictedJoinsInEventAuth() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		switch r.allowRestrictedJoinsInEventAuth {
		case NoRestrictedJoins:
			return false, nil
		case RestrictedOnly, RestrictedOrKnockRestricted:
			return true, nil
		}
	}
	return false, UnsupportedRoomVersionError{v}
}

// PowerLevelsIncludeNotifications returns true if the given room version calls
// for the power level checks to cover the `notifications` key or false otherwise.
func (v RoomVersion) EnforceCanonicalJSON() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.enforceCanonicalJSON, nil
	}
	return false, UnsupportedRoomVersionError{v}
}

// RequireIntegerPowerLevels returns true if the given room version calls for
// power levels as integers only, false otherwise.
func (v RoomVersion) RequireIntegerPowerLevels() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.requireIntegerPowerLevels, nil
	}
	return false, UnsupportedRoomVersionError{v}
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event.
func (v RoomVersion) RedactEventJSON(eventJSON []byte) ([]byte, error) {
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
	case spec.MRoomCreate:
		newContent.createContent = event.Content.createContent
	case spec.MRoomMember:
		newContent.memberContent = event.Content.memberContent
		if algo, err := v.RedactionAlgorithm(); err != nil {
			return nil, err
		} else if algo < RedactionAlgorithmV4 {
			// We only stopped redacting the 'join_authorised_via_users_server'
			// key in room version 9, so if the algorithm used is from an older
			// room version, we should ensure this field is redacted.
			newContent.memberContent.AuthorisedVia = ""
		}
	case spec.MRoomJoinRules:
		newContent.joinRulesContent = event.Content.joinRulesContent
		if algo, err := v.RedactionAlgorithm(); err != nil {
			return nil, err
		} else if algo < RedactionAlgorithmV3 {
			// We only stopped redacting the 'allow' key in room version 8,
			// so if the algorithm used is from an older room version, we
			// should ensure this field is redacted.
			newContent.joinRulesContent.Allow = nil
		}
	case spec.MRoomPowerLevels:
		newContent.powerLevelContent = event.Content.powerLevelContent
	case spec.MRoomHistoryVisibility:
		newContent.historyVisibilityContent = event.Content.historyVisibilityContent
	case spec.MRoomAliases:
		if algo, err := v.RedactionAlgorithm(); err != nil {
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

func (v RoomVersion) NewEventFromTrustedJSON(eventJSON []byte, redacted bool) (result *Event, err error) {
	return newEventFromTrustedJSON(eventJSON, redacted, v)
}

func (v RoomVersion) NewEventFromUntrustedJSON(eventJSON []byte) (result *Event, err error) {
	return newEventFromUntrustedJSON(eventJSON, v)
}

// UnsupportedRoomVersionError occurs when a call has been made with a room
// version that is not supported by this version of gomatrixserverlib.
type UnsupportedRoomVersionError struct {
	Version RoomVersion
}

func (e UnsupportedRoomVersionError) Error() string {
	return fmt.Sprintf("gomatrixserverlib: unsupported room version '%s'", e.Version)
}
