package gomatrixserverlib

import "fmt"

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

// RoomVersionDescription contains information about a given room version, e.g. which
// state resolution algorithm or event ID format to use.
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
			return joinRule == Knock, nil
		case KnockOrKnockRestricted:
			return (joinRule == Knock || joinRule == KnockRestricted), nil
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
			return joinRule == Restricted, nil
		case RestrictedOrKnockRestricted:
			return (joinRule == Restricted || joinRule == KnockRestricted), nil
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

// UnsupportedRoomVersionError occurs when a call has been made with a room
// version that is not supported by this version of gomatrixserverlib.
type UnsupportedRoomVersionError struct {
	Version RoomVersion
}

func (e UnsupportedRoomVersionError) Error() string {
	return fmt.Sprintf("gomatrixserverlib: unsupported room version '%s'", e.Version)
}
