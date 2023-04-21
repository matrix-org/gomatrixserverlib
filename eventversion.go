package gomatrixserverlib

import (
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

var roomVersionMeta = map[RoomVersion]RoomVersionImpl{
	RoomVersionV1: {
		ver:                             RoomVersionV1,
		Stable:                          true,
		stateResAlgorithm:               StateResV1,
		eventFormat:                     EventFormatV1,
		eventIDFormat:                   EventIDFormatV1,
		redactionAlgorithm:              redactEventJSONV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV2: {
		ver:                             RoomVersionV2,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV1,
		eventIDFormat:                   EventIDFormatV1,
		redactionAlgorithm:              redactEventJSONV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV3: {
		ver:                             RoomVersionV3,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV2,
		redactionAlgorithm:              redactEventJSONV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV4: {
		ver:                             RoomVersionV4,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV1,
		enforceSignatureChecks:          false,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV5: {
		ver:                             RoomVersionV5,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV1,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            false,
		powerLevelsIncludeNotifications: false,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV6: {
		ver:                             RoomVersionV6,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV2,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV7: {
		ver:                             RoomVersionV7,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV2,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV8: {
		ver:                             RoomVersionV8,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV3,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: RestrictedOnly,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV9: {
		ver:                             RoomVersionV9,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV4,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: RestrictedOnly,
		requireIntegerPowerLevels:       false,
	},
	RoomVersionV10: {
		ver:                             RoomVersionV10,
		Stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV4,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOrKnockRestricted,
		allowRestrictedJoinsInEventAuth: RestrictedOrKnockRestricted,
		requireIntegerPowerLevels:       true,
	},
	"org.matrix.msc3667": { // based on room version 7
		ver:                             RoomVersion("org.matrix.msc3667"),
		Stable:                          false,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV2,
		enforceSignatureChecks:          true,
		enforceCanonicalJSON:            true,
		powerLevelsIncludeNotifications: true,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		requireIntegerPowerLevels:       true,
	},
	"org.matrix.msc3787": { // roughly, the union of v7 and v9
		ver:                             RoomVersion("org.matrix.msc3787"),
		Stable:                          false,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV4,
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
func RoomVersions() map[RoomVersion]RoomVersionImpl {
	return roomVersionMeta
}

func KnownRoomVersion(verStr RoomVersion) bool {
	_, ok := roomVersionMeta[verStr]
	return ok
}

// MustGetRoomVersion is GetRoomVersion but panics if the version doesn't exist. Useful for tests.
func MustGetRoomVersion(verStr RoomVersion) RoomVersionImpl {
	impl, err := GetRoomVersion(verStr)
	if err != nil {
		panic(fmt.Sprintf("MustGetRoomVersion: %s", verStr))
	}
	return impl
}

func GetRoomVersion(verStr RoomVersion) (impl RoomVersionImpl, err error) {
	v, ok := roomVersionMeta[verStr]
	if !ok {
		return impl, UnsupportedRoomVersionError{
			Version: verStr,
		}
	}
	return v, nil
}

// StableRoomVersions returns a map of descriptions for room
// versions that are marked as stable.
func StableRoomVersions() map[RoomVersion]RoomVersionImpl {
	versions := make(map[RoomVersion]RoomVersionImpl)
	for id, version := range RoomVersions() {
		if version.Stable {
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
type RoomVersionImpl struct {
	ver                             RoomVersion
	stateResAlgorithm               StateResAlgorithm
	eventFormat                     EventFormat
	eventIDFormat                   EventIDFormat
	redactionAlgorithm              func(eventJSON []byte) ([]byte, error)
	allowKnockingInEventAuth        JoinRulesPermittingKnockInEventAuth
	allowRestrictedJoinsInEventAuth JoinRulesPermittingRestrictedJoinInEventAuth
	enforceSignatureChecks          bool
	enforceCanonicalJSON            bool
	powerLevelsIncludeNotifications bool
	requireIntegerPowerLevels       bool
	Stable                          bool
}

// StateResAlgorithm returns the state resolution for the given room version.
func (v RoomVersionImpl) StateResAlgorithm() StateResAlgorithm {
	return v.stateResAlgorithm
}

// EventFormat returns the event format for the given room version.
func (v RoomVersionImpl) EventFormat() EventFormat {
	return v.eventFormat
}

// EventIDFormat returns the event ID format for the given room version.
func (v RoomVersionImpl) EventIDFormat() EventIDFormat {
	return v.eventIDFormat
}

// StrictValidityChecking returns true if the given room version calls for
// strict signature checking (room version 5 and onward) or false otherwise.
func (v RoomVersionImpl) StrictValidityChecking() bool {
	return v.enforceSignatureChecks
}

// PowerLevelsIncludeNotifications returns true if the given room version calls
// for the power level checks to cover the `notifications` key or false otherwise.
func (v RoomVersionImpl) PowerLevelsIncludeNotifications() bool {
	return v.powerLevelsIncludeNotifications
}

// AllowKnockingInEventAuth returns true if the given room version and given
// join rule allows for the `knock` membership state or false otherwise.
func (v RoomVersionImpl) AllowKnockingInEventAuth(joinRule string) bool {
	switch v.allowKnockingInEventAuth {
	case KnockOnly:
		return joinRule == spec.Knock
	case KnockOrKnockRestricted:
		return (joinRule == spec.Knock || joinRule == spec.KnockRestricted)
	case KnocksForbidden:
		return false
	}
	return false
}

// AllowRestrictedJoinsInEventAuth returns true if the given room version and
// join rule allows for memberships signed by servers in the restricted join rules.
func (v RoomVersionImpl) AllowRestrictedJoinsInEventAuth(joinRule string) bool {
	switch v.allowRestrictedJoinsInEventAuth {
	case NoRestrictedJoins:
		return false
	case RestrictedOnly:
		return joinRule == spec.Restricted
	case RestrictedOrKnockRestricted:
		return (joinRule == spec.Restricted || joinRule == spec.KnockRestricted)
	}
	return false
}

// MayAllowRestrictedJoinsInEventAuth returns true if the given room version
// might allow for memberships signed by servers in the restricted join rules.
// (For an authoritative answer, the room's join rules must be known. If they
// are, use AllowRestrictedJoinsInEventAuth.)
func (v RoomVersionImpl) MayAllowRestrictedJoinsInEventAuth() bool {
	switch v.allowRestrictedJoinsInEventAuth {
	case NoRestrictedJoins:
		return false
	case RestrictedOnly, RestrictedOrKnockRestricted:
		return true
	}
	return false
}

// PowerLevelsIncludeNotifications returns true if the given room version calls
// for the power level checks to cover the `notifications` key or false otherwise.
func (v RoomVersionImpl) EnforceCanonicalJSON() bool {
	return v.enforceCanonicalJSON
}

// RequireIntegerPowerLevels returns true if the given room version calls for
// power levels as integers only, false otherwise.
func (v RoomVersionImpl) RequireIntegerPowerLevels() bool {
	return v.requireIntegerPowerLevels
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event.
func (v RoomVersionImpl) RedactEventJSON(eventJSON []byte) ([]byte, error) {
	return v.redactionAlgorithm(eventJSON)
}

func (v RoomVersionImpl) NewEventFromTrustedJSON(eventJSON []byte, redacted bool) (result *Event, err error) {
	return newEventFromTrustedJSON(eventJSON, redacted, v)
}

func (v RoomVersionImpl) NewEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool) (result *Event, err error) {
	return newEventFromTrustedJSONWithEventID(eventID, eventJSON, redacted, v)
}

func (v RoomVersionImpl) NewEventFromUntrustedJSON(eventJSON []byte) (result *Event, err error) {
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
