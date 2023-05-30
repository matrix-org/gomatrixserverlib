package gomatrixserverlib

import (
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// RoomVersion refers to the room version for a specific room.
type RoomVersion string

type IRoomVersion interface {
	Version() RoomVersion
	Stable() bool
	StateResAlgorithm() StateResAlgorithm
	EventFormat() EventFormat
	EventIDFormat() EventIDFormat
	SignatureValidityCheck(atTS, validUntil spec.Timestamp) bool
	checkNotificationLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error
	AllowKnockingInEventAuth(joinRule string) bool
	AllowRestrictedJoinsInEventAuth(joinRule string) bool
	MayAllowRestrictedJoinsInEventAuth() bool
	checkCanonicalJSON(input []byte) error
	parsePowerLevels(contentBytes []byte, c *PowerLevelContent) error
	RedactEventJSON(eventJSON []byte) ([]byte, error)
	NewEventFromTrustedJSON(eventJSON []byte, redacted bool) (result PDU, err error)
	NewEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool) (result PDU, err error)
	NewEventFromUntrustedJSON(eventJSON []byte) (result PDU, err error)
	NewEventBuilder() *EventBuilder
	NewEventBuilderFromProtoEvent(pe *ProtoEvent) *EventBuilder
}

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

var roomVersionMeta = map[RoomVersion]IRoomVersion{
	RoomVersionV1: RoomVersionImpl{
		ver:                             RoomVersionV1,
		stable:                          true,
		stateResAlgorithm:               StateResV1,
		eventFormat:                     EventFormatV1,
		eventIDFormat:                   EventIDFormatV1,
		redactionAlgorithm:              redactEventJSONV1,
		signatureValidityCheckFunc:      NoStrictValidityCheck,
		canonicalJSONCheck:              noVerifyCanonicalJSON,
		notificationLevelCheck:          noCheckLevels,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV2: RoomVersionImpl{
		ver:                             RoomVersionV2,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV1,
		eventIDFormat:                   EventIDFormatV1,
		redactionAlgorithm:              redactEventJSONV1,
		signatureValidityCheckFunc:      NoStrictValidityCheck,
		canonicalJSONCheck:              noVerifyCanonicalJSON,
		notificationLevelCheck:          noCheckLevels,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV3: RoomVersionImpl{
		ver:                             RoomVersionV3,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV2,
		redactionAlgorithm:              redactEventJSONV1,
		signatureValidityCheckFunc:      NoStrictValidityCheck,
		canonicalJSONCheck:              noVerifyCanonicalJSON,
		notificationLevelCheck:          noCheckLevels,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV4: RoomVersionImpl{
		ver:                             RoomVersionV4,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV1,
		signatureValidityCheckFunc:      NoStrictValidityCheck,
		canonicalJSONCheck:              noVerifyCanonicalJSON,
		notificationLevelCheck:          noCheckLevels,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV5: RoomVersionImpl{
		ver:                             RoomVersionV5,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV1,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              noVerifyCanonicalJSON,
		notificationLevelCheck:          noCheckLevels,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV6: RoomVersionImpl{
		ver:                             RoomVersionV6,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV2,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnocksForbidden,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV7: RoomVersionImpl{
		ver:                             RoomVersionV7,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV2,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV8: RoomVersionImpl{
		ver:                             RoomVersionV8,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV3,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: RestrictedOnly,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV9: RoomVersionImpl{
		ver:                             RoomVersionV9,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV4,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: RestrictedOnly,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
	RoomVersionV10: RoomVersionImpl{
		ver:                             RoomVersionV10,
		stable:                          true,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV4,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnockOrKnockRestricted,
		allowRestrictedJoinsInEventAuth: RestrictedOrKnockRestricted,
		parsePowerLevelsFunc:            parseIntegerPowerLevels,
	},
	"org.matrix.msc3667": RoomVersionImpl{ // based on room version 7
		ver:                             RoomVersion("org.matrix.msc3667"),
		stable:                          false,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV2,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnockOnly,
		allowRestrictedJoinsInEventAuth: NoRestrictedJoins,
		parsePowerLevelsFunc:            parseIntegerPowerLevels,
	},
	"org.matrix.msc3787": RoomVersionImpl{ // roughly, the union of v7 and v9
		ver:                             RoomVersion("org.matrix.msc3787"),
		stable:                          false,
		stateResAlgorithm:               StateResV2,
		eventFormat:                     EventFormatV2,
		eventIDFormat:                   EventIDFormatV3,
		redactionAlgorithm:              redactEventJSONV4,
		signatureValidityCheckFunc:      StrictValiditySignatureCheck,
		canonicalJSONCheck:              verifyEnforcedCanonicalJSON,
		notificationLevelCheck:          checkNotificationLevels,
		allowKnockingInEventAuth:        KnockOrKnockRestricted,
		allowRestrictedJoinsInEventAuth: RestrictedOrKnockRestricted,
		parsePowerLevelsFunc:            parsePowerLevels,
	},
}

// RoomVersions returns information about room versions currently
// implemented by this commit of gomatrixserverlib.
func RoomVersions() map[RoomVersion]IRoomVersion {
	return roomVersionMeta
}

func KnownRoomVersion(verStr RoomVersion) bool {
	_, ok := roomVersionMeta[verStr]
	return ok
}

// MustGetRoomVersion is GetRoomVersion but panics if the version doesn't exist. Useful for tests.
func MustGetRoomVersion(verStr RoomVersion) IRoomVersion {
	impl, err := GetRoomVersion(verStr)
	if err != nil {
		panic(fmt.Sprintf("MustGetRoomVersion: %s", verStr))
	}
	return impl
}

func GetRoomVersion(verStr RoomVersion) (impl IRoomVersion, err error) {
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
func StableRoomVersions() map[RoomVersion]IRoomVersion {
	versions := make(map[RoomVersion]IRoomVersion)
	for id, version := range RoomVersions() {
		if version.Stable() {
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
	signatureValidityCheckFunc      SignatureValidityCheckFunc
	canonicalJSONCheck              func(eventJSON []byte) error
	notificationLevelCheck          func(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error
	parsePowerLevelsFunc            func(contentBytes []byte, c *PowerLevelContent) error
	stable                          bool
}

func (v RoomVersionImpl) Version() RoomVersion {
	return v.ver
}

func (v RoomVersionImpl) Stable() bool {
	return v.stable
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
func (v RoomVersionImpl) SignatureValidityCheck(atTS, validUntilTS spec.Timestamp) bool {
	return v.signatureValidityCheckFunc(atTS, validUntilTS)
}

// checkNotificationLevels checks that the changes in notification levels are allowed.
func (v RoomVersionImpl) checkNotificationLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	return v.notificationLevelCheck(senderLevel, oldPowerLevels, newPowerLevels)
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
func (v RoomVersionImpl) checkCanonicalJSON(eventJSON []byte) error {
	return v.canonicalJSONCheck(eventJSON)
}

// ParsePowerLevels returns true if the given room version calls for
// power levels as integers only, false otherwise.
func (v RoomVersionImpl) parsePowerLevels(contentBytes []byte, c *PowerLevelContent) error {
	return v.parsePowerLevelsFunc(contentBytes, c)
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event.
func (v RoomVersionImpl) RedactEventJSON(eventJSON []byte) ([]byte, error) {
	return v.redactionAlgorithm(eventJSON)
}

func (v RoomVersionImpl) NewEventFromTrustedJSON(eventJSON []byte, redacted bool) (result PDU, err error) {
	return newEventFromTrustedJSON(eventJSON, redacted, v)
}

func (v RoomVersionImpl) NewEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool) (result PDU, err error) {
	return newEventFromTrustedJSONWithEventID(eventID, eventJSON, redacted, v)
}

func (v RoomVersionImpl) NewEventFromUntrustedJSON(eventJSON []byte) (result PDU, err error) {
	return newEventFromUntrustedJSON(eventJSON, v)
}

func (v RoomVersionImpl) NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		version: v,
	}
}
func (v RoomVersionImpl) NewEventBuilderFromProtoEvent(pe *ProtoEvent) *EventBuilder {
	eb := v.NewEventBuilder()
	// for now copies all fields, but we should be specific depending on the room version
	eb.AuthEvents = pe.AuthEvents
	eb.Content = pe.Content
	eb.Depth = pe.Depth
	eb.PrevEvents = pe.PrevEvents
	eb.Redacts = pe.Redacts
	eb.RoomID = pe.RoomID
	eb.Sender = pe.Sender
	eb.Signature = pe.Signature
	eb.StateKey = pe.StateKey
	eb.Type = pe.Type
	eb.Unsigned = pe.Unsigned
	return eb
}

// NewEventFromHeaderedJSON creates a new event where the room version is embedded in the JSON bytes.
// The version is contained in the top level "_room_version" key.
func NewEventFromHeaderedJSON(headeredEventJSON []byte, redacted bool) (PDU, error) {
	eventID := gjson.GetBytes(headeredEventJSON, "_event_id").String()
	roomVer := RoomVersion(gjson.GetBytes(headeredEventJSON, "_room_version").String())
	verImpl, err := GetRoomVersion(roomVer)
	if err != nil {
		return nil, err
	}
	headeredEventJSON, _ = sjson.DeleteBytes(headeredEventJSON, "_event_id")
	headeredEventJSON, _ = sjson.DeleteBytes(headeredEventJSON, "_room_version")

	return newEventFromTrustedJSONWithEventID(eventID, headeredEventJSON, redacted, verImpl)
}

// UnsupportedRoomVersionError occurs when a call has been made with a room
// version that is not supported by this version of gomatrixserverlib.
type UnsupportedRoomVersionError struct {
	Version RoomVersion
}

func (e UnsupportedRoomVersionError) Error() string {
	return fmt.Sprintf("gomatrixserverlib: unsupported room version '%s'", e.Version)
}
