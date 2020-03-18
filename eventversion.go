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

// Room version constants. These are strings because the version grammar
// allows for future expansion.
// https://matrix.org/docs/spec/#room-version-grammar
const (
	RoomVersionV1 RoomVersion = "1"
	RoomVersionV2 RoomVersion = "2"
	RoomVersionV3 RoomVersion = "3"
	RoomVersionV4 RoomVersion = "4"
	RoomVersionV5 RoomVersion = "5"
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

var roomVersionMeta = map[RoomVersion]roomVersion{
	"1": roomVersion{
		stateResAlgorithm:      StateResV1,
		eventFormat:            EventFormatV1,
		eventIDFormat:          EventIDFormatV1,
		enforceSignatureChecks: false,
	},
	"2": roomVersion{
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV1,
		eventIDFormat:          EventIDFormatV1,
		enforceSignatureChecks: false,
	},
	"3": roomVersion{
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV2,
		eventIDFormat:          EventIDFormatV2,
		enforceSignatureChecks: false,
	},
	"4": roomVersion{
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV2,
		eventIDFormat:          EventIDFormatV3,
		enforceSignatureChecks: false,
	},
	"5": roomVersion{
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV2,
		eventIDFormat:          EventIDFormatV3,
		enforceSignatureChecks: true,
	},
}

// roomVersion contains information about a given room version, e.g. which
// state resolution algorithm or event ID format to use.
type roomVersion struct {
	stateResAlgorithm      StateResAlgorithm
	eventFormat            EventFormat
	eventIDFormat          EventIDFormat
	enforceSignatureChecks bool
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

// EnforceSignatureChecks returns true if the given room version calls for
// strict signature checking (room version 5 and onward) or false otherwise.
func (v RoomVersion) EnforceSignatureChecks() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.enforceSignatureChecks, nil
	}
	return false, UnsupportedRoomVersionError{v}
}

// UnsupportedRoomVersionError occurs when a call has been made with a room
// version that is not supported by this version of gomatrixserverlib.
type UnsupportedRoomVersionError struct {
	Version RoomVersion
}

func (e UnsupportedRoomVersionError) Error() string {
	return fmt.Sprintf("gomatrixserverlib: unsupported version '%s'", e.Version)
}
