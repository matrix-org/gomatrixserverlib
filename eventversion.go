package gomatrixserverlib

// RoomVersion refers to the room version for a specific room.
type RoomVersion int

// StateResAlgorithm refers to a version of the state resolution algorithm.
type StateResAlgorithm int

// EventIDFormat refers to the formatting used to generate new event IDs.
type EventIDFormat int

// Room version constants
const (
	RoomVersionV1 RoomVersion = iota + 1
	RoomVersionV2
	RoomVersionV3
	RoomVersionV4
	RoomVersionV5
)

// Event ID format constants
const (
	EventIDFormatV1 EventIDFormat = iota + 1
	EventIDFormatV2
	EventIDFormatV3
)

// State resolution constants
const (
	StateResV1 StateResAlgorithm = iota + 1
	StateResV2
)

// RoomVersionMeta contains information about a given room version, e.g. which
// state resolution algorithm or event ID format to use.
type roomVersion struct {
	stateResAlgorithm      StateResAlgorithm
	eventIDFormat          EventIDFormat
	enforceSignatureChecks bool
}

// StateResAlgorithm returns the state resolution for the given room version.
func (v RoomVersion) StateResAlgorithm() StateResAlgorithm {
	if r, ok := roomVersionMeta[v]; ok {
		return r.stateResAlgorithm
	}
	return StateResV1
}

// EventIDFormat returns the event ID format for the given room version.
func (v RoomVersion) EventIDFormat() EventIDFormat {
	if r, ok := roomVersionMeta[v]; ok {
		return r.eventIDFormat
	}
	return EventIDFormatV1
}

// EnforceSignatureChecks returns true if the given room version calls for
// strict signature checking (room version 5 and onward) or false otherwise.
func (v RoomVersion) EnforceSignatureChecks() bool {
	if r, ok := roomVersionMeta[v]; ok {
		return r.enforceSignatureChecks
	}
	return false
}

var roomVersionMeta = map[RoomVersion]roomVersion{
	1: roomVersion{
		stateResAlgorithm:      StateResV1,
		eventIDFormat:          EventIDFormatV1,
		enforceSignatureChecks: false,
	},
	2: roomVersion{
		stateResAlgorithm:      StateResV2,
		eventIDFormat:          EventIDFormatV1,
		enforceSignatureChecks: false,
	},
	3: roomVersion{
		stateResAlgorithm:      StateResV2,
		eventIDFormat:          EventIDFormatV2,
		enforceSignatureChecks: false,
	},
	4: roomVersion{
		stateResAlgorithm:      StateResV2,
		eventIDFormat:          EventIDFormatV3,
		enforceSignatureChecks: false,
	},
	5: roomVersion{
		stateResAlgorithm:      StateResV2,
		eventIDFormat:          EventIDFormatV3,
		enforceSignatureChecks: true,
	},
}
