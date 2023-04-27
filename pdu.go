package gomatrixserverlib

import (
	"github.com/matrix-org/gomatrixserverlib/spec"
)

type PDU interface {
	EventID() string
	StateKey() *string
	StateKeyEquals(s string) bool
	Type() string
	Content() []byte
	Membership() (string, error)
	Version() RoomVersion
	RoomID() string
	Redacts() string
	PrevEventIDs() []string
	PrevEvents() []EventReference // TODO: remove, used in Dendrite in (d *EventDatabase) StoreEvent
	OriginServerTS() spec.Timestamp
	Sender() string
	EventReference() EventReference  // TODO: remove
	Depth() int64                    // TODO: remove
	JSON() []byte                    // TODO: remove
	AuthEventIDs() []string          // TODO: remove
	ToHeaderedJSON() ([]byte, error) // TODO: remove
}

// Convert a slice of concrete PDU implementations to a slice of PDUs. This is useful when
// interfacing with GMSL functions which require []PDU.
func ToPDUs[T PDU](events []T) []PDU {
	result := make([]PDU, len(events))
	for i := range events {
		result[i] = events[i]
	}
	return result
}

// Temporary function to convert []PDU to []*Event. Panics if other types are given.
// Remove this function when Dendrite no longer needs this (i.e it uses []PDU natively throughout)
func TempCastToEvents(pdus []PDU) []*Event {
	result := make([]*Event, len(pdus))
	for i := range pdus {
		result[i] = pdus[i].(*Event)
	}
	return result
}
