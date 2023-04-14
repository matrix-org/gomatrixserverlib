package gomatrixserverlib

import (
	"context"
	"fmt"
)

// AuthChainProvider returns the requested list of auth events.
type AuthChainProvider func(roomVer RoomVersion, eventIDs []string) ([]*Event, error)

// VerifyEventAuthChain will verify that the event is allowed according to its auth_events, and then
// recursively verify each of those auth_events.
//
// This function implements Step 4 of https://matrix.org/docs/spec/server_server/latest#checks-performed-on-receipt-of-a-pdu
// "Passes authorization rules based on the event's auth events, otherwise it is rejected."
// If an event passes this function without error, the caller should make sure that all the auth_events were actually for
// a valid room state, and not referencing random bits of room state from different positions in time (Step 5).
//
// The `provideEvents` function will only be called for *new* events rather than for everything as it is
// assumed that this function is costly. Failing to provide all the requested events will fail this function.
// Returning an error from `provideEvents` will also fail this function.
func VerifyEventAuthChain(ctx context.Context, eventToVerify *HeaderedEvent, provideEvents AuthChainProvider) error {
	eventsByID := make(map[string]*Event) // A lookup table for verifying this auth chain
	evv := eventToVerify.Unwrap()
	eventsByID[evv.EventID()] = evv
	verifiedEvents := make(map[string]bool) // events are put here when they are fully verified.
	eventsToVerify := []*Event{evv}
	var curr *Event

	for len(eventsToVerify) > 0 {
		// pop the top of the stack
		// A stack works best here as it means we do depth-first verification which reduces the
		// number of duplicate events to verify.
		curr, eventsToVerify = eventsToVerify[len(eventsToVerify)-1], eventsToVerify[:len(eventsToVerify)-1]
		if verifiedEvents[curr.EventID()] {
			continue // already verified
		}
		// work out which events we need to fetch, if any.
		var need []string
		for _, needEventID := range curr.AuthEventIDs() {
			if eventsByID[needEventID] == nil {
				need = append(need, needEventID)
			}
		}
		// fetch the events and add them to the lookup table
		if len(need) > 0 {
			newEvents, err := provideEvents(eventToVerify.roomVersion, need)
			if err != nil {
				return fmt.Errorf("gomatrixserverlib: VerifyEventAuthChain failed to obtain auth events: %w", err)
			}
			for i := range newEvents {
				eventsByID[newEvents[i].EventID()] = newEvents[i] // add to lookup table
			}
			eventsToVerify = append(eventsToVerify, newEvents...) // verify these events too
		}
		// verify the event
		if err := checkAllowedByAuthEvents(curr, eventsByID, provideEvents); err != nil {
			return fmt.Errorf("gomatrixserverlib: VerifyEventAuthChain %v failed auth check: %w", curr.EventID(), err)
		}
		// add to the verified list
		verifiedEvents[curr.EventID()] = true
	}
	return nil
}
