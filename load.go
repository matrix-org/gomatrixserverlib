package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// EventLoadResult is the result of loading and verifying an event in the EventsLoader.
type EventLoadResult struct {
	Event    *HeaderedEvent
	Error    error
	SoftFail bool
}

// EventsLoader loads untrusted events and verifies them.
type EventsLoader struct {
	roomVer       RoomVersion
	keyRing       JSONVerifier
	provider      AuthChainProvider
	stateProvider StateProvider
	// Set to true to do:
	// 6. Passes authorization rules based on the current state of the room, otherwise it is "soft failed".
	// This is only desirable for live events, not backfilled events hence the flag.
	performSoftFailCheck bool
}

// NewEventsLoader returns a new events loader
func NewEventsLoader(roomVer RoomVersion, keyRing JSONVerifier, stateProvider StateProvider, provider AuthChainProvider, performSoftFailCheck bool) *EventsLoader {
	return &EventsLoader{
		roomVer:              roomVer,
		keyRing:              keyRing,
		provider:             provider,
		stateProvider:        stateProvider,
		performSoftFailCheck: performSoftFailCheck,
	}
}

// LoadAndVerify loads untrusted events and verifies them.
// Checks performed are outlined at https://matrix.org/docs/spec/server_server/latest#checks-performed-on-receipt-of-a-pdu
// The length of the returned slice will always equal the length of rawEvents.
// The order of the returned events depends on `sortOrder`. The events are reverse topologically sorted by the ordering specified. However,
// in order to sort the events must be loaded which could fail. For those events which fail to be loaded, they will
// be put at the end of the returned slice.
func (l *EventsLoader) LoadAndVerify(ctx context.Context, rawEvents []json.RawMessage, sortOrder TopologicalOrder) ([]EventLoadResult, error) {
	results := make([]EventLoadResult, len(rawEvents))

	// 1. Is a valid event, otherwise it is dropped.
	// 3. Passes hash checks, otherwise it is redacted before being processed further.
	events := make([]*Event, 0, len(rawEvents))
	errs := make([]error, 0, len(rawEvents))
	for _, rawEv := range rawEvents {
		event, err := NewEventFromUntrustedJSON(rawEv, l.roomVer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		events = append(events, event)
	}

	events = ReverseTopologicalOrdering(events, sortOrder)
	// assign the errors to the end of the slice
	for i := 0; i < len(errs); i++ {
		results[len(results)-len(errs)+i] = EventLoadResult{
			Error: errs[i],
		}
	}
	// at this point, the three slices look something like:
	// results: [ _ , _ , _ , err1 , err2 ]
	// errs: [ err1, err2 ]
	// events [ ev1, ev2, ev3 ]
	// so we can directly index from events into results from now on.

	// 2. Passes signature checks, otherwise it is dropped.
	failures := VerifyAllEventSignatures(ctx, events, l.keyRing)
	if len(failures) != len(events) {
		return nil, fmt.Errorf("gomatrixserverlib: bulk event signature verification length mismatch: %d != %d", len(failures), len(events))
	}
	for i := range events {
		h := events[i].Headered(l.roomVer)
		results[i] = EventLoadResult{
			Event: h,
		}
		if eventErr := failures[i]; eventErr != nil {
			if results[i].Error == nil { // could have failed earlier
				results[i].Error = SignatureErr{eventErr}
				continue
			}
		}
		// 4. Passes authorization rules based on the event's auth events, otherwise it is rejected.
		if err := VerifyEventAuthChain(ctx, h, l.provider); err != nil {
			if results[i].Error == nil { // could have failed earlier
				results[i].Error = AuthChainErr{err}
				continue
			}
		}

		// 5. Passes authorization rules based on the state at the event, otherwise it is rejected.
		if err := VerifyAuthRulesAtState(ctx, l.stateProvider, h, true); err != nil {
			if results[i].Error == nil { // could have failed earlier
				results[i].Error = AuthRulesErr{err}
				continue
			}
		}
	}

	// TODO: performSoftFailCheck, needs forward extremity
	return results, nil
}

type SignatureErr struct {
	err error
}

func (se SignatureErr) Error() string {
	return fmt.Sprintf("SignatureErr: %s", se.err)
}

func (se SignatureErr) Is(target error) bool {
	return strings.HasPrefix(target.Error(), "SignatureErr")
}

type AuthChainErr struct {
	err error
}

func (se AuthChainErr) Error() string {
	return fmt.Sprintf("AuthChainErr: %s", se.err)
}

func (se AuthChainErr) Is(target error) bool {
	return strings.HasPrefix(target.Error(), "AuthChainErr")
}

type AuthRulesErr struct {
	err error
}

func (se AuthRulesErr) Error() string {
	return fmt.Sprintf("AuthRulesErr: %s", se.err)
}

func (se AuthRulesErr) Is(target error) bool {
	return strings.HasPrefix(target.Error(), "AuthRulesErr")
}
