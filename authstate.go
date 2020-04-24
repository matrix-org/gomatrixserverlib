package gomatrixserverlib

import (
	"context"
	"fmt"

	"github.com/matrix-org/util"
)

// StateProvider is capable of returning the room state at any point in time.
type StateProvider interface {
	// StateIDsAtEvent returns a list of state event IDs for the event ID provided, which represent the entire
	// room state at that event.
	StateIDsAtEvent(ctx context.Context, roomID, atEventID string) ([]string, error)
	// StateAtEvent returns the state of the room at the given event. `eventIDs` will be populated with the output
	// of StateIDsAtEvent to aid in event retrieval.
	StateAtEvent(ctx context.Context, roomVer RoomVersion, roomID, atEventID string, eventIDs []string) (map[string]*Event, error)
}

// FederatedStateProvider is an implementation of StateProvider which solely uses federation requests to retrieve events.
type FederatedStateProvider struct {
	FedClient *FederationClient
	// The remote server to ask.
	Server ServerName
	// Set to true to only return auth events, else returns everything.
	AuthEventsOnly bool
}

// StateIDsAtEvent implements StateProvider
func (p *FederatedStateProvider) StateIDsAtEvent(ctx context.Context, roomID, atEventID string) ([]string, error) {
	res, err := p.FedClient.LookupStateIDs(ctx, p.Server, roomID, atEventID)
	if err != nil {
		return nil, err
	}
	if p.AuthEventsOnly {
		return res.AuthEventIDs, nil
	}
	return util.UniqueStrings(append(res.AuthEventIDs, res.StateEventIDs...)), nil
}

// StateAtEvent implements StateProvider
func (p *FederatedStateProvider) StateAtEvent(ctx context.Context, roomVer RoomVersion, roomID, atEventID string, eventIDs []string) (map[string]*Event, error) {
	res, err := p.FedClient.LookupState(ctx, p.Server, roomID, atEventID, roomVer)
	if err != nil {
		return nil, err
	}
	result := make(map[string]*Event)
	for i := range res.AuthEvents {
		result[res.AuthEvents[i].EventID()] = &res.AuthEvents[i]
	}
	if p.AuthEventsOnly {
		return result, nil
	}
	for i := range res.StateEvents {
		result[res.StateEvents[i].EventID()] = &res.StateEvents[i]
	}
	return result, nil
}

// VerifyAuthRulesAtState will check that the auth_events in the given event are valid at the state provided by another event.
//
// This implements Step 5 and 6 of https://matrix.org/docs/spec/server_server/latest#checks-performed-on-receipt-of-a-pdu
// depending on what the value of `stateAtEvent` is.
// "Passes authorization rules based on the state at the event, otherwise it is rejected."
// "Passes authorization rules based on the current state of the room, otherwise it is "soft failed"."
//
// If `allowValidation` is true:
// This check initially attempts to validate that the auth_events are in the target room state, and if they are it will short-circuit
// and succeed early. THIS IS ONLY VALID IF STEP 4 HAS BEEN PREVIOUSLY APPLIED. Otherwise, a malicious server could lie and say that
// no auth_events are required and this function will short-circuit and allow it.
//
//
func VerifyAuthRulesAtState(ctx context.Context, sp StateProvider, eventToVerify HeaderedEvent, stateAtEvent string, allowValidation bool) error {
	stateIDs, err := sp.StateIDsAtEvent(ctx, eventToVerify.RoomID(), stateAtEvent)
	if err != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: cannot fetch state IDs at event %s: %w", stateAtEvent, err)
	}

	if allowValidation {
		authRulesExistAtState := true
		for _, authEventID := range eventToVerify.AuthEventIDs() {
			found := false
			for _, stateID := range stateIDs {
				if stateID == authEventID {
					found = true
					break
				}
			}
			if !found {
				authRulesExistAtState = false
				break
			}
		}
		if authRulesExistAtState {
			return nil
		}
	}
	if ctx.Err() != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: context cancelled: %w", ctx.Err())
	}

	// slow path: fetch the events at this state and check auth
	roomState, err := sp.StateAtEvent(ctx, eventToVerify.roomVersion, eventToVerify.RoomID(), stateAtEvent, stateIDs)
	if err != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: cannot get state at event %s: %w", stateAtEvent, err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: context cancelled: %w", ctx.Err())
	}
	if err := checkAllowedByAuthEvents(eventToVerify.Unwrap(), roomState); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib.VerifyAuthRulesAtState: event %s is not allowed at state %s : %w",
			eventToVerify.EventID(), stateAtEvent, err,
		)
	}
	return nil
}
