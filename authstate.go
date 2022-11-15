package gomatrixserverlib

import (
	"context"
	"fmt"
)

// StateProvider is capable of returning the room state at any point in time.
type StateProvider interface {
	// StateIDsBeforeEvent returns a list of state event IDs for the event ID provided, which represent the entire
	// room state before that event.
	StateIDsBeforeEvent(ctx context.Context, event *HeaderedEvent) ([]string, error)
	// StateBeforeEvent returns the state of the room before the given event. `eventIDs` will be populated with the output
	// of StateIDsAtEvent to aid in event retrieval.
	StateBeforeEvent(ctx context.Context, roomVer RoomVersion, event *HeaderedEvent, eventIDs []string) (map[string]*Event, error)
}

type FederatedStateClient interface {
	LookupState(
		ctx context.Context, origin, s ServerName, roomID, eventID string, roomVersion RoomVersion,
	) (res RespState, err error)
	LookupStateIDs(
		ctx context.Context, origin, s ServerName, roomID, eventID string,
	) (res RespStateIDs, err error)
}

// FederatedStateProvider is an implementation of StateProvider which solely uses federation requests to retrieve events.
type FederatedStateProvider struct {
	FedClient FederatedStateClient
	// The remote server to ask.
	Origin ServerName
	Server ServerName
	// Set to true to remember the auth event IDs for the room at various states
	RememberAuthEvents bool
	// Maps which are populated if AuthEvents is true, so you know which events are required to do PDU checks.
	EventToAuthEventIDs map[string][]string
	AuthEventMap        map[string]*Event
}

// StateIDsBeforeEvent implements StateProvider
func (p *FederatedStateProvider) StateIDsBeforeEvent(ctx context.Context, event *HeaderedEvent) ([]string, error) {
	res, err := p.FedClient.LookupStateIDs(ctx, p.Origin, p.Server, event.RoomID(), event.EventID())
	if err != nil {
		return nil, err
	}
	if p.RememberAuthEvents {
		p.EventToAuthEventIDs[event.EventID()] = res.AuthEventIDs
	}
	return res.StateEventIDs, nil
}

// StateBeforeEvent implements StateProvider
func (p *FederatedStateProvider) StateBeforeEvent(ctx context.Context, roomVer RoomVersion, event *HeaderedEvent, eventIDs []string) (map[string]*Event, error) {
	res, err := p.FedClient.LookupState(ctx, p.Origin, p.Server, event.RoomID(), event.EventID(), roomVer)
	if err != nil {
		return nil, err
	}
	if p.RememberAuthEvents {
		for _, js := range res.AuthEvents {
			event, err := js.UntrustedEvent(roomVer)
			if err != nil {
				continue
			}
			p.AuthEventMap[event.EventID()] = event
		}
	}

	result := make(map[string]*Event)
	for _, js := range res.StateEvents {
		event, err := js.UntrustedEvent(roomVer)
		if err != nil {
			continue
		}
		result[event.EventID()] = event
	}
	return result, nil
}

// VerifyAuthRulesAtState will check that the auth_events in the given event are valid at the state of the room before that event.
//
// This implements Step 5 of https://matrix.org/docs/spec/server_server/latest#checks-performed-on-receipt-of-a-pdu
// "Passes authorization rules based on the state at the event, otherwise it is rejected."
//
// If `allowValidation` is true:
// This check initially attempts to validate that the auth_events are in the target room state, and if they are it will short-circuit
// and succeed early. THIS IS ONLY VALID IF STEP 4 HAS BEEN PREVIOUSLY APPLIED. Otherwise, a malicious server could lie and say that
// no auth_events are required and this function will short-circuit and allow it.
func VerifyAuthRulesAtState(ctx context.Context, sp StateProvider, eventToVerify *HeaderedEvent, allowValidation bool) error {
	stateIDs, err := sp.StateIDsBeforeEvent(ctx, eventToVerify)
	if err != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: cannot fetch state IDs before event %s: %w", eventToVerify.EventID(), err)
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
	roomState, err := sp.StateBeforeEvent(ctx, eventToVerify.roomVersion, eventToVerify, stateIDs)
	if err != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: cannot get state at event %s: %w", eventToVerify.EventID(), err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: context cancelled: %w", ctx.Err())
	}
	if err := checkAllowedByAuthEvents(eventToVerify.Unwrap(), roomState, nil); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib.VerifyAuthRulesAtState: event %s is not allowed at state %s : %w",
			eventToVerify.EventID(), eventToVerify.EventID(), err,
		)
	}
	return nil
}
