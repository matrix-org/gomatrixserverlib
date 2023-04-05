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
	) (res StateResponse, err error)
	LookupStateIDs(
		ctx context.Context, origin, s ServerName, roomID, eventID string,
	) (res StateIDResponse, err error)
}

type StateResponse interface {
	GetAuthEvents() EventJSONs
	GetStateEvents() EventJSONs
}

type StateIDResponse interface {
	GetStateEventIDs() []string
	GetAuthEventIDs() []string
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
		p.EventToAuthEventIDs[event.EventID()] = res.GetAuthEventIDs()
	}
	return res.GetStateEventIDs(), nil
}

// StateBeforeEvent implements StateProvider
func (p *FederatedStateProvider) StateBeforeEvent(ctx context.Context, roomVer RoomVersion, event *HeaderedEvent, eventIDs []string) (map[string]*Event, error) {
	res, err := p.FedClient.LookupState(ctx, p.Origin, p.Server, event.RoomID(), event.EventID(), roomVer)
	if err != nil {
		return nil, err
	}
	if p.RememberAuthEvents {
		for _, js := range res.GetAuthEvents() {
			event, err := js.UntrustedEvent(roomVer)
			if err != nil {
				continue
			}
			p.AuthEventMap[event.EventID()] = event
		}
	}

	result := make(map[string]*Event)
	for _, js := range res.GetStateEvents() {
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
	if err := CheckAllowedByAuthEvents(eventToVerify.Unwrap(), roomState, nil); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib.VerifyAuthRulesAtState: event %s is not allowed at state %s : %w",
			eventToVerify.EventID(), eventToVerify.EventID(), err,
		)
	}
	return nil
}

// TODO: de-public this function once refactor has settled. DO NOT RELY ON THIS BEING PUBLIC.
func CheckAllowedByAuthEvents(
	event *Event, eventsByID map[string]*Event,
	missingAuth AuthChainProvider,
) error {
	authEvents := NewAuthEvents(nil)

	for _, ae := range event.AuthEventIDs() {
	retryEvent:
		authEvent, ok := eventsByID[ae]
		if !ok {
			// We don't have an entry in the eventsByID map - neither an event nor nil.
			if missingAuth != nil {
				// If we have a AuthChainProvider then ask it for the missing event.
				if ev, err := missingAuth(event.Version(), []string{ae}); err == nil && len(ev) > 0 {
					// It claims to have returned events - populate the eventsByID
					// map and the authEvents provider so that we can retry with the
					// new events.
					for _, e := range ev {
						if err := authEvents.AddEvent(e); err == nil {
							eventsByID[e.EventID()] = e
						} else {
							eventsByID[e.EventID()] = nil
						}
					}
				} else {
					// It claims to have not returned an event - put a nil into the
					// eventsByID map instead. This signals that we tried to retrieve
					// the event but failed, so we don't keep retrying.
					eventsByID[ae] = nil
				}
				goto retryEvent
			} else {
				// If we didn't have a AuthChainProvider then we can't get the event
				// so just carry on without it. If it was important for anything then
				// Check() below will catch it.
				continue
			}
		} else if authEvent != nil {
			// We had an entry in the map and it contains an actual event, so add it to
			// the auth events provider.
			if err := authEvents.AddEvent(authEvent); err != nil {
				return err
			}
		} else {
			// We had an entry in the map but it contains nil, which means that we tried
			// to use the AuthChainProvider to retrieve it and failed, so at this point
			// we just have to ignore the event.
			continue
		}
	}

	// If we made it this far then we've successfully got as many of the auth events as
	// as described by AuthEventIDs(). Check if they allow the event.
	if err := Allowed(event, &authEvents); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by its auth_events: %s",
			event.EventID(), err.Error(),
		)
	}
	return nil
}
