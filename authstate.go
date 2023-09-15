package gomatrixserverlib

import (
	"context"
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"
)

// StateProvider is capable of returning the room state at any point in time.
type StateProvider interface {
	// StateIDsBeforeEvent returns a list of state event IDs for the event ID provided, which represent the entire
	// room state before that event.
	StateIDsBeforeEvent(ctx context.Context, event PDU) ([]string, error)
	// StateBeforeEvent returns the state of the room before the given event. `eventIDs` will be populated with the output
	// of StateIDsAtEvent to aid in event retrieval.
	StateBeforeEvent(ctx context.Context, roomVer RoomVersion, event PDU, eventIDs []string) (map[string]PDU, error)
}

type FederatedStateClient interface {
	LookupState(
		ctx context.Context, origin, s spec.ServerName, roomID, eventID string, roomVersion RoomVersion,
	) (res StateResponse, err error)
	LookupStateIDs(
		ctx context.Context, origin, s spec.ServerName, roomID, eventID string,
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

type stateResponseImpl struct {
	authEvents  EventJSONs
	stateEvents EventJSONs
}

func (s *stateResponseImpl) GetAuthEvents() EventJSONs {
	return s.authEvents
}
func (s *stateResponseImpl) GetStateEvents() EventJSONs {
	return s.stateEvents
}

// FederatedStateProvider is an implementation of StateProvider which solely uses federation requests to retrieve events.
type FederatedStateProvider struct {
	FedClient FederatedStateClient
	// The remote server to ask.
	Origin spec.ServerName
	Server spec.ServerName
	// Set to true to remember the auth event IDs for the room at various states
	RememberAuthEvents bool
	// Maps which are populated if AuthEvents is true, so you know which events are required to do PDU checks.
	EventToAuthEventIDs map[string][]string
	AuthEventMap        map[string]PDU
}

// StateIDsBeforeEvent implements StateProvider
func (p *FederatedStateProvider) StateIDsBeforeEvent(ctx context.Context, event PDU) ([]string, error) {
	res, err := p.FedClient.LookupStateIDs(ctx, p.Origin, p.Server, event.RoomID().String(), event.EventID())
	if err != nil {
		return nil, err
	}
	if p.RememberAuthEvents {
		p.EventToAuthEventIDs[event.EventID()] = res.GetAuthEventIDs()
	}
	return res.GetStateEventIDs(), nil
}

// StateBeforeEvent implements StateProvider
func (p *FederatedStateProvider) StateBeforeEvent(ctx context.Context, roomVer RoomVersion, event PDU, eventIDs []string) (map[string]PDU, error) {
	res, err := p.FedClient.LookupState(ctx, p.Origin, p.Server, event.RoomID().String(), event.EventID(), roomVer)
	if err != nil {
		return nil, err
	}
	roomVerImpl, err := GetRoomVersion(roomVer)
	if err != nil {
		return nil, err
	}
	if p.RememberAuthEvents {
		for _, js := range res.GetAuthEvents() {
			event, err := roomVerImpl.NewEventFromUntrustedJSON(js)
			if err != nil {
				continue
			}
			p.AuthEventMap[event.EventID()] = event
		}
	}

	result := make(map[string]PDU)
	for _, js := range res.GetStateEvents() {
		event, err := roomVerImpl.NewEventFromUntrustedJSON(js)
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
func VerifyAuthRulesAtState(ctx context.Context, sp StateProvider, eventToVerify PDU, allowValidation bool, userIDForSender spec.UserIDForSender) error {
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
	roomState, err := sp.StateBeforeEvent(ctx, eventToVerify.Version(), eventToVerify, stateIDs)
	if err != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: cannot get state at event %s: %w", eventToVerify.EventID(), err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("gomatrixserverlib.VerifyAuthRulesAtState: context cancelled: %w", ctx.Err())
	}
	if err := checkAllowedByAuthEvents(eventToVerify, roomState, nil, userIDForSender); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib.VerifyAuthRulesAtState: event %s is not allowed at state %s : %w",
			eventToVerify.EventID(), eventToVerify.EventID(), err,
		)
	}
	return nil
}

func checkAllowedByAuthEvents(
	event PDU, eventsByID map[string]PDU,
	missingAuth EventProvider, userIDForSender spec.UserIDForSender,
) error {
	authEvents := NewAuthEvents(nil)

	for _, ae := range event.AuthEventIDs() {
	retryEvent:
		authEvent, ok := eventsByID[ae]
		if !ok {
			// We don't have an entry in the eventsByID map - neither an event nor nil.
			if missingAuth != nil {
				// If we have a EventProvider then ask it for the missing event.
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
				// If we didn't have a EventProvider then we can't get the event
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
			// to use the EventProvider to retrieve it and failed, so at this point
			// we just have to ignore the event.
			continue
		}
	}

	// If we made it this far then we've successfully got as many of the auth events as
	// as described by AuthEventIDs(). Check if they allow the event.
	if err := Allowed(event, &authEvents, userIDForSender); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by its auth_events: %s",
			event.EventID(), err.Error(),
		)
	}
	return nil
}

// CheckStateResponse checks that a response to /state is valid. This function removes events
// that do not have valid signatures, and also returns the unmarshalled
// auth events (first return parameter) and state events (second
// return parameter). Does not alter any input args.
func CheckStateResponse(
	ctx context.Context, r StateResponse, roomVersion RoomVersion,
	keyRing JSONVerifier, missingAuth EventProvider, userIDForSender spec.UserIDForSender,
) ([]PDU, []PDU, error) {
	logger := util.GetLogger(ctx)
	authEvents := r.GetAuthEvents().UntrustedEvents(roomVersion)
	stateEvents := r.GetStateEvents().UntrustedEvents(roomVersion)
	var allEvents []PDU
	for _, event := range authEvents {
		if event.StateKey() == nil {
			return nil, nil, fmt.Errorf("gomatrixserverlib: event %q does not have a state key", event.EventID())
		}
		allEvents = append(allEvents, event)
	}

	stateTuples := map[StateKeyTuple]bool{}
	for _, event := range stateEvents {
		if event.StateKey() == nil {
			return nil, nil, fmt.Errorf("gomatrixserverlib: event %q does not have a state key", event.EventID())
		}
		stateTuple := StateKeyTuple{EventType: event.Type(), StateKey: *event.StateKey()}
		if stateTuples[stateTuple] {
			return nil, nil, fmt.Errorf(
				"gomatrixserverlib: duplicate state key tuple (%q, %q)",
				event.Type(), *event.StateKey(),
			)
		}
		stateTuples[stateTuple] = true
		allEvents = append(allEvents, event)
	}

	// Check if the events pass signature checks.
	logger.Infof("Checking event signatures for %d events of room state", len(allEvents))
	errors := VerifyAllEventSignatures(ctx, allEvents, keyRing, userIDForSender)
	if len(errors) != len(allEvents) {
		return nil, nil, fmt.Errorf("expected %d errors but got %d", len(allEvents), len(errors))
	}

	// Work out which events failed the signature checks.
	failures := map[string]error{}
	for i, e := range allEvents {
		if errors[i] != nil {
			logrus.WithError(errors[i]).Warnf("Signature validation failed for event %q", e.EventID())
			failures[e.EventID()] = errors[i]
		}
	}

	// Collect a map of event reference to event.
	eventsByID := map[string]PDU{}
	for i := range allEvents {
		if _, ok := failures[allEvents[i].EventID()]; !ok {
			eventsByID[allEvents[i].EventID()] = allEvents[i]
		}
	}

	// Check whether the events are allowed by the auth rules.
	for _, event := range allEvents {
		if err := checkAllowedByAuthEvents(event, eventsByID, missingAuth, userIDForSender); err != nil {
			logrus.WithError(err).Warnf("Event %q is not allowed by its auth events", event.EventID())
			failures[event.EventID()] = err
		}
	}

	// For all of the events that weren't verified, remove them
	// from the RespState. This way they won't be passed onwards.
	if f := len(failures); f > 0 {
		logger.Warnf("Discarding %d auth/state event(s) due to invalid signatures", f)

		for i := 0; i < len(authEvents); i++ {
			if _, ok := failures[authEvents[i].EventID()]; ok {
				authEvents = append(authEvents[:i], authEvents[i+1:]...)
				i--
			}
		}
		for i := 0; i < len(stateEvents); i++ {
			if _, ok := failures[stateEvents[i].EventID()]; ok {
				stateEvents = append(stateEvents[:i], stateEvents[i+1:]...)
				i--
			}
		}
	}

	return authEvents, stateEvents, nil
}

// Check that a response to /send_join is valid. If it is then it
// returns a reference to the RespState that contains the room state
// excluding any events that failed signature checks.
// This checks that it would be valid as a response to /state.
// This also checks that the join event is allowed by the state.
// This function mutates the RespSendJoin to remove any events from
// AuthEvents or StateEvents that do not have valid signatures.
func CheckSendJoinResponse(
	ctx context.Context, roomVersion RoomVersion, r StateResponse,
	keyRing JSONVerifier, joinEvent PDU,
	missingAuth EventProvider, userIDForSender spec.UserIDForSender,
) (StateResponse, error) {
	// First check that the state is valid and that the events in the response
	// are correctly signed.
	//
	// The response to /send_join has the same data as a response to /state
	// and the checks for a response to /state also apply.
	authEvents, stateEvents, err := CheckStateResponse(ctx, r, roomVersion, keyRing, missingAuth, userIDForSender)
	if err != nil {
		return nil, err
	}

	eventsByID := map[string]PDU{}
	authEventProvider := NewAuthEvents(nil)

	// Since checkAllowedByAuthEvents needs to be able to look up any of the
	// auth events by ID only, we will build a map which contains references
	// to all of the auth events.
	for i, event := range authEvents {
		eventsByID[event.EventID()] = authEvents[i]
	}

	// Then we add the current state events too, since our newly formed
	// membership event will likely refer to these as auth events too.
	for i, event := range stateEvents {
		eventsByID[event.EventID()] = stateEvents[i]
	}

	// Now check that the join event is valid against its auth events.
	if err := checkAllowedByAuthEvents(joinEvent, eventsByID, missingAuth, userIDForSender); err != nil {
		return nil, fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by its auth events: %w",
			joinEvent.EventID(), err,
		)
	}

	// Add all of the current state events to an auth provider, allowing us
	// to check specifically that the join event is allowed by the supplied
	// state (and not by former auth events).
	stateEventsJSON := NewEventJSONsFromEvents(stateEvents)
	for i := range stateEventsJSON {
		if err := authEventProvider.AddEvent(stateEvents[i]); err != nil {
			return nil, err
		}
	}

	// Now check that the join event is valid against the supplied state.
	if err := Allowed(joinEvent, &authEventProvider, userIDForSender); err != nil {
		return nil, fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by the current room state: %w",
			joinEvent.EventID(), err,
		)
	}

	return &stateResponseImpl{
		authEvents:  NewEventJSONsFromEvents(authEvents),
		stateEvents: stateEventsJSON,
	}, nil
}

// LineariseStateResponse combines the auth events and the state events and returns
// them in an order where every event comes after its auth events.
// Each event will only appear once in the output list.
func LineariseStateResponse(roomVersion RoomVersion, r StateResponse) []PDU {
	authEvents := r.GetAuthEvents().UntrustedEvents(roomVersion)
	stateEvents := r.GetStateEvents().UntrustedEvents(roomVersion)
	eventsByID := make(map[string]PDU, len(authEvents)+len(stateEvents))
	for i, event := range authEvents {
		eventsByID[event.EventID()] = authEvents[i]
	}
	for i, event := range stateEvents {
		eventsByID[event.EventID()] = stateEvents[i]
	}
	allEvents := make([]PDU, 0, len(eventsByID))
	for _, event := range eventsByID {
		allEvents = append(allEvents, event)
	}
	return ReverseTopologicalOrdering(allEvents, TopologicalOrderByAuthEvents)
}
