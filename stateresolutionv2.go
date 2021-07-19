// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gomatrixserverlib

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"sort"
)

// TopologicalOrder represents how to sort a list of events, used primarily in ReverseTopologicalOrdering
type TopologicalOrder int

// Sort events by prev_events or auth_events
const (
	TopologicalOrderByPrevEvents TopologicalOrder = iota + 1
	TopologicalOrderByAuthEvents
)

type stateResolverV2 struct {
	authEventMap              map[string]*Event            // Map of all provided auth events
	powerLevelMainline        []*Event                     // Power level events in mainline ordering
	powerLevelMainlinePos     map[string]int               // Power level event positions in mainline
	resolvedCreate            *Event                       // Resolved create event
	resolvedPowerLevels       *Event                       // Resolved power level event
	resolvedJoinRules         *Event                       // Resolved join rules event
	resolvedThirdPartyInvites map[string]*Event            // Resolved third party invite events
	resolvedMembers           map[string]*Event            // Resolved member events
	resolvedOthers            map[string]map[string]*Event // Resolved other events
	result                    []*Event                     // Final list of resolved events
}

// Create implements AuthEventProvider
func (r *stateResolverV2) Create() (*Event, error) {
	return r.resolvedCreate, nil
}

// PowerLevels implements AuthEventProvider
func (r *stateResolverV2) PowerLevels() (*Event, error) {
	return r.resolvedPowerLevels, nil
}

// JoinRules implements AuthEventProvider
func (r *stateResolverV2) JoinRules() (*Event, error) {
	return r.resolvedJoinRules, nil
}

// ThirdPartyInvite implements AuthEventProvider
func (r *stateResolverV2) ThirdPartyInvite(key string) (*Event, error) {
	return r.resolvedThirdPartyInvites[key], nil
}

// Member implements AuthEventProvider
func (r *stateResolverV2) Member(key string) (*Event, error) {
	return r.resolvedMembers[key], nil
}

// ResolveStateConflicts takes a list of state events with conflicting state
// keys and works out which event should be used for each state event. This
// function returns the resolved state, including unconflicted state events.
func ResolveStateConflictsV2(
	conflicted, unconflicted []*Event,
	authEvents, authDifference []*Event,
) []*Event {
	// Prepare the state resolver.
	conflictedControlEvents := make([]*Event, 0, len(conflicted))
	conflictedOthers := make([]*Event, 0, len(conflicted))
	r := stateResolverV2{
		authEventMap:              eventMapFromEvents(authEvents),
		powerLevelMainlinePos:     make(map[string]int),
		resolvedThirdPartyInvites: make(map[string]*Event, len(conflicted)),
		resolvedMembers:           make(map[string]*Event, len(conflicted)),
		resolvedOthers:            make(map[string]map[string]*Event, len(conflicted)),
		result:                    make([]*Event, 0, len(conflicted)+len(unconflicted)),
	}

	// This is a map to help us determine if an event already belongs to the
	// unconflicted set. If it does then we shouldn't add it back into the
	// conflicted set later.
	isUnconflicted := make(map[string]struct{}, len(unconflicted))
	for _, u := range unconflicted {
		isUnconflicted[u.EventID()] = struct{}{}
	}

	// Separate out control events from the rest of the events. This is necessary
	// because we perform topological ordering of the control events separately,
	// and then the mainline ordering of all other events depends on that
	// ordering.
	for _, p := range append(conflicted, authDifference...) {
		if _, unconflicted := isUnconflicted[p.EventID()]; !unconflicted {
			if isControlEvent(p) {
				conflictedControlEvents = append(conflictedControlEvents, p)
			} else {
				conflictedOthers = append(conflictedOthers, p)
			}
		}
	}

	// Start with the unconflicted events by ordering them topologically and then
	// authing them. The successfully authed events will form the initial partial
	// state. We will then keep the successfully authed unconflicted events so that
	// they can be reapplied later.
	unconflicted = r.reverseTopologicalOrdering(unconflicted, TopologicalOrderByAuthEvents)
	r.applyEvents(unconflicted)

	// Then order the conflicted power level events topologically and then also
	// auth those too. The successfully authed events will be layered on top of
	// the partial state.
	conflictedControlEvents = r.reverseTopologicalOrdering(conflictedControlEvents, TopologicalOrderByAuthEvents)
	r.authAndApplyEvents(conflictedControlEvents)

	// Then generate the mainline of power level events, order the remaining state
	// events based on the mainline ordering and auth those too. The successfully
	// authed events are also layered on top of the partial state.
	r.powerLevelMainline = r.createPowerLevelMainline()
	for pos, event := range r.powerLevelMainline {
		r.powerLevelMainlinePos[event.EventID()] = pos
	}
	conflictedOthers = r.mainlineOrdering(conflictedOthers)
	r.authAndApplyEvents(conflictedOthers)

	// Finally we will reapply the original set of unconflicted events onto the
	// partial state, just in case any of these were overwritten by pulling in
	// auth events in the previous two steps, and that gives us our final resolved
	// state.
	r.applyEvents(unconflicted)

	// Now that we have our final state, populate the result array with the
	// resolved state and return it.
	if r.resolvedCreate != nil {
		r.result = append(r.result, r.resolvedCreate)
	}
	if r.resolvedJoinRules != nil {
		r.result = append(r.result, r.resolvedJoinRules)
	}
	if r.resolvedPowerLevels != nil {
		r.result = append(r.result, r.resolvedPowerLevels)
	}
	for _, member := range r.resolvedMembers {
		r.result = append(r.result, member)
	}
	for _, invite := range r.resolvedThirdPartyInvites {
		r.result = append(r.result, invite)
	}
	for _, other := range r.resolvedOthers {
		for _, event := range other {
			r.result = append(r.result, event)
		}
	}

	return r.result
}

// ReverseTopologicalOrdering takes a set of input events and sorts them
// using Kahn's algorithm in order to topologically order them. The
// result array of events will be sorted so that "earlier" events appear
// first.
func ReverseTopologicalOrdering(input []*Event, order TopologicalOrder) []*Event {
	r := stateResolverV2{}
	return r.reverseTopologicalOrdering(input, order)
}

// HeaderedReverseTopologicalOrdering takes a set of input events and sorts
// them using Kahn's algorithm in order to topologically order them. The
// result array of events will be sorted so that "earlier" events appear
// first.
func HeaderedReverseTopologicalOrdering(events []*HeaderedEvent, order TopologicalOrder) []*HeaderedEvent {
	r := stateResolverV2{}
	input := make([]*Event, len(events))
	for i := range events {
		unwrapped := events[i].Unwrap()
		input[i] = unwrapped
	}
	result := make([]*HeaderedEvent, len(input))
	for i, e := range r.reverseTopologicalOrdering(input, order) {
		result[i] = e.Headered(e.roomVersion)
	}
	return result
}

// isControlEvent returns true if the event meets the criteria for being classed
// as a "control" event for reverse topological sorting. If not then the event
// will be mainline sorted.
func isControlEvent(e *Event) bool {
	switch e.Type() {
	case MRoomPowerLevels:
		// Power level events are control events.
		return true
	case MRoomJoinRules:
		// Join rule events are control events.
		return true
	case MRoomMember:
		// Membership events must not have an empty state key.
		if e.StateKey() == nil || *e.StateKey() == "" {
			break
		}
		// Membership events are only control events if the sender does not match
		// the state key, i.e. because the event is caused by an admin or moderator.
		if e.Sender() == *e.StateKey() {
			break
		}
		// Membership events are only control events if the "membership" key in the
		// content is "leave" or "ban" so we need to extract the content.
		var content map[string]interface{}
		if err := json.Unmarshal(e.Content(), &content); err != nil {
			break
		}
		// If the "membership" key is set and is set to either "leave" or "ban" then
		// the event is a control event.
		if m, ok := content["membership"]; ok && (m == "leave" || m == "ban") {
			return true
		}
	default:
	}
	// If we have reached this point then we have failed all checks and we don't
	// count the event as a control event.
	return false
}

// createPowerLevelMainline generates the mainline of power level events,
// starting at the currently resolved power level event from the topological
// ordering and working our way back to the room creation. Note that we populate
// the result here in reverse, so that the room creation is at the beginning of
// the list, rather than the end.
func (r *stateResolverV2) createPowerLevelMainline() []*Event {
	var mainline []*Event

	// Define our iterator function.
	var iter func(event *Event)
	iter = func(event *Event) {
		// Append this event to the beginning of the mainline.
		mainline = append([]*Event{event}, mainline...)
		// Work through all of the auth event IDs that this event refers to.
		for _, authEventID := range event.AuthEventIDs() {
			// Check that we actually have the auth event in our map - we need this so
			// that we can look up the event type.
			if authEvent, ok := r.authEventMap[authEventID]; ok {
				// Is the event a power event?
				if authEvent.Type() == MRoomPowerLevels {
					// We found a power level event in the event's auth events - start
					// the iterator from this new event.
					iter(authEvent)
				}
			}
		}
	}

	// Begin the sequence from the currently resolved power level event from the
	// topological ordering.
	if r.resolvedPowerLevels != nil {
		iter(r.resolvedPowerLevels)
	}

	return mainline
}

// getFirstPowerLevelMainlineEvent iteratively steps through the auth events of
// the given event until it finds an event that exists in the mainline. Note
// that for this function to work, you must have first called
// createPowerLevelMainline. This function returns three things: the event that
// was found in the mainline, the position in the mainline of the found event
// and the number of steps it took to reach the mainline.
func (r *stateResolverV2) getFirstPowerLevelMainlineEvent(event *Event) (
	mainlineEvent *Event, mainlinePosition int, steps int,
) {
	// Define a function that the iterator can use to determine whether the event
	// is in the mainline set or not.
	isInMainline := func(searchEvent *Event) (bool, int) {
		// If we already know the mainline position then return it.
		if pos, ok := r.powerLevelMainlinePos[searchEvent.EventID()]; ok {
			return true, pos
		}
		// Otherwise, the event is not in the mainline.
		return false, 0
	}

	// Define our iterator function.
	var iter func(event *Event)
	iter = func(event *Event) {
		// In much the same way as we do in createPowerLevelMainline, we loop
		// through the event's auth events, checking that it exists in our supplied
		// auth event map and finding power level events.
		for _, authEventID := range event.AuthEventIDs() {
			// Check that we actually have the auth event in our map - we need this so
			// that we can look up the event type.
			if authEvent, ok := r.authEventMap[authEventID]; ok {
				// Is the event a power level event?
				if authEvent.Type() == MRoomPowerLevels {
					// Is the event in the mainline?
					if isIn, pos := isInMainline(authEvent); isIn {
						// It is - take a note of the event and position and stop the
						// iterator from running any further.
						mainlineEvent = authEvent
						mainlinePosition = pos
						// Cache the result so that a future request for this position will
						// be faster.
						r.powerLevelMainlinePos[mainlineEvent.EventID()] = mainlinePosition
						return
					}
					// It isn't - increase the step count and then run the iterator again
					// from the found auth event.
					steps++
					iter(authEvent)
				}
			}
		}
	}

	// Start the iterator with the supplied event.
	iter(event)

	return
}

// authAndApplyEvents iterates through the supplied list of events and auths
// them against the current partial state. If they pass the auth checks then we
// also apply them on top of the partial state. If they fail auth checks then
// the event is ignored and dropped. Returns two lists - the first contains the
// accepted (authed) events and the second contains the rejected events.
func (r *stateResolverV2) authAndApplyEvents(events []*Event) {
	allower := newAllowerContext(r)
	for _, event := range events {
		// Check if the event is allowed based on the current partial state. If the
		// event isn't allowed then simply ignore it and process the next one.
		if err := allower.allowed(event); err != nil {
			continue
		}
		// Apply the newly authed event to the partial state. We need to do this
		// here so that the next loop will have partial state to auth against.
		r.applyEvents([]*Event{event})
	}
}

// applyEvents applies the events on top of the partial state.
func (r *stateResolverV2) applyEvents(events []*Event) {
	for _, event := range events {
		st, sk := event.Type(), event.StateKey()
		switch st {
		case MRoomCreate:
			// Room creation events are only valid with an empty state key.
			if sk != nil && *sk == "" {
				r.resolvedCreate = event
			}
		case MRoomPowerLevels:
			// Power level events are only valid with an empty state key.
			if sk != nil && *sk == "" {
				r.resolvedPowerLevels = event
			}
		case MRoomJoinRules:
			// Join rule events are only valid with an empty state key.
			if sk != nil && *sk == "" {
				r.resolvedJoinRules = event
			}
		case MRoomThirdPartyInvite:
			// Third party invite events are only valid with a non-empty state key.
			if sk != nil && *sk != "" {
				r.resolvedThirdPartyInvites[*sk] = event
			}
		case MRoomMember:
			// Membership events are only valid with a non-empty state key.
			if sk != nil && *sk != "" {
				r.resolvedMembers[*sk] = event
			}
		default:
			// Doesn't match one of the core state types so store it by type and state
			// key.
			if _, ok := r.resolvedOthers[st]; !ok {
				r.resolvedOthers[st] = make(map[string]*Event)
			}
			if sk != nil {
				r.resolvedOthers[st][*sk] = event
			}
		}
	}
}

// eventMapFromEvents takes a list of events and returns a map, where the key
// for each value is the event ID.
func eventMapFromEvents(events []*Event) map[string]*Event {
	r := make(map[string]*Event, len(events))
	for _, e := range events {
		if _, ok := r[e.EventID()]; !ok {
			r[e.EventID()] = e
		}
	}
	return r
}

// wrapPowerLevelEventsForSort takes the input power level events and wraps them
// in stateResV2ConflictedPowerLevel structs so that we have the necessary
// information pre-calculated ahead of sorting.
func (r *stateResolverV2) wrapPowerLevelEventsForSort(events []*Event) []*stateResV2ConflictedPowerLevel {
	block := make([]*stateResV2ConflictedPowerLevel, len(events))
	for i, event := range events {
		block[i] = &stateResV2ConflictedPowerLevel{
			powerLevel:     r.getPowerLevelFromAuthEvents(event),
			originServerTS: int64(event.OriginServerTS()),
			eventID:        event.EventID(),
			event:          event,
		}
	}
	return block
}

// wrapOtherEventsForSort takes the input non-power level events and wraps them
// in stateResV2ConflictedPowerLevel structs so that we have the necessary
// information pre-calculated ahead of sorting.
func (r *stateResolverV2) wrapOtherEventsForSort(events []*Event) []*stateResV2ConflictedOther {
	block := make([]*stateResV2ConflictedOther, len(events))
	for i, event := range events {
		_, pos, _ := r.getFirstPowerLevelMainlineEvent(event)
		block[i] = &stateResV2ConflictedOther{
			mainlinePosition: pos,
			originServerTS:   int64(event.OriginServerTS()),
			eventID:          event.EventID(),
			event:            event,
		}
	}
	return block
}

// reverseTopologicalOrdering takes a set of input events, prepares them using
// wrapPowerLevelEventsForSort and then starts the Kahn's algorithm in order to
// topologically sort them. The result that is returned is correctly ordered.
func (r *stateResolverV2) reverseTopologicalOrdering(events []*Event, order TopologicalOrder) (result []*Event) {
	switch order {
	case TopologicalOrderByAuthEvents:
		block := r.wrapPowerLevelEventsForSort(events)
		for _, s := range kahnsAlgorithmUsingAuthEvents(block) {
			result = append(result, s.event)
		}
	case TopologicalOrderByPrevEvents:
		block := r.wrapOtherEventsForSort(events)
		for _, s := range kahnsAlgorithmUsingPrevEvents(block) {
			result = append(result, s.event)
		}
	default:
		panic(fmt.Sprintf("gomatrixserverlib.reverseTopologicalOrdering unknown Ordering %d", order))
	}
	return
}

// mainlineOrdering takes a set of input events, prepares them using
// wrapOtherEventsForSort and then sorts them based on mainline ordering. The
// result that is returned is correctly ordered.
func (r *stateResolverV2) mainlineOrdering(events []*Event) (result []*Event) {
	block := r.wrapOtherEventsForSort(events)
	sort.Sort(stateResV2ConflictedOtherHeap(block))
	for _, s := range block {
		result = append(result, s.event)
	}
	return
}

// getPowerLevelFromAuthEvents tries to determine the effective power level of
// the sender at the time that of the given event, based on the auth events.
// This is used in the Kahn's algorithm tiebreak.
func (r *stateResolverV2) getPowerLevelFromAuthEvents(event *Event) int64 {
	for _, authID := range event.AuthEventIDs() {
		// First check and see if we have the auth event in the auth map, if not
		// then we cannot deduce the real effective power level.
		authEvent, ok := r.authEventMap[authID]
		if !ok {
			return 0
		}

		// Ignore the auth event if it isn't a power level event.
		if authEvent.Type() != MRoomPowerLevels || *authEvent.StateKey() != "" {
			continue
		}

		// Try and parse the content of the event.
		content, err := NewPowerLevelContentFromEvent(authEvent)
		if err != nil {
			return 0
		}

		// Look up what the power level should be for this user. If the user is
		// not in the list, the default user power level will be returned instead.
		return content.UserLevel(event.Sender())
	}

	return 0
}

// kahnsAlgorithmByAuthEvents is, predictably, an implementation of Kahn's
// algorithm that uses auth events to topologically sort the input list of
// events. This works through each event, counting how many incoming auth event
// dependencies it has, and then adding them into the graph as the dependencies
// are resolved.
func kahnsAlgorithmUsingAuthEvents(events []*stateResV2ConflictedPowerLevel) []*stateResV2ConflictedPowerLevel {
	eventMap := make(map[string]*stateResV2ConflictedPowerLevel, len(events))
	graph := make([]*stateResV2ConflictedPowerLevel, 0, len(events))
	inDegree := make(map[string]int)

	for _, event := range events {
		// For each event that we have been given, add it to the event map so that
		// we can easily refer back to it by event ID later.
		eventMap[event.eventID] = event

		// If we haven't encountered this event ID yet, also start with a zero count
		// of incoming auth event dependencies.
		if _, ok := inDegree[event.eventID]; !ok {
			inDegree[event.eventID] = 0
		}

		// Find each of the auth events that this event depends on and make a note
		// for each auth event that there's an additional incoming dependency.
		for _, auth := range event.event.AuthEventIDs() {
			if _, ok := inDegree[auth]; !ok {
				// We don't know about this event yet - set an initial value.
				inDegree[auth] = 1
			} else {
				// We've already encountered this event so increment instead.
				inDegree[auth]++
			}
		}
	}

	// Now we need to work out which events don't have any incoming auth event
	// dependencies. These will be placed into the graph first. Remove the event
	// from the event map as this prevents us from processing it a second time.
	var noIncoming stateResV2ConflictedPowerLevelHeap
	heap.Init(&noIncoming)
	for eventID, count := range inDegree {
		if count == 0 {
			heap.Push(&noIncoming, eventMap[eventID])
			delete(eventMap, eventID)
		}
	}

	var event *stateResV2ConflictedPowerLevel
	for noIncoming.Len() > 0 {
		// Pop the first event ID off the list of events which have no incoming
		// auth event dependencies.
		event = heap.Pop(&noIncoming).(*stateResV2ConflictedPowerLevel)

		// Since there are no incoming dependencies to resolve, we can now add this
		// event into the graph.
		graph = append([]*stateResV2ConflictedPowerLevel{event}, graph...)

		// Now we should look at the outgoing auth dependencies that this event has.
		// Since this event is now in the graph, the event's outgoing auth
		// dependencies are no longer valid - those map to incoming dependencies on
		// the auth events, so let's update those.
		for _, auth := range event.event.AuthEventIDs() {
			inDegree[auth]--

			// If we see, by updating the incoming dependencies, that the auth event
			// no longer has any incoming dependencies, then it should also be added
			// into the graph on the next pass. In turn, this will also mean that we
			// process the outgoing dependencies of this auth event.
			if inDegree[auth] == 0 {
				if _, ok := eventMap[auth]; ok {
					heap.Push(&noIncoming, eventMap[auth])
					delete(eventMap, auth)
				}
			}
		}
	}

	// If we have stray events left over then add them into the result.
	if len(eventMap) > 0 {
		var remaining stateResV2ConflictedPowerLevelHeap
		for _, event := range eventMap {
			heap.Push(&remaining, event)
		}
		sort.Sort(sort.Reverse(remaining))
		graph = append(remaining, graph...)
	}

	// The graph is complete at this point!
	return graph
}

// kahnsAlgorithmUsingPrevEvents is, predictably, an implementation of Kahn's
// algorithm that uses prev events to topologically sort the input list of
// events. This works through each event, counting how many incoming prev event
// dependencies it has, and then adding them into the graph as the dependencies
// are resolved.
func kahnsAlgorithmUsingPrevEvents(events []*stateResV2ConflictedOther) []*stateResV2ConflictedOther {
	eventMap := make(map[string]*stateResV2ConflictedOther, len(events))
	graph := make([]*stateResV2ConflictedOther, 0, len(events))
	inDegree := make(map[string]int)

	for _, event := range events {
		// For each event that we have been given, add it to the event map so that
		// we can easily refer back to it by event ID later.
		eventMap[event.eventID] = event

		// If we haven't encountered this event ID yet, also start with a zero count
		// of incoming prev event dependencies.
		if _, ok := inDegree[event.eventID]; !ok {
			inDegree[event.eventID] = 0
		}

		// Find each of the prev events that this event depends on and make a note
		// for each prev event that there's an additional incoming dependency.
		for _, prev := range event.event.PrevEventIDs() {
			if _, ok := inDegree[prev]; !ok {
				// We don't know about this event yet - set an initial value.
				inDegree[prev] = 1
			} else {
				// We've already encountered this event so increment instead.
				inDegree[prev]++
			}
		}
	}

	// Now we need to work out which events don't have any incoming prev event
	// dependencies. These will be placed into the graph first. Remove the event
	// from the event map as this prevents us from processing it a second time.
	var noIncoming stateResV2ConflictedOtherHeap
	heap.Init(&noIncoming)
	for eventID, count := range inDegree {
		if count == 0 {
			heap.Push(&noIncoming, eventMap[eventID])
			delete(eventMap, eventID)
		}
	}

	var event *stateResV2ConflictedOther
	for noIncoming.Len() > 0 {
		// Pop the first event ID off the list of events which have no incoming
		// prev event dependencies.
		event = heap.Pop(&noIncoming).(*stateResV2ConflictedOther)

		// Since there are no incoming dependencies to resolve, we can now add this
		// event into the graph.
		graph = append([]*stateResV2ConflictedOther{event}, graph...)

		// Now we should look at the outgoing prev dependencies that this event has.
		// Since this event is now in the graph, the event's outgoing prev
		// dependencies are no longer valid - those map to incoming dependencies on
		// the prev events, so let's update those.
		for _, prev := range event.event.PrevEventIDs() {
			inDegree[prev]--

			// If we see, by updating the incoming dependencies, that the prev event
			// no longer has any incoming dependencies, then it should also be added
			// into the graph on the next pass. In turn, this will also mean that we
			// process the outgoing dependencies of this prev event.
			if inDegree[prev] == 0 {
				if _, ok := eventMap[prev]; ok {
					heap.Push(&noIncoming, eventMap[prev])
					delete(eventMap, prev)
				}
			}
		}
	}

	// If we have stray events left over then add them into the result.
	if len(eventMap) > 0 {
		var remaining stateResV2ConflictedOtherHeap
		for _, event := range eventMap {
			heap.Push(&remaining, event)
		}
		sort.Sort(sort.Reverse(remaining))
		graph = append(remaining, graph...)
	}
	return graph
}
