/* Copyright 2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

import (
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type stateResolverV2 struct {
	authEventMap              map[string]Event
	conflictedMap             map[string]Event
	unconflictedMap           map[string]Event
	powerLevelMainline        []Event
	conflictedPowerLevels     []Event
	conflictedOthers          []Event
	resolvedCreate            *Event
	resolvedPowerLevels       *Event
	resolvedJoinRules         *Event
	resolvedThirdPartyInvites map[string]*Event
	resolvedMembers           map[string]*Event
	result                    []Event
}

func (r *stateResolverV2) Create() (*Event, error) {
	if r.resolvedCreate == nil {
		return nil, errors.New("not resolved create event yet")
	}
	return r.resolvedCreate, nil
}

func (r *stateResolverV2) PowerLevels() (*Event, error) {
	if r.resolvedCreate == nil {
		return nil, errors.New("not resolved power levels event yet")
	}
	return r.resolvedPowerLevels, nil
}

func (r *stateResolverV2) JoinRules() (*Event, error) {
	if r.resolvedCreate == nil {
		return nil, errors.New("not resolved join rules event yet")
	}
	return r.resolvedJoinRules, nil
}

func (r *stateResolverV2) ThirdPartyInvite(key string) (*Event, error) {
	value := r.resolvedThirdPartyInvites[key]
	return value, nil
}

func (r *stateResolverV2) Member(key string) (*Event, error) {
	value := r.resolvedMembers[key]
	return value, nil
}

// ResolveStateConflicts takes a list of state events with conflicting state keys
// and works out which event should be used for each state event.
func ResolveStateConflictsV2(conflicted, unconflicted []Event, authEvents []Event) []Event {
	r := stateResolverV2{
		authEventMap:              eventMapFromEvents(authEvents),
		conflictedMap:             eventMapFromEvents(conflicted),
		unconflictedMap:           eventMapFromEvents(unconflicted),
		resolvedThirdPartyInvites: make(map[string]*Event),
		resolvedMembers:           make(map[string]*Event),
	}

	// Start with the unconflicted events and auth them.
	unconflicted = r.reverseTopologicalOrdering(unconflicted)
	if err := r.resolveUsingPartialState(unconflicted); err != nil {
		return r.result
	}

	// Take all power events (and any events in their auth chains) that appear in
	// the full conflicted set and order them by the reverse topological power
	// ordering.
	for _, p := range r.conflictedMap {
		if p.Type() == MRoomPowerLevels {
			r.conflictedPowerLevels = append(r.conflictedPowerLevels, p)
		}
	}
	r.conflictedPowerLevels = r.reverseTopologicalOrdering(r.conflictedPowerLevels)

	// Resolve the conflicted power level events.
	if err := r.resolveUsingPartialState(r.conflictedPowerLevels); err != nil {
		fmt.Println("error resolving partial state for conflicted power events:", err)
	}

	// then generate the mainline
	// then order the remaining normal state events events

	// Finally reapply the unconflicted state.
	if err := r.resolveUsingPartialState(unconflicted); err != nil {
		return r.result
	}

	// populate the final result list
	r.result = append(r.result, *r.resolvedCreate)
	r.result = append(r.result, *r.resolvedJoinRules)
	r.result = append(r.result, *r.resolvedPowerLevels)
	for _, member := range r.resolvedMembers {
		r.result = append(r.result, *member)
	}
	for _, invite := range r.resolvedThirdPartyInvites {
		r.result = append(r.result, *invite)
	}

	return r.result
}

func (r *stateResolverV2) resolveUsingPartialState(events []Event) error {
	for _, e := range events {
		event := e // so that the event remains addressable
		if err := Allowed(event, r); err != nil {
			fmt.Println(event.EventID(), "not allowed:", err)
			return err
		}
		switch event.Type() {
		case MRoomCreate:
			if event.StateKey() == nil || *event.StateKey() == "" {
				r.resolvedCreate = &event
			}
		case MRoomPowerLevels:
			if event.StateKey() == nil || *event.StateKey() == "" {
				r.resolvedPowerLevels = &event
			}
		case MRoomJoinRules:
			if event.StateKey() == nil || *event.StateKey() == "" {
				r.resolvedJoinRules = &event
			}
		case MRoomThirdPartyInvite:
			if event.StateKey() != nil && *event.StateKey() != "" {
				r.resolvedThirdPartyInvites[*event.StateKey()] = &event
			}
		case MRoomMember:
			if event.StateKey() != nil && *event.StateKey() != "" {
				r.resolvedMembers[*event.StateKey()] = &event
			}
		}
	}
	return nil
}

func eventMapFromEvents(events []Event) map[string]Event {
	r := make(map[string]Event)
	for _, e := range events {
		r[e.EventID()] = e
	}
	return r
}

func separate(events []Event) (conflicted, unconflicted []Event) {
	// The stack maps event type -> event state key -> list of state events
	stack := make(map[string]map[string][]Event)
	// Prepare the map
	for _, event := range events {
		// If we haven't encountered an entry of this type yet, create an entry§
		if _, ok := stack[event.Type()]; !ok {
			stack[event.Type()] = make(map[string][]Event)
		}
		// Add the event to the map
		stack[event.Type()][*event.StateKey()] = append(
			stack[event.Type()][*event.StateKey()], event,
		)
	}
	// Now we need to work out which of these events are conflicted. An event is
	// conflicted if there is more than one entry for the (type, statekey) tuple.
	// If we encounter these events, add them to their relevant conflicted list.
	for _, eventsOfType := range stack {
		for _, eventsOfStateKey := range eventsOfType {
			if len(eventsOfStateKey) > 1 {
				// We have more than one event for the (type, statekey) tuple, therefore
				// these are conflicted.
				for _, event := range eventsOfStateKey {
					conflicted = append(conflicted, event)
				}
			} else if len(eventsOfStateKey) == 1 {
				unconflicted = append(unconflicted, eventsOfStateKey[0])
			}
		}
	}
	return
}

func (r *stateResolverV2) prepareConflictedEvents(events []Event) []conflictedEventV2 {
	block := make([]conflictedEventV2, len(events))
	for i, event := range events {
		block[i] = conflictedEventV2{
			powerLevel:     r.getPowerLevelFromAuthEvents(event),
			originServerTS: int64(event.OriginServerTS()),
			eventID:        event.EventID(),
			event:          event,
		}
	}
	return block
}

func (r *stateResolverV2) reverseTopologicalOrdering(events []Event) (result []Event) {
	block := r.prepareConflictedEvents(events)
	sorted := kahnsAlgorithmUsingAuthEvents(block)
	for _, s := range sorted {
		result = append(result, s.event)
	}
	return
}

// getPowerLevelFromAuthEvents tries to determine the effective power level of
// the sender at the time that of the given event, based on the auth events.
// This is used in the Kahn's algorithm tiebreak.
func (r *stateResolverV2) getPowerLevelFromAuthEvents(event Event) (pl int) {
	for _, authID := range event.AuthEventIDs() {
		// First check and see if we have the auth event in the auth map, if not
		// then we cannot deduce the real effective power level
		authEvent, ok := r.authEventMap[authID]
		if !ok {
			return 0
		}

		// Ignore the auth event if it isn't a power level event
		if authEvent.Type() != MRoomPowerLevels || *authEvent.StateKey() != "" {
			continue
		}

		// Try and parse the content of the event
		var content map[string]interface{}
		if err := json.Unmarshal(authEvent.Content(), &content); err != nil {
			return 0
		}

		// First of all try to see if there's a default user power level. We'll use
		// that for now as a fallback
		if defaultPl, ok := content["users_default"].(int); ok {
			pl = defaultPl
		}

		// See if there is a "users" key in the event content
		if users, ok := content["users"].(map[string]string); ok {
			// Is there a key that matches the sender?
			if _, ok := users[event.Sender()]; ok {
				// A power level for this specific user is known, let's use that instead
				if p, err := strconv.Atoi(users[event.Sender()]); err == nil {
					pl = p
				}
			}
		}
	}

	return
}

// A conflictedEventV2 is used to sort the events in a block by ascending depth
// and descending sha1 of event ID. It is a bit of an optimisation to use this -
// by working out the effective power level etc ahead of time, we use less CPU
// cycles during the sort.
type conflictedEventV2 struct {
	powerLevel     int
	originServerTS int64
	eventID        string
	event          Event
}

// A conflictedEventV2Heap is used to sort the events using sort.Sort. We do
// this before processing the initial set of events with no incoming auth
// dependencies as it should help us get a deterministic result.
type conflictedEventV2Heap []conflictedEventV2

func (s conflictedEventV2Heap) Len() int {
	return len(s)
}

func (s conflictedEventV2Heap) Less(i, j int) bool {
	if s[i].powerLevel > s[j].powerLevel {
		return true
	}
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) < 0
}

func (s conflictedEventV2Heap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (pq *conflictedEventV2Heap) Push(x interface{}) {
	*pq = append(*pq, x.(conflictedEventV2))
}

func (pq *conflictedEventV2Heap) Pop() interface{} {
	old := *pq
	x := old[0]
	*pq = old[1:]
	return x
}

// kahnsAlgorithmByAuthEvents is, predictably, an implementation of Kahn's
// algorithm that uses auth events to topologically sort the input list of
// events. This works through each event, counting how many incoming auth event
// dependencies it has, and then adding them into the graph as the dependencies
// are resolved.
func kahnsAlgorithmUsingAuthEvents(events []conflictedEventV2) (graph []conflictedEventV2) {
	eventMap := make(map[string]conflictedEventV2)
	inDegree := make(map[string]int)

	for _, event := range events {
		// For each even that we have been given, add it to the event map so that we
		// can easily refer back to it by event ID later.
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
	var noIncoming conflictedEventV2Heap
	heap.Init(&noIncoming)
	for eventID, count := range inDegree {
		if count == 0 {
			heap.Push(&noIncoming, eventMap[eventID])
			delete(eventMap, eventID)
		}
	}

	var event conflictedEventV2
	for noIncoming.Len() > 0 {
		// Pop the first event ID off the list of events which have no incoming
		// auth event dependencies.
		event = heap.Pop(&noIncoming).(conflictedEventV2)

		// Since there are no incoming dependencies to resolve, we can now add this
		// event into the graph.
		graph = append([]conflictedEventV2{event}, graph...)

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

	// The graph is complete at this point!
	return graph
}
