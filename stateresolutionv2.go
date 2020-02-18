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
	"bytes"
	"fmt"
	"sort"
)

// ResolveStateConflicts takes a list of state events with conflicting state keys
// and works out which event should be used for each state event.
func ResolveStateConflictsV2(conflicted []Event, authEvents []Event) []Event {
	var r stateResolverV2
	r.resolvedThirdPartyInvites = map[string]*Event{}
	r.resolvedMembers = map[string]*Event{}
	// Group the conflicted events by type and state key.
	r.addConflicted(conflicted)
	// Add the unconflicted auth events needed for auth checks.
	for i := range authEvents {
		r.addAuthEvent(&authEvents[i])
	}
	// Resolve the conflicted auth events.
	r.resolveAndAddAuthBlocks([][]Event{r.creates})
	r.resolveAndAddAuthBlocks([][]Event{r.powerLevels})
	r.resolveAndAddAuthBlocks([][]Event{r.joinRules})
	r.resolveAndAddAuthBlocks(r.thirdPartyInvites)
	r.resolveAndAddAuthBlocks(r.members)
	// Resolve any other conflicted state events.
	for _, block := range r.others {
		if event := r.resolveNormalBlock(block); event != nil {
			r.result = append(r.result, *event)
		}
	}
	return r.result
}

// A stateResolver tracks the internal state of the state resolution algorithm
// It has 3 sections:
//
//  * Lists of lists of events to resolve grouped by event type and state key.
//  * The resolved auth events grouped by type and state key.
//  * A List of resolved events.
//
// It implements the AuthEvents interface and can be used for running auth checks.
type stateResolverV2 struct {
	// Lists of lists of events to resolve grouped by event type and state key:
	//   * creates, powerLevels, joinRules have empty state keys.
	//   * members and thirdPartyInvites are grouped by state key.
	//   * the others are grouped by the pair of type and state key.
	creates           []Event
	powerLevels       []Event
	joinRules         []Event
	thirdPartyInvites [][]Event
	members           [][]Event
	others            [][]Event
	// The resolved auth events grouped by type and state key.
	resolvedCreate            *Event
	resolvedPowerLevels       *Event
	resolvedJoinRules         *Event
	resolvedThirdPartyInvites map[string]*Event
	resolvedMembers           map[string]*Event
	// The list of resolved events.
	// This will contain one entry for each conflicted event type and state key.
	result []Event
}

func (r *stateResolverV2) Create() (*Event, error) {
	return r.resolvedCreate, nil
}

func (r *stateResolverV2) PowerLevels() (*Event, error) {
	return r.resolvedPowerLevels, nil
}

func (r *stateResolverV2) JoinRules() (*Event, error) {
	return r.resolvedJoinRules, nil
}

func (r *stateResolverV2) ThirdPartyInvite(key string) (*Event, error) {
	return r.resolvedThirdPartyInvites[key], nil
}

func (r *stateResolverV2) Member(key string) (*Event, error) {
	return r.resolvedMembers[key], nil
}

func (r *stateResolverV2) addConflicted(events []Event) { // nolint: gocyclo
	type conflictKey struct {
		eventType string
		stateKey  string
	}
	offsets := map[conflictKey]int{}
	// Split up the conflicted events into blocks with the same type and state key.
	// Separate the auth events into specifically named lists because they have
	// special rules for state resolution.
	for _, event := range events {
		key := conflictKey{event.Type(), *event.StateKey()}
		// Work out which block to add the event to.
		// By default we add the event to a block in the others list.
		blockList := &r.others
		switch key.eventType {
		case MRoomCreate:
			if key.stateKey == "" {
				r.creates = append(r.creates, event)
				continue
			}
		case MRoomPowerLevels:
			if key.stateKey == "" {
				r.powerLevels = append(r.powerLevels, event)
				continue
			}
		case MRoomJoinRules:
			if key.stateKey == "" {
				r.joinRules = append(r.joinRules, event)
				continue
			}
		case MRoomMember:
			blockList = &r.members
		case MRoomThirdPartyInvite:
			blockList = &r.thirdPartyInvites
		}
		// We need to find an entry for the state key in a block list.
		offset, ok := offsets[key]
		if !ok {
			// This is the first time we've seen that state key so we add a
			// new block to the block list.
			offset = len(*blockList)
			*blockList = append(*blockList, nil)
			offsets[key] = offset
		}
		// Get the address of the block in the block list.
		block := &(*blockList)[offset]
		// Add the event to the block.
		*block = append(*block, event)
	}
}

// Add an event to the resolved auth events.
func (r *stateResolverV2) addAuthEvent(event *Event) {
	switch event.Type() {
	case MRoomCreate:
		if event.StateKeyEquals("") {
			r.resolvedCreate = event
		}
	case MRoomPowerLevels:
		if event.StateKeyEquals("") {
			r.resolvedPowerLevels = event
		}
	case MRoomJoinRules:
		if event.StateKeyEquals("") {
			r.resolvedJoinRules = event
		}
	case MRoomMember:
		r.resolvedMembers[*event.StateKey()] = event
	case MRoomThirdPartyInvite:
		r.resolvedThirdPartyInvites[*event.StateKey()] = event
	default:
		panic(fmt.Errorf("Unexpected auth event with type %q", event.Type()))
	}
}

// Remove the auth event with the given type and state key.
func (r *stateResolverV2) removeAuthEvent(eventType, stateKey string) {
	switch eventType {
	case MRoomCreate:
		if stateKey == "" {
			r.resolvedCreate = nil
		}
	case MRoomPowerLevels:
		if stateKey == "" {
			r.resolvedPowerLevels = nil
		}
	case MRoomJoinRules:
		if stateKey == "" {
			r.resolvedJoinRules = nil
		}
	case MRoomMember:
		r.resolvedMembers[stateKey] = nil
	case MRoomThirdPartyInvite:
		r.resolvedThirdPartyInvites[stateKey] = nil
	default:
		panic(fmt.Errorf("Unexpected auth event with type %q", eventType))
	}
}

// resolveAndAddAuthBlocks resolves each block of conflicting auth state events in a list of blocks
// where all the blocks have the same event type.
// Once every block has been resolved the resulting events are added to the events used for auth checks.
// This is called once per auth event type and state key pair.
func (r *stateResolverV2) resolveAndAddAuthBlocks(blocks [][]Event) {
	start := len(r.result)
	for _, block := range blocks {
		if len(block) == 0 {
			continue
		}
		if event := r.resolveAuthBlock(block); event != nil {
			r.result = append(r.result, *event)
		}
	}
	// Only add the events to the auth events once all of the events with that type have been resolved.
	// (SPEC: This is done to avoid the result of state resolution depending on the iteration order)
	for i := start; i < len(r.result); i++ {
		r.addAuthEvent(&r.result[i])
	}
}

// resolveAuthBlock resolves a block of auth events with the same state key to a single event.
func (r *stateResolverV2) resolveAuthBlock(events []Event) *Event {
	// Sort the events by depth and sha1 of event ID
	block := sortConflictedEventsByReverseTopologicalOrdering(events)

	// Pick the "oldest" event, that is the one with the lowest depth, as the first candidate.
	// If none of the newer events pass auth checks against this event then we pick the "oldest" event.
	// (SPEC: This ensures that we always pick a state event for this type and state key.
	//  Note that if all the events fail auth checks we will still pick the "oldest" event.)
	result := block[0].event
	// Temporarily add the candidate event to the auth events.
	r.addAuthEvent(result)
	for i := 1; i < len(block); i++ {
		event := block[i].event
		// Check if the next event passes authentication checks against the current candidate.
		// (SPEC: This ensures that "ban" events cannot be replaced by "join" events through a conflict)
		if Allowed(*event, r) == nil {
			// If the event passes authentication checks pick it as the current candidate.
			// (SPEC: This prefers newer events so that we don't flip a valid state back to a previous version)
			result = event
			r.addAuthEvent(result)
		} else {
			// If the authentication check fails then we stop iterating the list and return the current candidate.
			break
		}
	}
	// Discard the event from the auth events.
	// We'll add it back later when all events of the same type have been resolved.
	// (SPEC: This is done to avoid the result of state resolution depending on the iteration order)
	r.removeAuthEvent(result.Type(), *result.StateKey())
	return result
}

// resolveNormalBlock resolves a block of normal state events with the same state key to a single event.
func (r *stateResolverV2) resolveNormalBlock(events []Event) *Event {
	// Sort the events by depth and sha1 of event ID
	block := sortConflictedEventsByReverseTopologicalOrdering(events)
	// Start at the "newest" event, that is the one with the highest depth, and go
	// backward through the list until we find one that passes authentication checks.
	// (SPEC: This prefers newer events so that we don't flip a valid state back to a previous version)
	for i := len(block) - 1; i > 0; i-- {
		event := block[i].event
		if Allowed(*event, r) == nil {
			return event
		}
	}
	// If all the auth checks for newer events fail then we pick the oldest event.
	// (SPEC: This ensures that we always pick a state event for this type and state key.
	//  Note that if all the events fail auth checks we will still pick the "oldest" event.)
	return block[0].event
}

// sortConflictedEventsByReverseTopologicalOrdering performs reverse topological ordering.
func sortConflictedEventsByReverseTopologicalOrdering(events []Event) []conflictedEventV2 {
	events = kahnsAlgorithmUsingAuthEvents(events)
	/*for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}*/
	block := make([]conflictedEventV2, len(events))
	for i := range events {
		event := &events[i]
		block[i] = conflictedEventV2{
			// effectivePowerLevel: event.
			originServerTS: int64(event.OriginServerTS()),
			eventID:        []byte(event.EventID()),
			event:          event,
		}
	}
	sort.Sort(conflictedEventV2Sorter(block))
	return block
}

// kahnsAlgorithmByAuthEvents is, predictably, an implementation of Kahn's
// algorithm that uses auth events to topologically sort the input list of
// events. This works through each event, counting how many incoming auth event
// dependencies it has, and then adding them into the graph as the dependencies
// are resolved.
func kahnsAlgorithmUsingAuthEvents(events []Event) (graph []Event) {
	eventMap := make(map[string]Event)
	inDegree := make(map[string]int)

	for _, event := range events {
		// For each even that we have been given, add it to the event map so that we
		// can easily refer back to it by event ID later.
		eventMap[event.EventID()] = event

		// If we haven't encountered this event ID yet, also start with a zero count
		// of incoming auth event dependencies.
		if _, ok := inDegree[event.EventID()]; !ok {
			inDegree[event.EventID()] = 0
		}

		// Find each of the auth events that this event depends on and make a note
		// for each auth event that there's an additional incoming dependency.
		for _, auth := range event.AuthEventIDs() {
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
	// dependencies. These will be placed into the graph first.
	var noIncoming []string
	for eventID, count := range inDegree {
		if count == 0 {
			noIncoming = append(noIncoming, eventID)
		}
	}

	var eventID string
	for len(noIncoming) > 0 {
		// Pop the first event ID off the list of events which have no incoming
		// auth event dependencies.
		eventID, noIncoming = noIncoming[0], noIncoming[1:]

		// Since there are no incoming dependencies to resolve, we can now add this
		// event into the graph.
		realEvent := eventMap[eventID]
		graph = append([]Event{realEvent}, graph...)

		// Now we should look at the outgoing auth dependencies that this event has.
		// Since this event is now in the graph, the event's outgoing auth
		// dependencies are no longer valid - those map to incoming dependencies on
		// the auth events, so let's update those.
		for _, auth := range realEvent.AuthEventIDs() {
			inDegree[auth]--

			// If we see, by updating the incoming dependencies, that the auth event
			// no longer has any incoming dependencies, then it should also be added
			// into the graph on the next pass. In turn, this will also mean that we
			// process the outgoing dependencies of this auth event.
			if inDegree[auth] == 0 {
				noIncoming = append(noIncoming, auth)
			}
		}
	}

	// The graph is complete at this point!
	return graph
}

// A conflictedEventV2 is used to sort the events in a block by ascending depth and descending sha1 of event ID.
// (SPEC: We use the SHA1 of the event ID as an arbitrary tie breaker between events with the same depth)
type conflictedEventV2 struct {
	effectivePowerLevel int64
	originServerTS      int64
	eventID             []byte
	event               *Event
}

// A conflictedEventV2Sorter is used to sort the events using sort.Sort.
type conflictedEventV2Sorter []conflictedEventV2

func (s conflictedEventV2Sorter) Len() int {
	return len(s)
}

func (s conflictedEventV2Sorter) Less(i, j int) bool {
	if s[i].effectivePowerLevel > s[j].effectivePowerLevel {
		return true
	}
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	return bytes.Compare(s[i].eventID[:], s[j].eventID[:]) > 0
}

func (s conflictedEventV2Sorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
