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
	"crypto/sha1"
	"fmt"
	"sort"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

// ResolveStateConflicts takes a list of state events with conflicting state keys
// and works out which event should be used for each state event.
func ResolveStateConflicts(conflicted []PDU, authEvents []PDU, userIDForSender spec.UserIDForSender) []PDU {
	r := stateResolver{valid: true}
	r.resolvedThirdPartyInvites = map[string]PDU{}
	r.resolvedMembers = map[spec.SenderID]PDU{}
	// Group the conflicted events by type and state key.
	r.addConflicted(conflicted)
	// Add the unconflicted auth events needed for auth checks.
	for i := range authEvents {
		r.addAuthEvent(authEvents[i])
	}
	// Resolve the conflicted auth events.
	r.resolveAndAddAuthBlocks([][]PDU{r.creates}, userIDForSender)
	r.resolveAndAddAuthBlocks([][]PDU{r.powerLevels}, userIDForSender)
	r.resolveAndAddAuthBlocks([][]PDU{r.joinRules}, userIDForSender)
	r.resolveAndAddAuthBlocks(r.thirdPartyInvites, userIDForSender)
	r.resolveAndAddAuthBlocks(r.members, userIDForSender)
	// Resolve any other conflicted state events.
	for _, block := range r.others {
		if event := r.resolveNormalBlock(block, userIDForSender); event != nil {
			r.result = append(r.result, event)
		}
	}
	return r.result
}

// A stateResolver tracks the internal state of the state resolution algorithm
// It has 3 sections:
//   - Lists of lists of events to resolve grouped by event type and state key.
//   - The resolved auth events grouped by type and state key.
//   - A List of resolved events.
//
// It implements the AuthEvents interface and can be used for running auth checks.
type stateResolver struct {
	// Lists of lists of events to resolve grouped by event type and state key:
	//   * creates, powerLevels, joinRules have empty state keys.
	//   * members and thirdPartyInvites are grouped by state key.
	//   * the others are grouped by the pair of type and state key.
	creates           []PDU
	powerLevels       []PDU
	joinRules         []PDU
	thirdPartyInvites [][]PDU
	members           [][]PDU
	others            [][]PDU
	// The resolved auth events grouped by type and state key.
	resolvedCreate            PDU
	resolvedPowerLevels       PDU
	resolvedJoinRules         PDU
	resolvedThirdPartyInvites map[string]PDU
	resolvedMembers           map[spec.SenderID]PDU
	// The list of resolved events.
	// This will contain one entry for each conflicted event type and state key.
	result []PDU
	roomID string
	valid  bool
}

func (r *stateResolver) Create() (PDU, error) {
	return r.resolvedCreate, nil
}

func (r *stateResolver) Valid() bool {
	return r.valid
}

func (r *stateResolver) PowerLevels() (PDU, error) {
	return r.resolvedPowerLevels, nil
}

func (r *stateResolver) JoinRules() (PDU, error) {
	return r.resolvedJoinRules, nil
}

func (r *stateResolver) ThirdPartyInvite(key string) (PDU, error) {
	return r.resolvedThirdPartyInvites[key], nil
}

func (r *stateResolver) Member(key spec.SenderID) (PDU, error) {
	return r.resolvedMembers[key], nil
}

func (r *stateResolver) addConflicted(events []PDU) { // nolint: gocyclo
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
		case spec.MRoomCreate:
			if key.stateKey == "" {
				r.creates = append(r.creates, event)
				continue
			}
		case spec.MRoomPowerLevels:
			if key.stateKey == "" {
				r.powerLevels = append(r.powerLevels, event)
				continue
			}
		case spec.MRoomJoinRules:
			if key.stateKey == "" {
				r.joinRules = append(r.joinRules, event)
				continue
			}
		case spec.MRoomMember:
			blockList = &r.members
		case spec.MRoomThirdPartyInvite:
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
func (r *stateResolver) addAuthEvent(event PDU) {
	if event.RoomID() != "" && r.roomID == "" {
		r.roomID = event.RoomID()
	}
	if r.roomID != event.RoomID() {
		r.valid = false
	}
	switch event.Type() {
	case spec.MRoomCreate:
		if event.StateKeyEquals("") {
			r.resolvedCreate = event
		}
	case spec.MRoomPowerLevels:
		if event.StateKeyEquals("") {
			r.resolvedPowerLevels = event
		}
	case spec.MRoomJoinRules:
		if event.StateKeyEquals("") {
			r.resolvedJoinRules = event
		}
	case spec.MRoomMember:
		r.resolvedMembers[spec.SenderID(*event.StateKey())] = event
	case spec.MRoomThirdPartyInvite:
		r.resolvedThirdPartyInvites[*event.StateKey()] = event
	}
}

// Remove the auth event with the given type and state key.
func (r *stateResolver) removeAuthEvent(eventType, stateKey string) {
	switch eventType {
	case spec.MRoomCreate:
		if stateKey == "" {
			r.resolvedCreate = nil
		}
	case spec.MRoomPowerLevels:
		if stateKey == "" {
			r.resolvedPowerLevels = nil
		}
	case spec.MRoomJoinRules:
		if stateKey == "" {
			r.resolvedJoinRules = nil
		}
	case spec.MRoomMember:
		r.resolvedMembers[spec.SenderID(stateKey)] = nil
	case spec.MRoomThirdPartyInvite:
		r.resolvedThirdPartyInvites[stateKey] = nil
	}
}

// resolveAndAddAuthBlocks resolves each block of conflicting auth state events in a list of blocks
// where all the blocks have the same event type.
// Once every block has been resolved the resulting events are added to the events used for auth checks.
// This is called once per auth event type and state key pair.
func (r *stateResolver) resolveAndAddAuthBlocks(blocks [][]PDU, userIDForSender spec.UserIDForSender) {
	start := len(r.result)
	for _, block := range blocks {
		if len(block) == 0 {
			continue
		}
		if event := r.resolveAuthBlock(block, userIDForSender); event != nil {
			r.result = append(r.result, event)
		}
	}
	// Only add the events to the auth events once all of the events with that type have been resolved.
	// (SPEC: This is done to avoid the result of state resolution depending on the iteration order)
	for i := start; i < len(r.result); i++ {
		r.addAuthEvent(r.result[i])
	}
}

// resolveAuthBlock resolves a block of auth events with the same state key to a single event.
func (r *stateResolver) resolveAuthBlock(events []PDU, userIDForSender spec.UserIDForSender) PDU {
	// Sort the events by depth and sha1 of event ID
	block := sortConflictedEventsByDepthAndSHA1(events)

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
		if Allowed(event, r, userIDForSender) == nil {
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
func (r *stateResolver) resolveNormalBlock(events []PDU, userIDForSender spec.UserIDForSender) PDU {
	// Sort the events by depth and sha1 of event ID
	block := sortConflictedEventsByDepthAndSHA1(events)
	// Start at the "newest" event, that is the one with the highest depth, and go
	// backward through the list until we find one that passes authentication checks.
	// (SPEC: This prefers newer events so that we don't flip a valid state back to a previous version)
	for i := len(block) - 1; i > 0; i-- {
		event := block[i].event
		if Allowed(event, r, userIDForSender) == nil {
			return event
		}
	}
	// If all the auth checks for newer events fail then we pick the oldest event.
	// (SPEC: This ensures that we always pick a state event for this type and state key.
	//  Note that if all the events fail auth checks we will still pick the "oldest" event.)
	return block[0].event
}

// sortConflictedEventsByDepthAndSHA1 sorts by ascending depth and descending sha1 of event ID.
func sortConflictedEventsByDepthAndSHA1(events []PDU) []conflictedEvent {
	block := make([]conflictedEvent, len(events))
	for i := range events {
		event := events[i]
		block[i] = conflictedEvent{
			depth:       event.Depth(),
			eventIDSHA1: sha1.Sum([]byte(event.EventID())),
			event:       event,
		}
	}
	sort.Sort(conflictedEventSorter(block))
	return block
}

// A conflictedEvent is used to sort the events in a block by ascending depth and descending sha1 of event ID.
// (SPEC: We use the SHA1 of the event ID as an arbitrary tie breaker between events with the same depth)
type conflictedEvent struct {
	depth       int64
	eventIDSHA1 [sha1.Size]byte
	event       PDU
}

// A conflictedEventSorter is used to sort the events using sort.Sort.
type conflictedEventSorter []conflictedEvent

func (s conflictedEventSorter) Len() int {
	return len(s)
}

func (s conflictedEventSorter) Less(i, j int) bool {
	if s[i].depth == s[j].depth {
		return bytes.Compare(s[i].eventIDSHA1[:], s[j].eventIDSHA1[:]) > 0
	}
	return s[i].depth < s[j].depth
}

func (s conflictedEventSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// ResolveConflicts performs state resolution on the input events, returning the
// resolved state. It will automatically decide which state resolution algorithm
// to use, depending on the room version. `events` should be all the state events
// to resolve. `authEvents` should be the entire set of auth_events for these `events`.
// Returns an error if the state resolution algorithm cannot be determined.
func ResolveConflicts(
	version RoomVersion,
	events []PDU,
	authEvents []PDU,
	userIDForSender spec.UserIDForSender,
) ([]PDU, error) {
	type stateKeyTuple struct {
		Type     string
		StateKey string
	}

	// Prepare our data structures.
	eventIDMap := map[string]struct{}{}
	eventMap := make(map[stateKeyTuple][]PDU)
	var conflicted, notConflicted, resolved []PDU

	// Run through all of the events that we were given and sort them
	// into a map, sorted by (event_type, state_key) tuple. This means
	// that we can easily spot events that are "conflicted", e.g.
	// there are duplicate values for the same tuple key.
	for _, event := range events {
		if _, ok := eventIDMap[event.EventID()]; ok {
			continue
		}
		eventIDMap[event.EventID()] = struct{}{}
		if event.StateKey() == nil {
			// Ignore events that are not state events.
			continue
		}
		// Append the events if there is already a conflicted list for
		// this tuple key, create it if not.
		tuple := stateKeyTuple{event.Type(), *event.StateKey()}
		eventMap[tuple] = append(eventMap[tuple], event)
	}

	// Split out the events in the map into conflicted and unconflicted
	// buckets. The conflicted events will be ran through state res,
	// whereas unconfliced events will always going to appear in the
	// final resolved state.
	for _, list := range eventMap {
		if len(list) > 1 {
			conflicted = append(conflicted, list...)
		} else {
			notConflicted = append(notConflicted, list...)
		}
	}

	// Work out which state resolution algorithm we want to run for
	// the room version.
	verImpl, err := GetRoomVersion(version)
	if err != nil {
		return nil, err
	}
	stateResAlgo := verImpl.StateResAlgorithm()
	switch stateResAlgo {
	case StateResV1:
		// Currently state res v1 doesn't handle unconflicted events
		// for us, like state res v2 does, so we will need to add the
		// unconflicted events into the state ourselves.
		// TODO: Fix state res v1 so this is handled for the caller.
		resolved = ResolveStateConflicts(conflicted, authEvents, userIDForSender)
		resolved = append(resolved, notConflicted...)
	case StateResV2:
		resolved = ResolveStateConflictsV2(conflicted, notConflicted, authEvents, userIDForSender)
	default:
		return nil, fmt.Errorf("unsupported state resolution algorithm %v", stateResAlgo)
	}

	// Return the final resolved state events, including both the
	// resolved set of conflicted events, and the unconflicted events.
	return resolved, nil
}
