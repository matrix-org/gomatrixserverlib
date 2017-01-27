package gomatrixserverlib

import (
	"bytes"
	"crypto/sha1"
	"sort"
)

// ResolveStateConflicts takes a list of state events with conflicting state keys
// and works out which event should be used for each state event.
func ResolveStateConflicts(conflicted []Event, authEvents []Event) []Event {
	var r stateResolver
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
type stateResolver struct {
	creates                   []Event
	powerLevels               []Event
	joinRules                 []Event
	thirdPartyInvites         [][]Event
	members                   [][]Event
	others                    [][]Event
	resolvedCreate            *Event
	resolvedPowerLevels       *Event
	resolvedJoinRules         *Event
	resolvedThirdPartyInvites map[string]*Event
	resolvedMembers           map[string]*Event
	result                    []Event
}

func (r *stateResolver) Create() (*Event, error) {
	return r.resolvedCreate, nil
}

func (r *stateResolver) PowerLevels() (*Event, error) {
	return r.resolvedPowerLevels, nil
}

func (r *stateResolver) JoinRules() (*Event, error) {
	return r.resolvedJoinRules, nil
}

func (r *stateResolver) ThirdPartyInvite(key string) (*Event, error) {
	return r.resolvedThirdPartyInvites[key], nil
}

func (r *stateResolver) Member(key string) (*Event, error) {
	return r.resolvedMembers[key], nil
}

func (r *stateResolver) addConflicted(events []Event) {
	type conflictKey struct {
		eventType string
		stateKey  string
	}
	offsets := map[conflictKey]int{}
	// Split up the conflicted events into blocks with the same state key.
	for _, event := range events {
		key := conflictKey{event.Type(), *event.StateKey()}
		// Work out which block to add the event to.
		var block *[]Event
		// By default we add the event to a block in the others list.
		blockList := &r.others
		switch key.eventType {
		case "m.room.create":
			if key.stateKey == "" {
				block = &r.creates
			}
		case "m.room.power_levels":
			if key.stateKey == "" {
				block = &r.powerLevels
			}
		case "m.room.join_rules":
			if key.stateKey == "" {
				block = &r.joinRules
			}
		case "m.room.member":
			blockList = &r.members
		case "m.room.third_party_invite":
			blockList = &r.thirdPartyInvites
		}
		if block == nil {
			// We need to find an entry for the state key in a block list.
			offset, ok := offsets[key]
			if !ok {
				// This is the first time we've seen that state key so we add a
				// new block to the block list.
				offset = len(*blockList)
				*blockList = append(*blockList, nil)
			}
			// Get the address of the block in the block list.
			block = &(*blockList)[offset]
		}
		// Add the event to the block.
		*block = append(*block, event)
	}
}

// Add an event to the resolved auth events.
func (r *stateResolver) addAuthEvent(event *Event) {
	switch event.Type() {
	case "m.room.create":
		r.resolvedCreate = event
	case "m.room.power_levels":
		r.resolvedPowerLevels = event
	case "m.room.join_rules":
		r.resolvedJoinRules = event
	case "m.room.member":
		r.resolvedMembers[*event.StateKey()] = event
	case "m.room.third_party_invite":
		r.resolvedThirdPartyInvites[*event.StateKey()] = event
	}
}

// Remove the auth event with the given type and state key.
func (r *stateResolver) removeAuthEvent(eventType, stateKey string) {
	switch eventType {
	case "m.room.create":
		r.resolvedCreate = nil
	case "m.room.power_levels":
		r.resolvedPowerLevels = nil
	case "m.room.join_rules":
		r.resolvedJoinRules = nil
	case "m.room.member":
		r.resolvedMembers[stateKey] = nil
	case "m.room.third_party_invite":
		r.resolvedThirdPartyInvites[stateKey] = nil
	}
}

// resolveAndAddAuthBlocks resolves each block of conflicting auth state events in a list of blocks
// where all the blocks have the same event type.
// Once every block has been resolved the resulting events are added to the events used for auth checks.
func (r *stateResolver) resolveAndAddAuthBlocks(blocks [][]Event) {
	start := len(r.result)
	for _, block := range blocks {
		if event := r.resolveAuthBlock(block); event != nil {
			r.result = append(r.result, *event)
		}
	}
	for i := start; i < len(r.result); i++ {
		r.addAuthEvent(&r.result[i])
	}
}

// resolveAuthBlock resolves a block of auth events with the same state key to a single event.
func (r *stateResolver) resolveAuthBlock(events []Event) *Event {
	// Sort the events by depth and sha1 of event ID
	block := make([]conflictedEvent, len(events))
	for i := range events {
		event := &events[i]
		block[i] = conflictedEvent{
			depth:       event.Depth(),
			eventIDSHA1: sha1.Sum([]byte(event.EventID())),
			event:       event,
		}
	}
	sort.Sort(conflictedEventSorter(block))

	// Pick the "oldest" event, that is the one with the lowest depth, as the first candidate.
	result := block[0].event
	// Temporarily add the candidate event to the auth events.
	r.addAuthEvent(result)
	for i := 1; i < len(block); i++ {
		event := block[i].event
		// Check if the next event passes authentication checks against the current candidate.
		if Allowed(*event, r) == nil {
			// If the event passes authentication checks pick it as the current candidate.
			result = event
			r.addAuthEvent(result)
		} else {
			break
		}
	}
	// Discard the event from the auth events.
	// We'll add it back later when all events of the same type have been resolved.
	r.removeAuthEvent(result.Type(), *result.StateKey())
	return result
}

// resolveNormalBlock resolves a block of normal state events with the same state key to a single event.
func (r *stateResolver) resolveNormalBlock(events []Event) *Event {
	// Sort the events by depth and sha1 of event ID
	block := make([]conflictedEvent, len(events))
	for i := range events {
		event := &events[i]
		block[i] = conflictedEvent{
			depth:       event.Depth(),
			eventIDSHA1: sha1.Sum([]byte(event.EventID())),
			event:       event,
		}
	}
	sort.Sort(conflictedEventSorter(block))

	// Start at the "newest" event, that is the one with the highest depth, and go
	// backward through the list until we find one that passes authentication checks.
	for i := len(block) - 1; i > 0; i-- {
		event := block[i].event
		if Allowed(*event, r) == nil {
			return event
		}
	}
	return block[0].event
}

// A conflictedEvent is used to sort the events in a block by depth and sha1 of event ID.
type conflictedEvent struct {
	depth       int64
	eventIDSHA1 [sha1.Size]byte
	event       *Event
}

// A conflictedEventSorter is used to sort the events using sort.Sort.
type conflictedEventSorter []conflictedEvent

func (s conflictedEventSorter) Len() int {
	return len(s)
}

func (s conflictedEventSorter) Less(i, j int) bool {
	if s[i].depth == s[j].depth {
		return 0 < bytes.Compare(s[i].eventIDSHA1[:], s[j].eventIDSHA1[:])
	}
	return s[i].depth < s[j].depth
}

func (s conflictedEventSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
