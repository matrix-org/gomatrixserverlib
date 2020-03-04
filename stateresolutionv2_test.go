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
	"sort"
	"testing"
)

var (
	ALICE   = "@alice:example.com"
	BOB     = "@bob:example.com"
	CHARLIE = "@charlie:example.com"
	EVELYN  = "@evelyn:example.com"
	ZARA    = "@zara:example.com"
)

var emptyStateKey = ""

// separate takes a list of events and works out which events are conflicted and
// which are unconflicted.
func separate(events []Event) (conflicted, unconflicted []Event) {
	// The stack maps event type -> event state key -> list of state events.
	stack := make(map[string]map[string][]Event)
	// Prepare the map.
	for _, event := range events {
		// If we haven't encountered an entry of this type yet, create an entry.
		if _, ok := stack[event.Type()]; !ok {
			stack[event.Type()] = make(map[string][]Event)
		}
		// Add the event to the map.
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
				conflicted = append(conflicted, eventsOfStateKey...)
			} else if len(eventsOfStateKey) == 1 {
				unconflicted = append(unconflicted, eventsOfStateKey[0])
			}
		}
	}
	return
}

func getBaseStateResV2Graph() []Event {
	return []Event{
		{
			fields: eventFields{
				EventID:        "$CREATE:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomCreate,
				OriginServerTS: 1,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				Content:        []byte(`{"creator": "` + ALICE + `"}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IMA:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomMember,
				OriginServerTS: 2,
				Sender:         ALICE,
				StateKey:       &ALICE,
				PrevEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
				},
				Content: []byte(`{"membership": "join"}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IPOWER:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomPowerLevels,
				OriginServerTS: 3,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMA:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IMA:example.com"},
				},
				Content: []byte(`{"users": {"` + ALICE + `": 100}}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IJR:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomJoinRules,
				OriginServerTS: 4,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IPOWER:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IMA:example.com"},
					EventReference{EventID: "$IPOWER:example.com"},
				},
				Content: []byte(`{"join_rule": "public"}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IMB:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomMember,
				OriginServerTS: 5,
				Sender:         BOB,
				StateKey:       &BOB,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IJR:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$IPOWER:example.com"},
				},
				Content: []byte(`{"membership": "join"}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IMC:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomMember,
				OriginServerTS: 6,
				Sender:         CHARLIE,
				StateKey:       &CHARLIE,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMB:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$IPOWER:example.com"},
				},
				Content: []byte(`{"membership": "join"}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IMZ:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomMember,
				OriginServerTS: 7,
				Sender:         ZARA,
				StateKey:       &ZARA,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMC:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$IPOWER:example.com"},
				},
				Content: []byte(`{"membership": "join"}`),
			},
		},
	}
}

func TestStateResolutionBase(t *testing.T) {
	expected := []string{
		"$CREATE:example.com", "$IJR:example.com", "$IPOWER:example.com",
		"$IMA:example.com", "$IMB:example.com", "$IMC:example.com",
		"$IMZ:example.com",
	}

	runStateResolutionV2(t, []Event{}, expected)
}

func TestStateResolutionBanVsPowerLevel(t *testing.T) {
	expected := []string{
		"$CREATE:example.com", "$IJR:example.com", "$PA:example.com",
		"$IMA:example.com", "$IMB:example.com", "$IMC:example.com",
		"$MB:example.com", "$IMZ:example.com",
	}

	runStateResolutionV2(t, []Event{
		{
			fields: eventFields{
				EventID:        "$PA:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomPowerLevels,
				OriginServerTS: 8,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMC:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$IPOWER:example.com"},
				},
				Content: []byte(`{"users": {
					"` + ALICE + `": 100,
					"` + BOB + `": 50
				}}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$PB:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomPowerLevels,
				OriginServerTS: 9,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMC:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$IPOWER:example.com"},
				},
				Content: []byte(`{"users": {
					"` + ALICE + `": 100,
					"` + BOB + `": 50
				}}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$MB:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomMember,
				OriginServerTS: 10,
				Sender:         ALICE,
				StateKey:       &EVELYN,
				PrevEvents: []EventReference{
					EventReference{EventID: "$PA:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$PB:example.com"},
				},
				Content: []byte(`{"membership": "ban"}`),
			},
		},
		{
			fields: eventFields{
				EventID:        "$IME:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomMember,
				OriginServerTS: 11,
				Sender:         EVELYN,
				StateKey:       &EVELYN,
				PrevEvents: []EventReference{
					EventReference{EventID: "$MB:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJR:example.com"},
					EventReference{EventID: "$PA:example.com"},
				},
				Content: []byte(`{"membership": "join"}`),
			},
		},
	}, expected)
}

func TestLexicographicalSorting(t *testing.T) {
	input := []stateResV2ConflictedPowerLevel{
		stateResV2ConflictedPowerLevel{eventID: "a", powerLevel: 0, originServerTS: 1},
		stateResV2ConflictedPowerLevel{eventID: "b", powerLevel: 0, originServerTS: 2},
		stateResV2ConflictedPowerLevel{eventID: "c", powerLevel: 0, originServerTS: 2},
		stateResV2ConflictedPowerLevel{eventID: "d", powerLevel: 25, originServerTS: 3},
		stateResV2ConflictedPowerLevel{eventID: "e", powerLevel: 50, originServerTS: 4},
		stateResV2ConflictedPowerLevel{eventID: "f", powerLevel: 75, originServerTS: 4},
		stateResV2ConflictedPowerLevel{eventID: "g", powerLevel: 100, originServerTS: 5},
	}
	expected := []string{"g", "f", "e", "d", "c", "b", "a"}

	sort.Stable(stateResV2ConflictedPowerLevelHeap(input))

	t.Log("Results:")
	for k, v := range input {
		t.Log("-", k, v.eventID)
	}
	t.Log("Expected:")
	for k, v := range expected {
		t.Log("-", k, v)
	}

	if len(input) != len(expected) {
		t.Fatalf("got %d elements but expected %d", len(input), len(expected))
	}

	for p, i := range input {
		if i.eventID != expected[p] {
			t.Fatalf("position %d did not match, got '%s' but expected '%s'", p, i.eventID, expected[p])
		}
	}
}

func TestReverseTopologicalEventSorting(t *testing.T) {
	r := stateResolverV2{}
	input := r.reverseTopologicalOrdering(getBaseStateResV2Graph())

	expected := []string{
		"$CREATE:example.com", "$IMA:example.com", "$IPOWER:example.com",
		"$IJR:example.com", "$IMB:example.com", "$IMC:example.com", "$IMZ:example.com",
	}

	t.Log("Result:")
	for k, v := range input {
		t.Log("-", k, v.EventID(), v.OriginServerTS())
	}
	t.Log("Expected:")
	for k, v := range expected {
		t.Log("-", k, v)
	}

	if len(input) != len(expected) {
		t.Fatalf("got %d elements but expected %d", len(input), len(expected))
	}

	for p, i := range input {
		if i.EventID() != expected[p] {
			t.Fatalf(
				"position %d did not match, got '%s' but expected '%s'",
				p, i.EventID(), expected[p],
			)
		}
	}
}

func runStateResolutionV2(t *testing.T, additional []Event, expected []string) {
	input := append(getBaseStateResV2Graph(), additional...)
	conflicted, unconflicted := separate(input)
	result := ResolveStateConflictsV2(
		conflicted,   // conflicted set
		unconflicted, // unconflicted set
		input,        // full auth set
		additional,   // auth difference
	)

	t.Log("Result:")
	for k, v := range result {
		t.Log("-", k, v.EventID())
	}
	t.Log("Expected:")
	for k, v := range expected {
		t.Log("-", k, v)
	}

	if len(result) != len(expected) {
		t.Fatalf("got %d elements but expected %d", len(result), len(expected))
	}

	isExpected := func(s string) bool {
		for _, e := range expected {
			if e == s {
				return true
			}
		}
		return false
	}

	noneMissing := func() (bool, string) {
		e := make(map[string]bool)
		r := make(map[string]bool)
		for _, event := range expected {
			e[event] = true
		}
		for _, event := range result {
			r[event.EventID()] = true
		}
		for event := range e {
			if _, ok := r[event]; !ok {
				return false, event
			}
		}
		return true, ""
	}

	for _, r := range result {
		if !isExpected(r.EventID()) {
			t.Fatalf("didn't expect to find '%s' in resolved state", r.EventID())
		}
	}

	if ok, missing := noneMissing(); !ok {
		t.Fatalf("expected to find '%s' in resolved state but didn't", missing)
	}
}
