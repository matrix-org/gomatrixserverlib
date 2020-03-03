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
	"fmt"
	"sort"
	"testing"
)

var (
	ALICE  = "@alice:example.com"
	BOB    = "@bob:example.com"
	EVELYN = "@evelyn:example.com"
	ZARA   = "@zara:example.com"
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

var stateResolutionV2Base = []Event{
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
			EventID:        "$IMEMBERA:example.com",
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
				EventReference{EventID: "$IMEMBERA:example.com"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "$CREATE:example.com"},
				EventReference{EventID: "$IMEMBERA:example.com"},
			},
			Content: []byte(`{"users": {"` + ALICE + `": 100}}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "$IJOINRULE:example.com",
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
				EventReference{EventID: "$IMEMBERA:example.com"},
				EventReference{EventID: "$IPOWER:example.com"},
			},
			Content: []byte(`{"join_rule": "public"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "$IMEMBERC:example.com",
			RoomID:         "!ROOM:example.com",
			Type:           MRoomMember,
			OriginServerTS: 5,
			Sender:         BOB,
			StateKey:       &BOB,
			PrevEvents: []EventReference{
				EventReference{EventID: "$IJOINRULE:example.com"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "$CREATE:example.com"},
				EventReference{EventID: "$IJOINRULE:example.com"},
				EventReference{EventID: "$IPOWER:example.com"},
			},
			Content: []byte(`{"membership": "join"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "$IMEMBERZ:example.com",
			RoomID:         "!ROOM:example.com",
			Type:           MRoomMember,
			OriginServerTS: 6,
			Sender:         ZARA,
			StateKey:       &ZARA,
			PrevEvents: []EventReference{
				EventReference{EventID: "$IMEMBERC:example.com"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "$CREATE:example.com"},
				EventReference{EventID: "$IJOINRULE:example.com"},
				EventReference{EventID: "$IPOWER:example.com"},
			},
			Content: []byte(`{"membership": "join"}`),
		},
	},
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
	expected := []string{"g", "f", "e", "d", "a", "b", "c"}

	sort.Stable(stateResV2ConflictedPowerLevelHeap(input))

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
	input := r.reverseTopologicalOrdering(stateResolutionV2Base)

	expected := []string{
		"$CREATE:example.com", "$IMEMBERA:example.com", "$IPOWER:example.com",
		"$IJOINRULE:example.com", "$IMEMBERC:example.com", "$IMEMBERZ:example.com",
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

func TestStateResolutionX100(t *testing.T) {
	// This test will very quickly highlight if the algorithm is non-deterministic
	// or resolves different results when ran multiple times.
	for i := 0; i < 100; i++ {
		TestStateResolution(t)
	}
}

func TestStateResolution(t *testing.T) {
	input := append(stateResolutionV2Base, []Event{
		{
			fields: eventFields{
				EventID:        "$PA:example.com",
				RoomID:         "!ROOM:example.com",
				Type:           MRoomPowerLevels,
				OriginServerTS: 7,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMEMBERZ:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJOINRULE:example.com"},
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
				OriginServerTS: 8,
				Sender:         ALICE,
				StateKey:       &emptyStateKey,
				PrevEvents: []EventReference{
					EventReference{EventID: "$IMEMBERZ:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJOINRULE:example.com"},
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
				OriginServerTS: 9,
				Sender:         ALICE,
				StateKey:       &EVELYN,
				PrevEvents: []EventReference{
					EventReference{EventID: "$PA:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJOINRULE:example.com"},
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
				OriginServerTS: 10,
				Sender:         EVELYN,
				StateKey:       &EVELYN,
				PrevEvents: []EventReference{
					EventReference{EventID: "$MB:example.com"},
				},
				AuthEvents: []EventReference{
					EventReference{EventID: "$CREATE:example.com"},
					EventReference{EventID: "$IJOINRULE:example.com"},
					EventReference{EventID: "$PA:example.com"},
				},
				Content: []byte(`{"membership": "join"}`),
			},
		},
	}...)

	conflicted, unconflicted := separate(input)
	result := ResolveStateConflictsV2(conflicted, unconflicted, input)

	expected := []string{
		"$CREATE:example.com", "$IJOINRULE:example.com", "$PB:example.com",
		"$IMEMBERA:example.com", "$IMEMBERC:example.com", "$IMEMBERZ:example.com",
		"$MB:example.com",
	}

	if len(result) != len(expected) {
		fmt.Println("Result:")
		for k, v := range result {
			fmt.Println("-", k, v.EventID())
		}
		fmt.Println("Expected:")
		for k, v := range expected {
			fmt.Println("-", k, v)
		}

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

	noneMissing := func() (found bool) {
		for _, e := range expected {
			for _, r := range result {
				if r.EventID() == e {
					found = true
					return
				}
			}
		}
		return
	}

	for p, r := range result {
		if !isExpected(r.EventID()) {
			t.Fatalf("position %d did not match, got '%s' but expected '%s'", p, r.EventID(), expected[p])
		}
	}

	if !noneMissing() {
		t.Fatalf("expected to find element but didn't")
	}
}
