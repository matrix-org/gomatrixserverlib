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
func separate(events []*Event) (conflicted, unconflicted []*Event) {
	// The stack maps event type -> event state key -> list of state events.
	stack := make(map[string]map[string][]*Event)
	// Prepare the map.
	for _, event := range events {
		// If we haven't encountered an entry of this type yet, create an entry.
		if _, ok := stack[event.Type()]; !ok {
			stack[event.Type()] = make(map[string][]*Event)
		}
		// Work out the state key in a crash-proof manner.
		statekey := ""
		if event.StateKey() != nil {
			statekey = *event.StateKey()
		}
		// Check that we haven't already got this event in the list already. If we
		// do then don't bother duplicating it - that way if we end up with only
		// one unique value eventually, it'll get sorted as unconflicted.
		found := false
		for _, e := range stack[event.Type()][statekey] {
			if e.EventID() == event.EventID() {
				found = true
			}
		}
		// Add the event to the map if we haven't already found it.
		if !found {
			stack[event.Type()][statekey] = append(
				stack[event.Type()][statekey], event,
			)
		}
	}

	// Now we need to work out which of these events are conflicted. An event is
	// conflicted if there is more than one entry for the (type, statekey) tuple.
	// If we encounter these events, add them to their relevant conflicted list.
	for _, eventsOfType := range stack {
		for _, eventsOfStateKey := range eventsOfType {
			if len(eventsOfStateKey) > 1 {
				conflicted = append(conflicted, eventsOfStateKey...)
			} else {
				unconflicted = append(unconflicted, eventsOfStateKey...)
			}
		}
	}
	return
}

func getBaseStateResV2Graph() []*Event {
	return []*Event{
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$CREATE:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomCreate,
					OriginServerTS: 1,
					Sender:         ALICE,
					StateKey:       &emptyStateKey,
					Content:        []byte(`{"creator": "` + ALICE + `"}`),
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IMA:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomMember,
					OriginServerTS: 2,
					Sender:         ALICE,
					StateKey:       &ALICE,
					Content:        []byte(`{"membership": "join"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IPOWER:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomPowerLevels,
					OriginServerTS: 3,
					Sender:         ALICE,
					StateKey:       &emptyStateKey,
					Content:        []byte(`{"users": {"` + ALICE + `": 100}}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IMA:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IMA:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IJR:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomJoinRules,
					OriginServerTS: 4,
					Sender:         ALICE,
					StateKey:       &emptyStateKey,
					Content:        []byte(`{"join_rule": "public"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IPOWER:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IMA:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IMB:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomMember,
					OriginServerTS: 5,
					Sender:         BOB,
					StateKey:       &BOB,
					Content:        []byte(`{"membership": "join"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IJR:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IJR:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IMC:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomMember,
					OriginServerTS: 6,
					Sender:         CHARLIE,
					StateKey:       &CHARLIE,
					Content:        []byte(`{"membership": "join"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IMB:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IJR:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
	}
}

func TestStateResolutionBase(t *testing.T) {
	expected := []string{
		"$CREATE:example.com", "$IJR:example.com", "$IPOWER:example.com",
		"$IMA:example.com", "$IMB:example.com", "$IMC:example.com",
	}

	runStateResolutionV2(t, []*Event{}, expected)
}

func BenchmarkStateResolutionBanVsPowerLevel(b *testing.B) {
	t := &testing.T{}
	for i := 0; i < b.N; i++ {
		TestStateResolutionBanVsPowerLevel(t)
	}
}

func TestStateResolutionBanVsPowerLevel(t *testing.T) {
	expected := []string{
		"$CREATE:example.com", "$IJR:example.com", "$PA:example.com",
		"$IMA:example.com", "$IMB:example.com", "$IMC:example.com",
		"$MB:example.com",
	}

	runStateResolutionV2(t, []*Event{
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$PA:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomPowerLevels,
					OriginServerTS: 7,
					Sender:         ALICE,
					StateKey:       &emptyStateKey,
					Content: []byte(`{"users": {
					"` + ALICE + `": 100,
					"` + BOB + `": 50
				}}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IMZJOIN:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IMA:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$PB:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomPowerLevels,
					OriginServerTS: 8,
					Sender:         ALICE,
					StateKey:       &emptyStateKey,
					Content: []byte(`{"users": {
					"` + ALICE + `": 100,
					"` + BOB + `": 50
				}}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IMC:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IMA:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$MB:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomMember,
					OriginServerTS: 9,
					Sender:         ALICE,
					StateKey:       &EVELYN,
					Content:        []byte(`{"membership": "ban"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$PA:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IMA:example.com"},
					{EventID: "$PB:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IME:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomMember,
					OriginServerTS: 10,
					Sender:         EVELYN,
					StateKey:       &EVELYN,
					Content:        []byte(`{"membership": "join"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$MB:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IJR:example.com"},
					{EventID: "$PA:example.com"},
				},
			},
		},
	}, expected)
}

func TestStateResolutionJoinRuleEvasion(t *testing.T) {
	expected := []string{
		"$CREATE:example.com", "$JR:example.com", "$IPOWER:example.com",
		"$IMA:example.com", "$IMB:example.com", "$IMC:example.com",
		"$IMZ:example.com",
	}

	runStateResolutionV2(t, []*Event{
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$JR:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomJoinRules,
					OriginServerTS: 8,
					Sender:         ALICE,
					StateKey:       &emptyStateKey,
					Content:        []byte(`{"join_rule": "invite"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$IMZ:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$IMA:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
		{
			roomVersion: RoomVersionV2,
			fields: eventFormatV1Fields{
				eventFields: eventFields{
					EventID:        "$IMZ:example.com",
					RoomID:         "!ROOM:example.com",
					Type:           MRoomMember,
					OriginServerTS: 9,
					Sender:         ZARA,
					StateKey:       &ZARA,
					Content:        []byte(`{"membership": "join"}`),
				},
				PrevEvents: []EventReference{
					{EventID: "$JR:example.com"},
				},
				AuthEvents: []EventReference{
					{EventID: "$CREATE:example.com"},
					{EventID: "$JR:example.com"},
					{EventID: "$IPOWER:example.com"},
				},
			},
		},
	}, expected)
}

func TestLexicographicalSorting(t *testing.T) {
	input := []*stateResV2ConflictedPowerLevel{
		{eventID: "a", powerLevel: 0, originServerTS: 1},
		{eventID: "b", powerLevel: 0, originServerTS: 2},
		{eventID: "c", powerLevel: 0, originServerTS: 2},
		{eventID: "d", powerLevel: 25, originServerTS: 3},
		{eventID: "e", powerLevel: 50, originServerTS: 4},
		{eventID: "f", powerLevel: 75, originServerTS: 4},
		{eventID: "g", powerLevel: 100, originServerTS: 5},
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
	graph := getBaseStateResV2Graph()
	var base []*Event
	for i := range graph {
		base = append(base, graph[i])
	}
	input := r.reverseTopologicalOrdering(base, TopologicalOrderByAuthEvents)

	expected := []string{
		"$CREATE:example.com", "$IMA:example.com", "$IPOWER:example.com",
		"$IJR:example.com", "$IMB:example.com", "$IMC:example.com",
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

func runStateResolutionV2(t *testing.T, additional []*Event, expected []string) {
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
