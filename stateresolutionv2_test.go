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
	"reflect"
	"slices"
	"testing"

	sets "github.com/hashicorp/go-set/v3"
	"github.com/matrix-org/gomatrixserverlib/spec"
)

var (
	ALICE   = "@alice:example.com"
	BOB     = "@bob:example.com"
	CHARLIE = "@charlie:example.com"
	EVELYN  = "@evelyn:example.com"
	ZARA    = "@zara:example.com"
)

var emptyStateKey = ""

func getBaseStateResV2Graph() []PDU {
	return []PDU{
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$CREATE:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomCreate,
				OriginServerTS: 1,
				SenderID:       ALICE,
				StateKey:       &emptyStateKey,
				Content:        []byte(`{"creator": "` + ALICE + `"}`),
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IMA:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomMember,
				OriginServerTS: 2,
				SenderID:       ALICE,
				StateKey:       &ALICE,
				Content:        []byte(`{"membership": "join"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IPOWER:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomPowerLevels,
				OriginServerTS: 3,
				SenderID:       ALICE,
				StateKey:       &emptyStateKey,
				Content:        []byte(`{"users": {"` + ALICE + `": 100}}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IMA:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IMA:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IJR:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomJoinRules,
				OriginServerTS: 4,
				SenderID:       ALICE,
				StateKey:       &emptyStateKey,
				Content:        []byte(`{"join_rule": "public"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IPOWER:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IMA:example.com"},
				{EventID: "$IPOWER:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IMB:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomMember,
				OriginServerTS: 5,
				SenderID:       BOB,
				StateKey:       &BOB,
				Content:        []byte(`{"membership": "join"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IJR:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IJR:example.com"},
				{EventID: "$IPOWER:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IMC:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomMember,
				OriginServerTS: 6,
				SenderID:       CHARLIE,
				StateKey:       &CHARLIE,
				Content:        []byte(`{"membership": "join"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IMB:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IJR:example.com"},
				{EventID: "$IPOWER:example.com"},
			},
		},
	}
}

func TestLexicographicalSorting(t *testing.T) {
	input := []*stateResV2ConflictedPowerLevel{
		{eventID: "a", powerLevel: 0, originServerTS: 1},
		{eventID: "b", powerLevel: 0, originServerTS: 2},
		{eventID: "c", powerLevel: 0, originServerTS: 2},
		{eventID: "d", powerLevel: 25, originServerTS: 3},
		{eventID: "e", powerLevel: 50, originServerTS: 4},
		{eventID: "f", powerLevel: 50, originServerTS: 3},
		{eventID: "g", powerLevel: 75, originServerTS: 4},
		{eventID: "h", powerLevel: 100, originServerTS: 5},
	}
	expected := []string{"h", "g", "f", "e", "d", "a", "b", "c"}

	slices.SortStableFunc(input, sortStateResV2ConflictedPowerLevelHeap)

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
	var base []PDU
	base = append(base, graph...)
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

func isRejectedTest(_ string) bool { return false }

func TestCalculateFullAuthChain(t *testing.T) {
	//
	//             .- D < D2 -.
	// A < B < C <-+          +-- F < G
	//             `- E < E2 -`
	//
	graph := map[string][]string{
		"A":  {},
		"B":  {"A"},
		"C":  {"B"},
		"D":  {"C"},
		"E":  {"C"},
		"D2": {"D"},
		"E2": {"E"},
		"F":  {"D2", "E2"},
		"G":  {"F"},
	}
	authEventMap := make(map[string]PDU)
	for eventID, authEventIDs := range graph {
		authEvent := &eventV2{
			eventV1: eventV1{
				EventIDRaw: eventID,
			},
			AuthEvents: authEventIDs,
		}
		authEventMap[authEvent.EventID()] = authEvent
	}
	resolver := stateResolverV2{
		authEventMap: authEventMap,
	}
	testCases := []struct {
		name          string
		startEventIDs []string
		wantAuthChain []string
	}{
		{
			name:          "simple linear",
			startEventIDs: []string{"C"},
			wantAuthChain: []string{"A", "B"},
		},
		{
			name:          "simple fork",
			startEventIDs: []string{"F"},
			wantAuthChain: []string{"A", "B", "C", "D", "D2", "E", "E2"},
		},
		{
			name:          "simple fork with redundant",
			startEventIDs: []string{"F", "D", "B"},
			wantAuthChain: []string{"A", "B", "C", "D", "D2", "E", "E2"},
		},
	}
	for _, tc := range testCases {
		t.Logf("%s", tc.name)
		stateSet := make([]PDU, len(tc.startEventIDs))
		for i := range tc.startEventIDs {
			stateSet[i] = authEventMap[tc.startEventIDs[i]]
		}
		fullAuthChains, _ := resolver.calculateFullAuthChainAndConflictedSubgraph(StateResV2, stateSet, newPDUSet(nil))
		assertSetEquals(t, tc.name, fullAuthChains, tc.wantAuthChain)
	}
}

func TestCalculateFullAuthChainAndConflictedSubgraph(t *testing.T) {
	//
	//             .- D < D2 -.
	// A < B < C <-+          +-- F < G
	//             `- E < E2 -`
	//
	graph := map[string][]string{
		"A":  {},
		"B":  {"A"},
		"C":  {"B"},
		"D":  {"C"},
		"E":  {"C"},
		"D2": {"D"},
		"E2": {"E"},
		"F":  {"D2", "E2"},
		"G":  {"F"},
	}
	authEventMap := make(map[string]PDU)
	for eventID, authEventIDs := range graph {
		authEvent := &eventV2{
			eventV1: eventV1{
				EventIDRaw: eventID,
			},
			AuthEvents: authEventIDs,
		}
		authEventMap[authEvent.EventID()] = authEvent
	}
	resolver := stateResolverV2{
		authEventMap: authEventMap,
	}
	testCases := []struct {
		name                   string
		startEventIDs          []string
		conflictedEventIDs     []string
		wantAuthChain          []string
		wantConflictedSubgraph []string
	}{
		{
			name:                   "simple linear",
			startEventIDs:          []string{"B", "D"},
			conflictedEventIDs:     []string{"B", "D"},
			wantAuthChain:          []string{"A", "B", "C"},
			wantConflictedSubgraph: []string{"B", "C", "D"},
		},
		{
			name:                   "simple fork",
			startEventIDs:          []string{"F", "B"},
			conflictedEventIDs:     []string{"F", "B"},
			wantAuthChain:          []string{"A", "B", "C", "D", "D2", "E", "E2"},
			wantConflictedSubgraph: []string{"F", "E2", "E", "D2", "D", "C", "B"},
		},
		{
			name: "walks already walked paths",
			// we expect to walk G->A and F->A first, meaning we would have explored C -> A
			// we want to assert that we re-walk the conflicted events
			startEventIDs:          []string{"G", "F", "C", "A"},
			conflictedEventIDs:     []string{"C", "A"},
			wantAuthChain:          []string{"A", "B", "C", "D", "D2", "E", "E2", "F"},
			wantConflictedSubgraph: []string{"C", "B", "A"},
		},
	}
	for _, tc := range testCases {
		t.Logf("%s", tc.name)
		stateSet := make([]PDU, len(tc.startEventIDs))
		for i := range tc.startEventIDs {
			stateSet[i] = authEventMap[tc.startEventIDs[i]]
		}
		conflictedEvents := make([]PDU, len(tc.conflictedEventIDs))
		for i := range tc.conflictedEventIDs {
			conflictedEvents[i] = authEventMap[tc.conflictedEventIDs[i]]
		}
		fullAuthChains, conflictedSubgraph := resolver.calculateFullAuthChainAndConflictedSubgraph(StateResV2_1, stateSet, newPDUSet(conflictedEvents))
		assertSetEquals(t, "wrong full auth chain: "+tc.name, fullAuthChains, tc.wantAuthChain)
		assertSetEquals(t, "wrong conflicted subgraph: "+tc.name, conflictedSubgraph, tc.wantConflictedSubgraph)
	}
}

func assertSetEquals(t *testing.T, name string, gotSet *sets.HashSet[PDU, string], wantSet []string) {
	t.Helper()
	var got []string
	for ev := range gotSet.Items() {
		got = append(got, ev.EventID())
	}
	slices.Sort(wantSet)
	slices.Sort(got)
	if !reflect.DeepEqual(got, wantSet) {
		t.Errorf("%s:\ngot  %v\nwant %v", name, got, wantSet)
	}
}

// TODO:
// TestStateResolutionSingleNonPowerConflict
// TestStateResolutionSinglePowerConflict
//  f.e winner on PL, winner on timestamp
// TestStateResolutionConcurrentBan
// TestStateResolutionV2_1ConflictedSubgraph
// TestStateResolutionV2_1EmptySet

func mustParseEvent(t *testing.T, eventBytes []byte) PDU {
	t.Helper()
	event, err := MustGetRoomVersion(RoomVersionV6).NewEventFromTrustedJSON(eventBytes, false)
	if err != nil {
		t.Fatal(err)
	}
	return event
}
