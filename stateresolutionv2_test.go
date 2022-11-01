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
				EventID: "$CREATE:example.com",
				eventFields: eventFields{
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
				EventID: "$IMA:example.com",
				eventFields: eventFields{
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
				EventID: "$IPOWER:example.com",
				eventFields: eventFields{
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
				EventID: "$IJR:example.com",
				eventFields: eventFields{
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
				EventID: "$IMB:example.com",
				eventFields: eventFields{
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
				EventID: "$IMC:example.com",
				eventFields: eventFields{
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
				EventID: "$PA:example.com",
				eventFields: eventFields{
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
				EventID: "$PB:example.com",
				eventFields: eventFields{
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
				EventID: "$MB:example.com",
				eventFields: eventFields{
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
				EventID: "$IME:example.com",
				eventFields: eventFields{
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
				EventID: "$JR:example.com",
				eventFields: eventFields{
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
				EventID: "$IMZ:example.com",
				eventFields: eventFields{
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

func TestStateResolutionOtherEventDoesntOverpowerPowerEvent(t *testing.T) {
	eventJSONs := []string{
		/* create event            */ `{"auth_events":[],"content":{"creator":"@anon-20220512_124253-1:localhost:8800","room_version":"6"},"depth":1,"hashes":{"sha256":"ej3MHt4EnQemwqnfLhgwN6RBArYc5JnWcZt1PI3m4hE"},"origin":"localhost:8800","origin_server_ts":1652359375504,"prev_events":[],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"7Pu9f39yDWJtl8msrnz+sPSBEA2jOJ4tJsZ1Zb6Bi+vZQMzMWwT/U6GZipxQqaeJr0TpVMa7zq/YhivArRRbAA"}},"state_key":"","type":"m.room.create"}`,
		/* first user joins        */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8"],"content":{"displayname":"anon-20220512_124253-1","membership":"join"},"depth":2,"hashes":{"sha256":"L3aLzAakLKWzl9IlhjO6CAqAaANjyV6W5mI8XlD8XR8"},"origin":"localhost:8800","origin_server_ts":1652359375504,"prev_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"1lRHwVx5kFAfeUdndh3/hhAe5S3uugA+FwPR2ZiXBxr4DkjcfDb4TRCobEv3G9IBWPPbQxKw20x3LlTsstunAw"}},"state_key":"@anon-20220512_124253-1:localhost:8800","type":"m.room.member"}`,
		/* power levels            */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8","$00fae_PeYsZWsrtXYTSfauzH51QfRVe43ADCUIjtN1E"],"content":{"ban":50,"events":{"m.room.avatar":50,"m.room.canonical_alias":50,"m.room.history_visibility":100,"m.room.name":50,"m.room.power_levels":100},"events_default":0,"invite":50,"kick":50,"notifications":{"room":50},"redact":50,"state_default":50,"users":{"@anon-20220512_124253-1:localhost:8800":100},"users_default":0},"depth":3,"hashes":{"sha256":"6yG8CSKC31H0GJlUdSuML3XGZLrIL/hS5aF8n6kLWaU"},"origin":"localhost:8800","origin_server_ts":1652359375504,"prev_events":["$00fae_PeYsZWsrtXYTSfauzH51QfRVe43ADCUIjtN1E"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"4chQhuq4KYyJdQDA+ym/SswbSwtQYACvdFUPravvLHSzkJISCQ+6t76Hj90AgWo0TTiOIkJxsgmakkUiWQnYAg"}},"state_key":"","type":"m.room.power_levels"}`,
		/* join rules = public     */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8","$i2hsVdh5QxBroLmgpo91TxPcHQzd9VnQKgoYwY66SxI","$00fae_PeYsZWsrtXYTSfauzH51QfRVe43ADCUIjtN1E"],"content":{"join_rule":"public"},"depth":4,"hashes":{"sha256":"YqSmumeFsCepwGoOFzcdQoHHM1aY8Ddk9r2XhYOM9wY"},"origin":"localhost:8800","origin_server_ts":1652359375504,"prev_events":["$i2hsVdh5QxBroLmgpo91TxPcHQzd9VnQKgoYwY66SxI"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"C2k2CVlsgXYYDI8XQtwR0su/e9ujrp4hVjZ9zI1f7EEGDV8r6BLR46Y0I858vuA+kkGNiOz+HxutxcZY26OFDw"}},"state_key":"","type":"m.room.join_rules"}`,
		/* history vis = shared    */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8","$i2hsVdh5QxBroLmgpo91TxPcHQzd9VnQKgoYwY66SxI","$00fae_PeYsZWsrtXYTSfauzH51QfRVe43ADCUIjtN1E"],"content":{"history_visibility":"shared"},"depth":5,"hashes":{"sha256":"+PfJAGh4ZC2h44a91vvIjC1atM9zUqSUhX1P6n1o0hM"},"origin":"localhost:8800","origin_server_ts":1652359375504,"prev_events":["$RTbObai9XOoujyGg2pz90sbOZHJ1807sF9ic-mqSGL8"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"Kmvs8/Mh4LllCO5BqJLmq7deRPb8UM07MOK9RYdZYSoqn0vhTOEet2zkPHVi8kFXCQR0Fwlx2qfN5RYSk1d/CA"}},"state_key":"","type":"m.room.history_visibility"}`,
		/* aliases                 */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8","$i2hsVdh5QxBroLmgpo91TxPcHQzd9VnQKgoYwY66SxI","$00fae_PeYsZWsrtXYTSfauzH51QfRVe43ADCUIjtN1E"],"content":{"alias":"#test-20220512_124253-2:localhost:8800"},"depth":6,"hashes":{"sha256":"PRniKNpqRwT8OhqqGLlWohAZwlBAW/Ls+tfzkFwWGWo"},"origin":"localhost:8800","origin_server_ts":1652359375504,"prev_events":["$NfX__HuszWh6DvwNaUZBY0ZYhEoYHRnkF4yJT3dfaww"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"NPZw/aGT+NykXTloRi/1SxalTdJBYmgwiy+SbsQkRGyKkAIqo3JkSgvUBb618ZtGxfJwgvsvQlBu53Tu+SAUCQ"}},"state_key":"","type":"m.room.canonical_alias"}`,
		/* second user joins       */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8","$RTbObai9XOoujyGg2pz90sbOZHJ1807sF9ic-mqSGL8","$i2hsVdh5QxBroLmgpo91TxPcHQzd9VnQKgoYwY66SxI"],"content":{"avatar_url":"","displayname":"anon-20220512_124253-2","membership":"join"},"depth":7,"hashes":{"sha256":"BLec3G4mLa99dr8K1NaVvGh1pDWCOHZd10/mcVc7hMA"},"origin":"localhost:8800","origin_server_ts":1652359375689,"prev_events":["$oUu8vxS4Sikr6tUITnHbnMrW-8fQpJWnLfO0sNB7kW4"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-2:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"gyF1Qph/s1Z94Ne3QI42FsOLjiZs7DbEB6+vAu59XEY5SkoCdm5THqXfrIkbOIcebKcE2HntSjNZOyhGXSETBQ"}},"state_key":"@anon-20220512_124253-2:localhost:8800","type":"m.room.member","unsigned":{}}`,
		/* first user kicks second */ `{"auth_events":["$497roGiLBBI5Q2ZKPCoSegSi8f8sSfWJW9JLPGnlGw8","$i2hsVdh5QxBroLmgpo91TxPcHQzd9VnQKgoYwY66SxI","$00fae_PeYsZWsrtXYTSfauzH51QfRVe43ADCUIjtN1E","$Djpz6XCVAF39psdQSwgZdiYyDDwKEPBgs9M6Bmbw11s"],"content":{"displayname":"anon-20220512_124253-2","membership":"leave","reason":"testing"},"depth":8,"hashes":{"sha256":"I9EXGDXtPo6WRVpbr06ppeQYEJtEkx/pxsveNR8pmj0"},"origin":"localhost:8800","origin_server_ts":1652359375738,"prev_events":["$Djpz6XCVAF39psdQSwgZdiYyDDwKEPBgs9M6Bmbw11s"],"prev_state":[],"room_id":"!3CHu7khd0phWyTm5:localhost:8800","sender":"@anon-20220512_124253-1:localhost:8800","signatures":{"localhost:8800":{"ed25519:rhNBRg":"ho7JrdMV3FgFD94grYNmdgS7lbuenE180ATVGYlae14IH7IsS071Vg7HMjihGc+2KXiaM5Njwy9+9VUXvbiJBA"}},"state_key":"@anon-20220512_124253-2:localhost:8800","type":"m.room.member"}`,
	}
	events := make([]*Event, 0, len(eventJSONs))
	for _, eventJSON := range eventJSONs {
		event, err := NewEventFromTrustedJSON([]byte(eventJSON), false, RoomVersionV6)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	conflicted, unconflicted := separate(events)
	t.Log("Unconflicted:")
	for _, v := range unconflicted {
		t.Log("-", v.EventID())
		t.Log("  ", v.Type(), *v.StateKey())
		t.Log("  ", string(v.Content()))
	}
	t.Log("Conflicted:")
	for _, v := range conflicted {
		t.Log("-", v.EventID())
		t.Log("  ", v.Type(), *v.StateKey())
		t.Log("  ", string(v.Content()))
	}
	result := ResolveStateConflictsV2(
		conflicted,   // conflicted set
		unconflicted, // unconflicted set
		events,       // full auth set
	)
	t.Log("Resolved:")
	for k, v := range result {
		t.Log("-", k, v.EventID())
	}
	found := false
	for _, v := range result {
		if v.EventID() == events[len(eventJSONs)-1].eventID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Expected to find the last event in the resolved set")
	}
}

func runStateResolutionV2(t *testing.T, additional []*Event, expected []string) {
	input := append(getBaseStateResV2Graph(), additional...)
	conflicted, unconflicted := separate(input)

	result := ResolveStateConflictsV2(
		conflicted,   // conflicted set
		unconflicted, // unconflicted set
		input,        // full auth set
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
