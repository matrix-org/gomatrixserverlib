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

// separate takes a list of events and works out which events are conflicted and
// which are unconflicted.
func separate(events []PDU) (conflicted, unconflicted []PDU) {
	// The stack maps event type -> event state key -> list of state events.
	stack := make(map[string]map[string][]PDU)
	// Prepare the map.
	for _, event := range events {
		// If we haven't encountered an entry of this type yet, create an entry.
		if _, ok := stack[event.Type()]; !ok {
			stack[event.Type()] = make(map[string][]PDU)
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

func TestStateResolutionBase(t *testing.T) {
	expected := []string{
		"$CREATE:example.com", "$IJR:example.com", "$IPOWER:example.com",
		"$IMA:example.com", "$IMB:example.com", "$IMC:example.com",
	}

	runStateResolutionV2(t, []PDU{}, expected)
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

	runStateResolutionV2(t, []PDU{
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$PA:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomPowerLevels,
				OriginServerTS: 7,
				SenderID:       ALICE,
				StateKey:       &emptyStateKey,
				Content: []byte(`{"users": {
					"` + ALICE + `": 100,
					"` + BOB + `": 50
				}}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IMZJOIN:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IMA:example.com"},
				{EventID: "$IPOWER:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$PB:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomPowerLevels,
				OriginServerTS: 8,
				SenderID:       ALICE,
				StateKey:       &emptyStateKey,
				Content: []byte(`{"users": {
					"` + ALICE + `": 100,
					"` + BOB + `": 50
				}}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IMC:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IMA:example.com"},
				{EventID: "$IPOWER:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$MB:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomMember,
				OriginServerTS: 9,
				SenderID:       ALICE,
				StateKey:       &EVELYN,
				Content:        []byte(`{"membership": "ban"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$PA:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IMA:example.com"},
				{EventID: "$PB:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IME:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomMember,
				OriginServerTS: 10,
				SenderID:       EVELYN,
				StateKey:       &EVELYN,
				Content:        []byte(`{"membership": "join"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$MB:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IJR:example.com"},
				{EventID: "$PA:example.com"},
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

	runStateResolutionV2(t, []PDU{
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$JR:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomJoinRules,
				OriginServerTS: 8,
				SenderID:       ALICE,
				StateKey:       &emptyStateKey,
				Content:        []byte(`{"join_rule": "invite"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$IMZ:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$IMA:example.com"},
				{EventID: "$IPOWER:example.com"},
			},
		},
		&eventV1{
			roomVersion: RoomVersionV2,
			EventIDRaw:  "$IMZ:example.com",
			eventFields: eventFields{
				RoomID:         "!ROOM:example.com",
				Type:           spec.MRoomMember,
				OriginServerTS: 9,
				SenderID:       ZARA,
				StateKey:       &ZARA,
				Content:        []byte(`{"membership": "join"}`),
			},
			PrevEvents: []eventReference{
				{EventID: "$JR:example.com"},
			},
			AuthEvents: []eventReference{
				{EventID: "$CREATE:example.com"},
				{EventID: "$JR:example.com"},
				{EventID: "$IPOWER:example.com"},
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
	events := make([]PDU, 0, len(eventJSONs))
	for _, eventJSON := range eventJSONs {
		event, err := MustGetRoomVersion(RoomVersionV6).NewEventFromTrustedJSON([]byte(eventJSON), false)
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
		UserIDForSenderTest,
	)
	t.Log("Resolved:")
	for k, v := range result {
		t.Log("-", k, v.EventID())
	}
	found := false
	for _, v := range result {
		if v.EventID() == events[len(eventJSONs)-1].EventID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Expected to find the last event in the resolved set")
	}
}

func runStateResolutionV2(t *testing.T, additional []PDU, expected []string) {
	input := append(getBaseStateResV2Graph(), additional...)
	conflicted, unconflicted := separate(input)

	result := ResolveStateConflictsV2(
		conflicted,   // conflicted set
		unconflicted, // unconflicted set
		input,        // full auth set
		UserIDForSenderTest,
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

// TestStateReset validates that, given "wrong" prev events, we correctly calculate the
// new state. See https://github.com/matrix-org/dendrite/pull/3231 as well.
func TestStateReset(t *testing.T) {
	// NOTE: The following events are taken from a Dendrite UT.
	createEv := mustParseEvent(t, []byte(`{"auth_events":[],"content":{"creator":"@1:test","room_version":"9"},"depth":1,"hashes":{"sha256":"OZriBeMNVoymY/JqjM3Ee6oKSfoWskCiy48dUq5crR8"},"origin":"test","origin_server_ts":1697134517143,"prev_events":[],"prev_state":[],"room_id":"!2:test","sender":"@1:test","signatures":{"test":{"ed25519:test":"eyVzDAWjFtEaDtcYD2aLOjwxYegJSRJTEg5eRkksL3rNJUB0nRim2iGGCznjNzTg3V84K4bmuIs41aR7A2TBBQ"}},"state_key":"","type":"m.room.create"}`))
	aliceJoinEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg"],"content":{"membership":"join"},"depth":2,"hashes":{"sha256":"xktNmFYn936RCil8B5h5Jfb+BFuyCKfUsOHCU92KHbE"},"origin":"test","origin_server_ts":1697134517143,"prev_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg"],"prev_state":[],"room_id":"!2:test","sender":"@1:test","signatures":{"test":{"ed25519:test":"cBaNa3UDzDE/TEH0ZmDciJj7aa5XOv8Ze1F+YGxea/TI86ivD6ULkylEl9+52A3kNC1/k8u7d7VZTDEMA/YZCw"}},"state_key":"@1:test","type":"m.room.member"}`))
	plEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$pha7iGLaAXqkf_GAwBhPtdyjM0DF4qxiAbbc-zGJbRc"],"content":{"ban":50,"events":{"m.room.avatar":50,"m.room.canonical_alias":50,"m.room.encryption":100,"m.room.history_visibility":100,"m.room.name":50,"m.room.power_levels":100,"m.room.server_acl":100,"m.room.tombstone":100},"events_default":0,"invite":0,"kick":50,"notifications":{"room":50},"redact":50,"state_default":50,"users":{"@1:test":100},"users_default":0},"depth":3,"hashes":{"sha256":"Tg8kVJh7Pam9Q9rkMa2qoPzkQ2febdBLGiB2dB+6aqQ"},"origin":"test","origin_server_ts":1697134517143,"prev_events":["$pha7iGLaAXqkf_GAwBhPtdyjM0DF4qxiAbbc-zGJbRc"],"prev_state":[],"room_id":"!2:test","sender":"@1:test","signatures":{"test":{"ed25519:test":"1BKFKdklWUkxeKn8+9lGUVRNYSTscFwP0JR6KPH/KvuqOdOOl896mIJ3lp9iLrrHFYEOP0+Tl/gWWjY0r4zoBA"}},"state_key":"","type":"m.room.power_levels"}`))
	jrEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0","$pha7iGLaAXqkf_GAwBhPtdyjM0DF4qxiAbbc-zGJbRc"],"content":{"join_rule":"public"},"depth":4,"hashes":{"sha256":"he+A0e/+4282sOZ0E6eXAGrQ7b2wAHfr4E/qMX2Sosg"},"origin":"test","origin_server_ts":1697134517144,"prev_events":["$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0"],"prev_state":[],"room_id":"!2:test","sender":"@1:test","signatures":{"test":{"ed25519:test":"tnX+YOaNhWipRTAsnXtxDeT0OLGQRhQN/cWF4cjLj92zjfyvGPIgoMXBpdFojq+0TiCsTPx673aWiYKFGap3AA"}},"state_key":"","type":"m.room.join_rules"}`))
	hisVisEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0","$pha7iGLaAXqkf_GAwBhPtdyjM0DF4qxiAbbc-zGJbRc"],"content":{"history_visibility":"shared"},"depth":5,"hashes":{"sha256":"keUaZvadB9S775FT2/WOog+XwqcquUMDLlsKjtx7HYI"},"origin":"test","origin_server_ts":1697134517144,"prev_events":["$ZDzKFnVFil6ea2QoMa5wpFW_RJe5kTEv2ZD4jctEWM4"],"prev_state":[],"room_id":"!2:test","sender":"@1:test","signatures":{"test":{"ed25519:test":"OX1cA63VvYy/xli+kzJqAy/0f20RKMxn8khqvWYry3bRQqXRN2Z+er3wMFo6dego9e37l1b4UWXnoFvAUYbaDA"}},"state_key":"","type":"m.room.history_visibility"}`))
	bobJoinEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$ZDzKFnVFil6ea2QoMa5wpFW_RJe5kTEv2ZD4jctEWM4","$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0"],"content":{"membership":"join"},"depth":6,"hashes":{"sha256":"eMAArXQGPaJMbU22Bvgqzks1zLMiQTGXI28eT4CsEaM"},"origin":"test","origin_server_ts":1697134517145,"prev_events":["$KvMXxqhECWclFe58hgxr_s26ytJ57olFSMv2uVjbtSo"],"prev_state":[],"room_id":"!2:test","sender":"@2:test","signatures":{"test":{"ed25519:test":"TT+NLaNGzJbEe2B9AZ1rPUX/Af3S7rHpZK2Vqv3ioxrH7pzs7nDSs2+1G9+yxxjqLtybi1QuFbyGKAb2J/DmDA"}},"state_key":"@2:test","type":"m.room.member"}`))
	charlieJoinEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$ZDzKFnVFil6ea2QoMa5wpFW_RJe5kTEv2ZD4jctEWM4","$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0"],"content":{"membership":"join"},"depth":7,"hashes":{"sha256":"lsD2HYq8ovMhfTznU4RH2vk/cZTa8nwQVM8LYyCTzZs"},"origin":"test","origin_server_ts":1697134517145,"prev_events":["$AbMj-EZa-blPfjNYj9dPUXAQM5oLxcnPdoUvtTVI-hs"],"prev_state":[],"room_id":"!2:test","sender":"@3:test","signatures":{"test":{"ed25519:test":"5wOjA9IZkN28/yd4bJl8elnsxGR9QjDzKhSxDq/Js24hnqErV0DRB4luETZZDTWdCJJPRy5q7mIOoCTr6Zv/DQ"}},"state_key":"@3:test","type":"m.room.member"}`))
	bobNameEv := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$ZDzKFnVFil6ea2QoMa5wpFW_RJe5kTEv2ZD4jctEWM4","$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0","$AbMj-EZa-blPfjNYj9dPUXAQM5oLxcnPdoUvtTVI-hs"],"content":{"displayname":"Bob!","membership":"join"},"depth":10,"hashes":{"sha256":"GKm317RAdHnrAnESQRocRS5DhSJ756/3UjxBskjKEz4"},"origin":"test","origin_server_ts":1697134517386,"prev_events":["$sd5vMK06VQ28CEnyUfZuJbiD-HXSsQXAS2-6Mm906qk"],"prev_state":[],"room_id":"!2:test","sender":"@2:test","signatures":{"test":{"ed25519:test":"oXQalkq0zQ28+KFueHLTD+hXu2oq4/MgN9w2jThn79IICDl+RDp0svYzqaYRahwbBDpTjPvWXjjiN6oJ4Z53Bw"}},"state_key":"@2:test","type":"m.room.member"}`))
	jr2Ev := mustParseEvent(t, []byte(`{"auth_events":["$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg","$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0","$pha7iGLaAXqkf_GAwBhPtdyjM0DF4qxiAbbc-zGJbRc"],"content":{"join_rule":"invite"},"depth":11,"hashes":{"sha256":"HtEx3O2ORo/V5Q3FHQVuPi8AvXts5tcMV5BbmsHcm+E"},"origin":"test","origin_server_ts":1697134517410,"prev_events":["$7w83ropQafHxxgMcJFWgynFXN_f1L-DgVHUPYC8KYVY"],"prev_state":[],"room_id":"!2:test","sender":"@1:test","signatures":{"test":{"ed25519:test":"5euVd5N/01mjrYQoNLlSnQWqonb2DUPSwQ4ZQz0A34fQzV3z+QjsBaIByYh2ZwkhFHnmJUvC8rUH8+JSv28NAA"}},"state_key":"","type":"m.room.join_rules"}`))

	// conflicted/unconflicted as calculated by Dendrite
	conflicted := []PDU{bobJoinEv, bobNameEv}
	unconflicted := []PDU{createEv, aliceJoinEv, plEv, jrEv, hisVisEv, charlieJoinEv, jr2Ev}
	authEvents := append(unconflicted, conflicted...)

	// The events we expect after state resolution
	expectedEvents := map[string]PDU{
		"$7w83ropQafHxxgMcJFWgynFXN_f1L-DgVHUPYC8KYVY": bobNameEv,
		"$0B4FVZWbziXiuaBZyVerHDfBs40toK4FhoT1DNLs_tg": createEv,
		"$pha7iGLaAXqkf_GAwBhPtdyjM0DF4qxiAbbc-zGJbRc": aliceJoinEv,
		"$B6yTeN_9fWhp5duir471Ac-OSC9BlsHnlRcbVpfmOH0": plEv,
		"$KvMXxqhECWclFe58hgxr_s26ytJ57olFSMv2uVjbtSo": hisVisEv,
		"$9IhOwrJzpmcAKaq05_MmKq7mqBUZENVoFOYz1_GQgX4": charlieJoinEv,
		"$IaXTO8US6DmRrPexxTucUaMoc7M0uwvMrOzWoFSsy5o": jr2Ev,
	}

	resolved := ResolveStateConflictsV2(conflicted, unconflicted, authEvents, UserIDForSenderTest)
	unexpectedEvents := make(map[string]PDU)
	for _, resolvedEv := range resolved {
		if _, found := expectedEvents[resolvedEv.EventID()]; !found {
			unexpectedEvents[resolvedEv.EventID()] = resolvedEv
			continue
		}
		delete(expectedEvents, resolvedEv.EventID())
	}

	if len(expectedEvents) > 0 {
		t.Error("Expected event missing after state resolution:")
		for evID, ev := range expectedEvents {
			t.Errorf("\t%s: %s", evID, ev.JSON())
		}
	}

	if len(unexpectedEvents) > 0 {
		t.Error("Unexpected events after state resolution:")
		for evID, ev := range unexpectedEvents {
			t.Errorf("\t%s: %s", evID, ev.JSON())
		}
	}
}

func mustParseEvent(t *testing.T, eventBytes []byte) PDU {
	t.Helper()
	event, err := MustGetRoomVersion(RoomVersionV6).NewEventFromTrustedJSON([]byte(eventBytes), false)
	if err != nil {
		t.Fatal(err)
	}
	return event
}
