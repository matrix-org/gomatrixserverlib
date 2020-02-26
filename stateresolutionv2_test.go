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
		t.Fatalf("got %d elements but expected %d", len(input), len(expected))
	}

	for p, i := range result {
		if i.EventID() != expected[p] {
			t.Fatalf("position %d did not match, got '%s' but expected '%s'", p, i.EventID(), expected[p])
		}
	}
}
