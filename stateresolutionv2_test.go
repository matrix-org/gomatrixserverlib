package gomatrixserverlib

import (
	"sort"
	"testing"
)

var (
	ALICE   = "@alice:test"
	BOB     = "@bob:test"
	CHARLIE = "@charlie:test"
	EVELYN  = "@evelyn:test"
	ZARA    = "@zara:test"
)

var stateResolutionV2Base = []Event{
	{
		fields: eventFields{
			EventID:        "CREATE",
			Type:           "m.room.create",
			OriginServerTS: 1,
			Sender:         ALICE,
			Content:        []byte(`{"creator": "` + ALICE + `"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "IMA",
			Type:           "m.room.member",
			OriginServerTS: 2,
			Sender:         ALICE,
			StateKey:       &ALICE,
			PrevEvents: []EventReference{
				EventReference{EventID: "CREATE"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "CREATE"},
			},
			Content: []byte(`{"membership": "join"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "IPOWER",
			Type:           "m.room.power_levels",
			OriginServerTS: 3,
			Sender:         ALICE,
			PrevEvents: []EventReference{
				EventReference{EventID: "IMA"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "CREATE"},
				EventReference{EventID: "IMA"},
			},
			Content: []byte(`{"users": {"` + ALICE + `": 100}}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "IJR",
			Type:           "m.room.join_rules",
			OriginServerTS: 4,
			Sender:         ALICE,
			PrevEvents: []EventReference{
				EventReference{EventID: "IPOWER"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "CREATE"},
				EventReference{EventID: "IMA"},
				EventReference{EventID: "IPOWER"},
			},
			Content: []byte(`{"join_rule": "public"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "IMC",
			Type:           "m.room.member",
			OriginServerTS: 5,
			Sender:         BOB,
			StateKey:       &BOB,
			PrevEvents: []EventReference{
				EventReference{EventID: "IJR"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "CREATE"},
				EventReference{EventID: "IJR"},
				EventReference{EventID: "IPOWER"},
			},
			Content: []byte(`{"membership": "join"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "IMZ",
			Type:           "m.room.member",
			OriginServerTS: 6,
			Sender:         ZARA,
			StateKey:       &ZARA,
			PrevEvents: []EventReference{
				EventReference{EventID: "IMC"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "CREATE"},
				EventReference{EventID: "IJR"},
				EventReference{EventID: "IPOWER"},
			},
			Content: []byte(`{"membership": "join"}`),
		},
	},
	{
		fields: eventFields{
			EventID:        "START",
			Type:           "m.room.message",
			OriginServerTS: 7,
			Sender:         ZARA,
			PrevEvents: []EventReference{
				EventReference{EventID: "IMZ"},
			},
			AuthEvents: []EventReference{
				EventReference{EventID: "CREATE"},
				EventReference{EventID: "IMZ"},
				EventReference{EventID: "IPOWER"},
			},
			Content: []byte(`{}`),
		},
	},
}

func TestLexicographicalSorting(t *testing.T) {
	input := []conflictedEventV2{
		conflictedEventV2{eventID: "a", effectivePowerLevel: 0, originServerTS: 1},
		conflictedEventV2{eventID: "b", effectivePowerLevel: 0, originServerTS: 2},
		conflictedEventV2{eventID: "c", effectivePowerLevel: 0, originServerTS: 2},
		conflictedEventV2{eventID: "d", effectivePowerLevel: 25, originServerTS: 3},
		conflictedEventV2{eventID: "e", effectivePowerLevel: 50, originServerTS: 4},
		conflictedEventV2{eventID: "f", effectivePowerLevel: 75, originServerTS: 4},
		conflictedEventV2{eventID: "g", effectivePowerLevel: 100, originServerTS: 5},
	}
	expected := []string{"g", "f", "e", "d", "a", "b", "c"}

	sort.Stable(conflictedEventV2Heap(input))

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
	input := sortConflictedEventsByReverseTopologicalOrdering(stateResolutionV2Base)
	expected := []string{"CREATE", "IMA", "IPOWER", "IJR", "IMC", "IMZ", "START"}

	if len(input) != len(expected) {
		t.Fatalf("got %d elements but expected %d", len(input), len(expected))
	}

	for p, i := range input {
		if i.eventID != expected[p] {
			t.Fatalf("position %d did not match, got '%s' but expected '%s'", p, i.eventID, expected[p])
		}
	}
}
