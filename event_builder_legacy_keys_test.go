// Copyright 2026 Damir Mukimov
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package gomatrixserverlib

import (
	"crypto/ed25519"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// The "origin" and "prev_state" keys were removed from the event format in
// room v3. Events built for room v3+ must not carry them, because strict
// peers (e.g. SyTest's mock federation server) keep those keys when deriving
// event IDs from legacy redaction lists and end up with IDs that disagree
// with the ones this library declared. Room v1/v2 events keep both keys.
func TestEventBuilderOmitsLegacyEventFormatKeysForV3Plus(t *testing.T) {
	testCases := []struct {
		version      string
		wantOrigin   bool
		wantPrevStat bool
	}{
		{"1", true, true},
		{"2", true, true},
		{"6", false, false},
		{"10", false, false},
		{"12", false, false},
	}

	for _, tc := range testCases {
		for _, stateful := range []bool{true, false} {
			r := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test key
			_, privateKey, err := ed25519.GenerateKey(r)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			eb := MustGetRoomVersion(RoomVersion(tc.version)).NewEventBuilder()
			eb.SenderID = "@user:origin.example"
			eb.RoomID = "!room:origin.example"
			eb.Type = "m.room.topic"
			if stateful {
				sk := ""
				eb.StateKey = &sk
			}
			if err = eb.SetContent(map[string]interface{}{"topic": "legacy key check"}); err != nil {
				t.Fatalf("failed to set content: %v", err)
			}
			eb.Depth = 1
			eb.PrevEvents = []string{}
			eb.AuthEvents = []string{}
			event, err := eb.Build(time.Unix(1700000000, 0).UTC(), "origin.example", "ed25519:k1", privateKey)
			if err != nil {
				t.Fatalf("failed to build %s event: %v", tc.version, err)
			}
			eventJSON := string(event.JSON())

			if got := strings.Contains(eventJSON, "\"origin\":"); got != tc.wantOrigin {
				t.Errorf("room %s (stateful=%v): origin key present=%v, want %v", tc.version, stateful, got, tc.wantOrigin)
			}
			// Stateful events carry prev_state in v1/v2; message events never did.
			wantPrevState := tc.wantPrevStat && stateful
			if got := strings.Contains(eventJSON, "prev_state"); got != wantPrevState {
				t.Errorf("room %s (stateful=%v): prev_state key present=%v, want %v", tc.version, stateful, got, wantPrevState)
			}
		}
	}
}
