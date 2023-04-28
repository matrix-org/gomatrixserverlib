package spec_test

import (
	"fmt"
	"testing"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

func TestValidRoomIDs(t *testing.T) {
	tests := map[string]struct {
		opaque string
		domain string
	}{
		"basic":            {opaque: defaultLocalpart, domain: defaultDomain},
		"extensive_opaque": {opaque: "!\"#$%&'()*+,-./0123456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", domain: defaultDomain},
		"domain_with_port": {opaque: defaultLocalpart, domain: "domain.org:80"},
		"minimum_id":       {opaque: "a", domain: "1"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf("!%s:%s", tc.opaque, tc.domain)

			roomID, err := spec.NewRoomID(raw)

			if err != nil {
				t.Fatalf("valid roomID should not fail: %s", err.Error())
			}
			if roomID.OpaqueID() != tc.opaque {
				t.Fatalf("OpaqueID - Expected: %s Actual: %s ", tc.opaque, roomID.OpaqueID())
			}
			if roomID.Domain() != spec.ServerName(tc.domain) {
				t.Fatalf("Domain - Expected: %s Actual: %s ", spec.ServerName(tc.domain), roomID.Domain())
			}
			if roomID.String() != raw {
				t.Fatalf("Raw - Expected: %s Actual: %s ", raw, roomID.String())
			}
		})
	}
}

func TestInvalidRoomIDs(t *testing.T) {
	tests := map[string]struct {
		rawRoomID string
	}{
		"empty":                {rawRoomID: ""},
		"no_leading_!":         {rawRoomID: "localpart:domain"},
		"no_colon":             {rawRoomID: "!localpartdomain"},
		"invalid_domain_chars": {rawRoomID: "!localpart:domain/"},
		"no_local":             {rawRoomID: "!:domain"},
		"no_domain":            {rawRoomID: "!localpart:"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := spec.NewRoomID(tc.rawRoomID)

			if err == nil {
				t.Fatalf("roomID is not valid, it shouldn't parse")
			}
		})
	}
}

func TestSameRoomIDsAreEqual(t *testing.T) {
	id := "!localpart:domain"

	roomID, err := spec.NewRoomID(id)
	roomID2, err2 := spec.NewRoomID(id)

	if err != nil || err2 != nil {
		t.Fatalf("roomID is valid, it should parse")
	}

	if *roomID != *roomID2 {
		t.Fatalf("roomIDs should be equal")
	}
}

func TestDifferentRoomIDsAreNotEqual(t *testing.T) {
	id := "!localpart:domain"
	id2 := "!localpart2:domain"

	roomID, err := spec.NewRoomID(id)
	roomID2, err2 := spec.NewRoomID(id2)

	if err != nil || err2 != nil {
		t.Fatalf("roomID is valid, it should parse")
	}

	if *roomID == *roomID2 {
		t.Fatalf("roomIDs shouldn't be equal")
	}
}
