package gomatrixserverlib_test

import (
	"fmt"
	"testing"

	"github.com/matrix-org/gomatrixserverlib"
)

const defaultDomain = "domain"
const defaultLocalpart = "localpart"

func TestEmptyFails(t *testing.T) {
	_, err := gomatrixserverlib.NewUserID("", false)
	if err == nil {
		t.Fatalf("empty userID is not valid, it shouldn't parse")
	}
}

func TestValidUserIDs(t *testing.T) {
	tests := map[string]struct {
		localpart        string
		domain           string
		allowHistoricIDs bool
	}{
		"basic":                    {localpart: defaultLocalpart, domain: defaultDomain, allowHistoricIDs: false},
		"extensive_local":          {localpart: "abcdefghijklmnopqrstuvwxyz0123456789._=-/", domain: defaultDomain, allowHistoricIDs: false},
		"extensive_local_historic": {localpart: "!\"#$%&'()*+,-./0123456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", domain: defaultDomain, allowHistoricIDs: true},
		"domain_with_port":         {localpart: defaultLocalpart, domain: "domain.org:80", allowHistoricIDs: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf("@%s:%s", tc.localpart, tc.domain)

			userID, err := gomatrixserverlib.NewUserID(raw, tc.allowHistoricIDs)

			if err != nil {
				t.Fatalf("valid userID should not fail: %s", err.Error())
			}
			if userID.Local() != tc.localpart {
				t.Fatalf("Localpart - Expected: %s Actual: %s ", tc.localpart, userID.Local())
			}
			if userID.Domain() != gomatrixserverlib.ServerName(tc.domain) {
				t.Fatalf("Domain - Expected: %s Actual: %s ", gomatrixserverlib.ServerName(tc.domain), userID.Domain())
			}
			if userID.Raw() != raw {
				t.Fatalf("Raw - Expected: %s Actual: %s ", raw, userID.Raw())
			}
		})
	}
}

func TestInvalidUserIDs(t *testing.T) {
	tests := map[string]struct {
		rawUserID string
	}{
		"too_long": {rawUserID: func() string {
			userID := "@a:"
			domain := ""
			for i := 0; i < 255-len(userID)+1; i++ {
				domain = domain + "a"
			}

			raw := userID + domain

			if len(raw) <= 255 {
				t.Fatalf("ensure the userid is greater than 255 (is %d) characters for this test", len(raw))
			}
			return raw
		}()},
		"no_leading_@":         {rawUserID: "localpart:domain"},
		"no_colon":             {rawUserID: "@localpartdomain"},
		"invalid_local_chars":  {rawUserID: "@local&part:domain"},
		"invalid_domain_chars": {rawUserID: "@localpart:domain/"},
		"no_local":             {rawUserID: "@:domain"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := gomatrixserverlib.NewUserID(tc.rawUserID, false)

			if err == nil {
				t.Fatalf("userID is not valid, it shouldn't parse")
			}
		})
	}
}

func TestSameUserIDsAreEqual(t *testing.T) {
	id := "@localpart:domain"

	userID, err := gomatrixserverlib.NewUserID(id, false)
	userID2, err2 := gomatrixserverlib.NewUserID(id, false)

	if err != nil || err2 != nil {
		t.Fatalf("userID is valid, it should parse")
	}

	if *userID != *userID2 {
		t.Fatalf("userIDs should be equal")
	}
}

func TestDifferentUserIDsAreNotEqual(t *testing.T) {
	id := "@localpart:domain"
	id2 := "@localpart2:domain"

	userID, err := gomatrixserverlib.NewUserID(id, false)
	userID2, err2 := gomatrixserverlib.NewUserID(id2, false)

	if err != nil || err2 != nil {
		t.Fatalf("userID is valid, it should parse")
	}

	if *userID == *userID2 {
		t.Fatalf("userIDs shouldn't be equal")
	}
}
