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

func TestBasicValidSucceeds(t *testing.T) {
	localpart := defaultLocalpart
	domain := defaultDomain
	raw := fmt.Sprintf("@%s:%s", localpart, domain)

	userID, err := gomatrixserverlib.NewUserID(raw, false)

	if err != nil {
		t.Fatalf("valid userID should not fail")
	}
	if userID.Local() != localpart {
		t.Fatalf("Localpart - Expected: %s Actual: %s ", localpart, userID.Local())
	}
	if userID.Domain() != gomatrixserverlib.ServerName(domain) {
		t.Fatalf("Domain - Expected: %s Actual: %s ", gomatrixserverlib.ServerName(domain), userID.Domain())
	}
	if userID.Raw() != raw {
		t.Fatalf("Raw - Expected: %s Actual: %s ", raw, userID.Raw())
	}
}

func TestExtensiveLocalpartSucceeds(t *testing.T) {
	localpart := "abcdefghijklmnopqrstuvwxyz0123456789._=-/"
	domain := defaultDomain
	raw := fmt.Sprintf("@%s:%s", localpart, domain)

	userID, err := gomatrixserverlib.NewUserID(raw, false)

	if err != nil {
		t.Fatalf("valid userID should not fail")
	}
	if userID.Local() != localpart {
		t.Fatalf("Localpart - Expected: %s Actual: %s ", localpart, userID.Local())
	}
	if userID.Domain() != gomatrixserverlib.ServerName(domain) {
		t.Fatalf("Domain - Expected: %s Actual: %s ", domain, userID.Domain())
	}
	if userID.Raw() != raw {
		t.Fatalf("Raw - Expected: %s Actual: %s ", raw, userID.Raw())
	}
}

func TestExtensiveLocalpartHistoricalSucceeds(t *testing.T) {
	localpart := "!\"#$%&'()*+,-./0123456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	domain := defaultDomain
	raw := fmt.Sprintf("@%s:%s", localpart, domain)

	userID, err := gomatrixserverlib.NewUserID(raw, true)

	if err != nil {
		t.Fatalf("valid userID should not fail")
	}
	if userID.Local() != localpart {
		t.Fatalf("Localpart - Expected: %s Actual: %s ", localpart, userID.Local())
	}
	if userID.Domain() != gomatrixserverlib.ServerName(domain) {
		t.Fatalf("Domain - Expected: %s Actual: %s ", domain, userID.Domain())
	}
	if userID.Raw() != raw {
		t.Fatalf("Raw - Expected: %s Actual: %s ", raw, userID.Raw())
	}
}

func TestDomainWithPortSucceeds(t *testing.T) {
	localpart := defaultLocalpart
	domain := "domain.org:80"
	raw := fmt.Sprintf("@%s:%s", localpart, domain)

	userID, err := gomatrixserverlib.NewUserID(raw, false)

	if err != nil {
		t.Fatalf("valid userID should not fail")
	}
	if userID.Local() != localpart {
		t.Fatalf("Localpart - Expected: %s Actual: %s ", localpart, userID.Local())
	}
	if userID.Domain() != gomatrixserverlib.ServerName(domain) {
		t.Fatalf("Domain - Expected: %s Actual: %s ", domain, userID.Domain())
	}
	if userID.Raw() != raw {
		t.Fatalf("Raw - Expected: %s Actual: %s ", raw, userID.Raw())
	}
}

func TestTooLongFails(t *testing.T) {
	userID := "@a:"
	domain := ""
	for i := 0; i < 255-len(userID)+1; i++ {
		domain = domain + "a"
	}

	raw := userID + domain

	if len(raw) <= 255 {
		t.Fatalf("ensure the userid is greater than 255 (is %d) characters for this test", len(raw))
	}

	_, err := gomatrixserverlib.NewUserID(raw, false)

	if err == nil {
		t.Fatalf("userID is not valid, it shouldn't parse")
	}
}

func TestNoLeadingAtFails(t *testing.T) {
	userID := "localpart:domain"

	_, err := gomatrixserverlib.NewUserID(userID, false)

	if err == nil {
		t.Fatalf("userID is not valid, it shouldn't parse")
	}
}

func TestNoColonFails(t *testing.T) {
	userID := "@localpartdomain"

	_, err := gomatrixserverlib.NewUserID(userID, false)

	if err == nil {
		t.Fatalf("userID is not valid, it shouldn't parse")
	}
}

func TestInvalidLocalCharactersFails(t *testing.T) {
	userID := "@local&part:domain"

	_, err := gomatrixserverlib.NewUserID(userID, false)

	if err == nil {
		t.Fatalf("userID is not valid, it shouldn't parse")
	}
}

func TestInvalidDomainFails(t *testing.T) {
	userID := "@localpart:domain.com/"

	_, err := gomatrixserverlib.NewUserID(userID, false)

	if err == nil {
		t.Fatalf("domain is not valid, it shouldn't parse")
	}
}

func TestEmptyLocalpartFails(t *testing.T) {
	userID := "@:domain"

	_, err := gomatrixserverlib.NewUserID(userID, false)

	if err == nil {
		t.Fatalf("userID is not valid, it shouldn't parse")
	}
}
