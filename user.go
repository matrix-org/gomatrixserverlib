package gomatrixserverlib

import (
	"fmt"
	"strings"
)

const userSigil = '@'
const localDomainSeparator = ':'

// A UserID identifies a matrix user as per the matrix specification
type UserID struct {
	raw    string
	local  string
	domain string
}

func NewUserID(id string, allowHistoricalIDs bool) (*UserID, error) {
	return parseAndValidateUserID(id, allowHistoricalIDs)
}

func (user *UserID) Raw() string {
	return user.raw
}

func (user *UserID) Local() string {
	return user.local
}

func (user *UserID) Domain() ServerName {
	return ServerName(user.domain)
}

func parseAndValidateUserID(id string, allowHistoricalIDs bool) (*UserID, error) {
	idLength := len(id)
	if idLength < 1 || idLength > 255 {
		return nil, fmt.Errorf("length %d is not within the bounds 1-255", idLength)
	}
	if id[0] != userSigil {
		return nil, fmt.Errorf("first character is not '%c'", userSigil)
	}

	localpart, domain, found := strings.Cut(id[1:], string(localDomainSeparator))
	if !found {
		return nil, fmt.Errorf("at least one '%c' is expected in the user id", localDomainSeparator)
	}
	if _, _, ok := ParseAndValidateServerName(ServerName(domain)); !ok {
		return nil, fmt.Errorf("domain is invalid")
	}

	for _, r := range localpart {
		if !isLocalUserIDChar(r, allowHistoricalIDs) {
			return nil, fmt.Errorf("local part contains invalid characters")
		}
	}

	userID := &UserID{
		raw:    id,
		local:  localpart,
		domain: domain,
	}
	return userID, nil
}

func isLocalUserIDChar(r rune, allowHistoricalIDs bool) bool {
	// NOTE: Allowed in the latest spec
	// https://spec.matrix.org/v1.4/appendices/#user-identifiers
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	if r == '.' || r == '_' || r == '=' || r == '-' || r == '/' {
		return true
	}

	if allowHistoricalIDs {
		// NOTE: Allowing historical userIDs
		// https://spec.matrix.org/v1.4/appendices/#historical-user-ids
		if r >= 0x21 && r <= 0x39 {
			return true
		}
		if r >= 0x3B && r <= 0x7E {
			return true
		}
	}

	return false
}
