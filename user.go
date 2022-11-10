package gomatrixserverlib

import (
	"fmt"
	"regexp"
	"strings"
)

const userSigil = '@'
const localDomainSeparator = ':'

var validUsernameRegex = regexp.MustCompile(`^[0-9a-z_\-=./]+$`)

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

	if allowHistoricalIDs {
		// NOTE: Allowed historical userIDs:
		// https://spec.matrix.org/v1.4/appendices/#historical-user-ids
		if !historicallyValidCharacters(localpart) {
			return nil, fmt.Errorf("local part contains invalid characters from historical set")
		}
	} else {
		// NOTE: Allowed in the latest spec:
		// https://spec.matrix.org/v1.4/appendices/#user-identifiers
		if !validUsernameRegex.MatchString(localpart) {
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

func historicallyValidCharacters(localpart string) bool {
	for _, r := range localpart {
		if r < 0x21 || r == 0x3A || r > 0x7E {
			return false
		}
	}

	return true
}
