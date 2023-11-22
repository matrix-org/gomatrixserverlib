package spec

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

// Creates a new UserID, returning an error if invalid
func NewUserID(id string, allowHistoricalIDs bool) (*UserID, error) {
	return parseAndValidateUserID(id, allowHistoricalIDs)
}

// Creates a new UserID, panicing if invalid
func NewUserIDOrPanic(id string, allowHistoricalIDs bool) UserID {
	userID, err := parseAndValidateUserID(id, allowHistoricalIDs)
	if err != nil {
		panic(fmt.Sprintf("NewUserIDOrPanic failed: invalid user ID %s: %s", id, err.Error()))
	}
	return *userID
}

// Returns the full userID string including leading sigil
func (user *UserID) String() string {
	return user.raw
}

// Returns just the localpart of the userID
func (user *UserID) Local() string {
	return user.local
}

// Returns just the domain of the userID
func (user *UserID) Domain() ServerName {
	return ServerName(user.domain)
}

func parseAndValidateUserID(id string, allowHistoricalIDs bool) (*UserID, error) {
	idLength := len(id)
	if idLength < 4 || idLength > 255 { // 4 since minimum userID includes an @, :, non-empty localpart, non-empty domain
		return nil, fmt.Errorf("length %d is not within the bounds 4-255", idLength)
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
