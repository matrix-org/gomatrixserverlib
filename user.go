package gomatrixserverlib

import (
	"fmt"
	"strings"
)

// A UserID identifies a matrix user as per the matrix specification:
// https://spec.matrix.org/v1.4/appendices/#user-identifiers
type UserID struct {
	raw    string
	local  string
	domain string
}

func NewUserID(id string) (*UserID, error) {
	return parseAndValidateUserID(id)
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

func parseAndValidateUserID(id string) (*UserID, error) {
	idLength := len(id)
	if idLength < 1 || idLength > 255 {
		return nil, fmt.Errorf("length %d is not within the bounds 1-255", idLength)
	}
	if string(id[0]) != "@" {
		return nil, fmt.Errorf("first character is not '@'")
	}

	idParts := strings.Split(id[1:], ":")
	if len(idParts) < 2 {
		return nil, fmt.Errorf("at least one ':' is expected in the user id")
	}
	if _, _, ok := ParseAndValidateServerName(ServerName(idParts[1])); !ok {
		return nil, fmt.Errorf("domain is invalid")
	}

	for _, r := range idParts[0] {
		if !isLocalUserIDChar(r) {
			return nil, fmt.Errorf("local part contains invalid characters")
		}
	}

	colonIndex := strings.Index(id, ":")
	userID := &UserID{
		raw:    id,
		local:  id[1:colonIndex],
		domain: id[colonIndex+1:],
	}
	return userID, nil
}

func isLocalUserIDChar(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	if r == '.' || r == '_' || r == '=' || r == '-' || r == '/' {
		return true
	}
	return false
}
