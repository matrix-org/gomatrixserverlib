package spec

import (
	"fmt"
	"strings"
)

const roomSigil = '!'

// A RoomID identifies a matrix room as per the matrix specification
// https://spec.matrix.org/v1.6/appendices/#room-ids-and-event-ids
type RoomID struct {
	raw      string
	opaqueID string
	domain   string
}

func NewRoomID(id string) (*RoomID, error) {
	return parseAndValidateRoomID(id)
}

// Returns the full roomID string including leading sigil
func (room RoomID) String() string {
	return room.raw
}

// Returns just the localpart of the roomID
func (room RoomID) OpaqueID() string {
	return room.opaqueID
}

// Returns just the domain of the roomID
func (room RoomID) Domain() ServerName {
	return ServerName(room.domain)
}

func parseAndValidateRoomID(id string) (*RoomID, error) {
	// NOTE: There is no length limit for room ids
	idLength := len(id)
	if idLength < 4 { // 4 since minimum roomID includes an !, :, non-empty opaque ID, non-empty domain
		return nil, fmt.Errorf("length %d is too short to be valid", idLength)
	}

	if id[0] != roomSigil {
		return nil, fmt.Errorf("first character is not '%c'", roomSigil)
	}

	opaqueID, domain, found := strings.Cut(id[1:], string(localDomainSeparator))
	if !found {
		return nil, fmt.Errorf("at least one '%c' is expected in the room id", localDomainSeparator)
	}
	if _, _, ok := ParseAndValidateServerName(ServerName(domain)); !ok {
		return nil, fmt.Errorf("domain is invalid")
	}

	// NOTE: There are no character limitations on the opaque part of room ids
	opaqueLength := len(opaqueID)
	if opaqueLength < 1 {
		return nil, fmt.Errorf("opaque id length %d is too short to be valid", opaqueLength)
	}

	roomID := &RoomID{
		raw:      id,
		opaqueID: opaqueID,
		domain:   domain,
	}
	return roomID, nil
}
