/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

// Event validation errors
const (
	EventValidationTooLarge int = 1
)

// EventValidationError is returned if there is a problem validating an event
type EventValidationError struct {
	Message     string
	Code        int
	Persistable bool
}

func (e EventValidationError) Error() string {
	return e.Message
}

type eventFields struct {
	RoomID         string         `json:"room_id"`
	SenderID       string         `json:"sender"`
	Type           string         `json:"type"`
	StateKey       *string        `json:"state_key"`
	Content        spec.RawJSON   `json:"content"`
	Redacts        string         `json:"redacts"`
	Depth          int64          `json:"depth"`
	Unsigned       spec.RawJSON   `json:"unsigned,omitempty"`
	OriginServerTS spec.Timestamp `json:"origin_server_ts"`
	//Origin         spec.ServerName `json:"origin"`
}

var emptyEventReferenceList = []eventReference{}

const (
	// The event ID, room ID, sender, event type and state key fields cannot be
	// bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L173-L182
	maxIDLength = 255
	// The entire event JSON, including signatures cannot be bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L183-184
	maxEventLength = 65536
)

func checkID(id, kind string, sigil byte) (err error) {
	if _, err = domainFromID(id); err != nil {
		return
	}
	if id[0] != sigil {
		err = fmt.Errorf(
			"gomatrixserverlib: invalid %s ID, wanted first byte to be '%c' got '%c'",
			kind, sigil, id[0],
		)
		return
	}
	if l := utf8.RuneCountInString(id); l > maxIDLength {
		err = EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: %s ID is too long, length %d > maximum %d", kind, l, maxIDLength),
		}
		return
	}
	if l := len(id); l > maxIDLength {
		err = EventValidationError{
			Code:        EventValidationTooLarge,
			Message:     fmt.Sprintf("gomatrixserverlib: %s ID is too long, length %d bytes > maximum %d bytes", kind, l, maxIDLength),
			Persistable: true,
		}
		return
	}
	return
}

// SplitID splits a matrix ID into a local part and a server name.
func SplitID(sigil byte, id string) (local string, domain spec.ServerName, err error) {
	// IDs have the format: SIGIL LOCALPART ":" DOMAIN
	// Split on the first ":" character since the domain can contain ":"
	// characters.
	if len(id) == 0 || id[0] != sigil {
		return "", "", fmt.Errorf("gomatrixserverlib: invalid ID %q doesn't start with %q", id, sigil)
	}
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		// The ID must have a ":" character.
		return "", "", fmt.Errorf("gomatrixserverlib: invalid ID %q missing ':'", id)
	}
	return parts[0][1:], spec.ServerName(parts[1]), nil
}
