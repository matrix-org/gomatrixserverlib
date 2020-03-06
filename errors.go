package gomatrixserverlib

import "fmt"

type MissingAuthEventError struct {
	AuthEventID string
	ForEventID  string
}

func (e MissingAuthEventError) Error() string {
	return fmt.Sprintf(
		"gomatrixserverlib: missing auth event with ID %s for event %s",
		e.AuthEventID, e.ForEventID,
	)
}
