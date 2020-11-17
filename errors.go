package gomatrixserverlib

import "fmt"

// MissingAuthEventError refers to a situation where one of the auth
// event for a given event was not found.
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

type BadJSONError struct {
	err error
}

func (e BadJSONError) Error() string {
	return fmt.Sprintf("gomatrixserverlib: bad JSON: %s", e.err.Error())
}

func (e BadJSONError) Unwrap() error {
	return e.err
}
