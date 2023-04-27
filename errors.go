package gomatrixserverlib

import (
	"fmt"

	"github.com/matrix-org/gomatrixserverlib/spec"
)

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

// FederationError contains context surrounding why a federation request may have failed.
type FederationError struct {
	ServerName spec.ServerName // The server being contacted.
	Transient  bool            // Whether the failure is permanent (will fail if performed again) or not.
	Reachable  bool            // Whether the server could be contacted.
	Err        error           // The underlying error message.
}

func (e FederationError) Error() string {
	return fmt.Sprintf("FederationError(t=%v, r=%v): %s", e.Transient, e.Reachable, e.Err.Error())
}
