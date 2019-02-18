package gomatrixserverlib

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

// WellKnownResult is the result of looking up a matrix server's well-known file.
// Located at https://<server_name>/.well-known/matrix/server
type WellKnownResult struct {
	NewAddress ServerName `json:"m.server"`
}

// LookupWellKnown looks up a well-known record for a matrix server. If one if
// found, it returns the server to redirect to. It also returns a boolean which
// value is true if a well-known record was found, false otherwise.
func LookupWellKnown(serverNameType ServerName) (*WellKnownResult, bool, error) {
	serverName := string(serverNameType)

	// Handle ending "/"
	strings.Trim(serverName, "/")

	wellKnownPath := "/.well-known/matrix/server"
	wellKnown := "https://" + serverName + wellKnownPath

	// Request server's well-known record
	resp, err := http.Get(wellKnown)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, false, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, true, err
	}

	// Convert result to JSON
	wellKnownResponse := &WellKnownResult{}
	err = json.Unmarshal(body, wellKnownResponse)
	if err != nil {
		return nil, true, err
	}

	// Return result
	return wellKnownResponse, true, nil
}
