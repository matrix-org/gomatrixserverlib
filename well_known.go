package gomatrixserverlib

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

// WellKnownResult is the result of looking up a matrix server's well-known file.
// Located at https://<server_name>/.well-known/matrix/server
type WellKnownResult struct {
	NewAddress ServerName `json:"m.server"`
	Error      string     `json:"Error,omitempty"`
}

// LookupWellKnown looks up a well-known record for a matrix server. If one if
// found, it returns the server to redirect to.
func LookupWellKnown(serverNameType ServerName) (WellKnownResult, error) {
	serverName := string(serverNameType)

	// Handle ending "/"
	strings.Trim(serverName, "/")

	wellKnownPath := "/.well-known/matrix/server"
	wellKnown := "https://" + serverName + wellKnownPath

	// Request server's well-known record
	resp, err := http.Get(wellKnown)
	if err != nil {
		return WellKnownResult{Error: err.Error()}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		err = errors.New("No .well-known found")
		return WellKnownResult{Error: err.Error()}, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return WellKnownResult{Error: err.Error()}, err
	}

	// Convert result to JSON
	wellKnownResponse := &WellKnownResult{}
	err = json.Unmarshal(body, wellKnownResponse)
	if err != nil {
		wellKnownResponse.Error = err.Error()
		return *wellKnownResponse, err
	}

	// Return result
	return *wellKnownResponse, nil
}
