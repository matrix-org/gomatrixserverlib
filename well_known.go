package gomatrixserverlib

import (
	"errors"
	json "github.com/json-iterator/go"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	errNoWellKnown = errors.New("No .well-known found")
)

// WellKnownResult is the result of looking up a matrix server's well-known file.
// Located at https://<server_name>/.well-known/matrix/server
type WellKnownResult struct {
	NewAddress     ServerName `json:"m.server"`
	CacheExpiresAt int64
}

// LookupWellKnown looks up a well-known record for a matrix server. If one if
// found, it returns the server to redirect to.
func LookupWellKnown(serverNameType ServerName) (*WellKnownResult, error) {
	serverName := string(serverNameType)

	// Handle ending "/"
	serverName = strings.TrimRight(serverName, "/")

	wellKnownPath := "/.well-known/matrix/server"

	// Request server's well-known record
	resp, err := http.Get("https://" + serverName + wellKnownPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		return nil, errNoWellKnown
	}

	// Figure out when the cache expiry time of this well-known record is
	cacheControlHeader := resp.Header.Get("Cache-Control")
	expiresHeader := resp.Header.Get("Expires")

	expiryTimestamp := int64(0)

	if expiresHeader != "" {
		// parse the HTTP-date (RFC7231 section 7.1.1.1)
		// Mon Jan 2 15:04:05 -0700 MST 2006
		referenceTimeFormat := "Mon, 02 Jan 2006 15:04:05 MST"
		expiresTime, err := time.Parse(referenceTimeFormat, expiresHeader)
		if err == nil {
			expiryTimestamp = expiresTime.Unix()
		}
	}

	// According to RFC7234 section 5.3, Cache-Control with max-age directive
	// MUST be preferred to Expires header.
	if cacheControlHeader != "" {
		kvPairs := strings.Split(cacheControlHeader, ",")
		for _, keyValuePair := range kvPairs {
			keyValuePair = strings.Trim(keyValuePair, " ")
			pieces := strings.SplitN(keyValuePair, "=", 2)
			if len(pieces) == 2 && strings.EqualFold(pieces[0], "max-age") {
				// max-age is the (maximum) number of seconds this record can
				// be assumed to live
				stringValue := pieces[1]
				age, err := strconv.ParseInt(stringValue, 10, 64)

				if err == nil {
					expiryTimestamp = age + time.Now().Unix()
				}
			}
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Convert result to JSON
	wellKnownResponse := &WellKnownResult{
		CacheExpiresAt: expiryTimestamp,
	}
	err = json.Unmarshal(body, wellKnownResponse)
	if err != nil {
		return nil, err
	}

	if wellKnownResponse.NewAddress == "" {
		return nil, errors.New("No m.server key found in well-known response")
	}

	// Return result
	return wellKnownResponse, nil
}
