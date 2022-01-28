package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	errNoWellKnown = errors.New("No .well-known found")
)

const WellKnownMaxSize = 50 * 1024 // 50KB

// WellKnownResult is the result of looking up a matrix server's well-known file.
// Located at https://<server_name>/.well-known/matrix/server
type WellKnownResult struct {
	NewAddress     ServerName `json:"m.server"`
	CacheExpiresAt int64
}

// LookupWellKnown looks up a well-known record for a matrix server. If one if
// found, it returns the server to redirect to.
func LookupWellKnown(ctx context.Context, serverNameType ServerName) (*WellKnownResult, error) {
	serverName := string(serverNameType)

	// Handle ending "/"
	serverName = strings.TrimRight(serverName, "/")

	wellKnownPath := "/.well-known/matrix/server"

	// Request server's well-known record

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+serverName+wellKnownPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		return nil, errNoWellKnown
	}

	// If the remote server reports a Content-Length to us then make sure
	// that the well-known response size doesn't exceed WellKnownMaxSize.
	contentLengthHeader := resp.Header.Get("Content-Length")
	if l, err := strconv.Atoi(contentLengthHeader); err == nil && l > WellKnownMaxSize {
		return nil, fmt.Errorf("well-known content length %d exceeds %d bytes", l, WellKnownMaxSize)
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

	// By this point we hope that we've caught any huge well-known records
	// by checking Content-Length, but it's possible that header will be
	// missing. Better to be safe than sorry by reading no more than the
	// WellKnownMaxSize in any case.
	bodyBuffer := make([]byte, WellKnownMaxSize)
	limitedReader := &io.LimitedReader{
		R: resp.Body,
		N: WellKnownMaxSize,
	}
	n, err := limitedReader.Read(bodyBuffer)
	if err != nil && err != io.EOF {
		return nil, err
	}
	body := bodyBuffer[:n]

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
