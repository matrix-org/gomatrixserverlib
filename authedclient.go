package gomatrixserverlib

import (
	"encoding/json"
	"github.com/matrix-org/gomatrix"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"net/http"
	"net/url"
)

// An FederationClient is a matrix federation client that adds
// "Authorization: X-Matrix" headers to requests that need ed25519 signatures
type FederationClient struct {
	Client
	serverName       ServerName
	serverKeyID      KeyID
	serverPrivateKey ed25519.PrivateKey
}

// NewFederationClient makes a new FederationClient
func NewFederationClient(
	serverName ServerName, keyID KeyID, privateKey ed25519.PrivateKey,
) *FederationClient {
	return &FederationClient{
		Client:           Client{client: http.Client{Transport: newFederationTripper()}},
		serverName:       serverName,
		serverKeyID:      keyID,
		serverPrivateKey: privateKey,
	}
}

func (ac *FederationClient) doRequest(r FederationRequest, resBody interface{}) error {
	if err := r.Sign(ac.serverName, ac.serverKeyID, ac.serverPrivateKey); err != nil {
		return err
	}

	req, err := r.HTTPRequest()
	if err != nil {
		return err
	}

	res, err := ac.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}

	if err != nil {
		return err
	}

	contents, err := ioutil.ReadAll(res.Body)
	if res.StatusCode/100 != 2 { // not 2xx
		// Adapted from https://github.com/matrix-org/gomatrix/blob/master/client.go
		var wrap error
		var respErr gomatrix.RespError
		if _ = json.Unmarshal(contents, &respErr); respErr.ErrCode != "" {
			wrap = respErr
		}

		// If we failed to decode as RespError, don't just drop the HTTP body, include it in the
		// HTTP error instead (e.g proxy errors which return HTML).
		msg := "Failed to " + r.Method() + " JSON to " + r.RequestURI()
		if wrap == nil {
			msg = msg + ": " + string(contents)
		}

		return gomatrix.HTTPError{
			Code:         res.StatusCode,
			Message:      msg,
			WrappedError: wrap,
		}
	}

	if err != nil {
		return err
	}

	return json.Unmarshal(contents, resBody)
}

// SendTransaction sends a transaction
func (ac *FederationClient) SendTransaction(t Transaction) (res SendResponse, err error) {
	path := "/_matrix/federation/v1/send/" + string(t.TransactionID) + "/"
	req := NewFederationRequest("PUT", t.Destination, path)
	if err = req.SetContent(SendRequest(t)); err != nil {
		return
	}
	err = ac.doRequest(req, &res)
	return
}

// MakeJoin makes a join m.room.member event for a room on a remote matrix server.
// This is used to join a room the local server isn't a member of.
func (ac *FederationClient) MakeJoin(s ServerName, roomID, userID string) (res MakeJoinResponse, err error) {
	path := "/_matrix/federation/v1/make_join/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(userID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(req, &res)
	return
}

// SendJoin sends a join m.room.member event via a remote matrix server.
// This is used to join a room the local server isn't a member of.
func (ac *FederationClient) SendJoin(s ServerName, event Event) (res SendJoinResponse, err error) {
	path := "/_matrix/federation/v1/send_join/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(req, &res)
	return
}

// LookupState retrieves the room state for a room at an event from a
// remote matrix server as full matrix events.
func (ac *FederationClient) LookupState(s ServerName, roomID, eventID string) (res StateResponse, err error) {
	path := "/_matrix/federation/v1/state/" +
		url.PathEscape(roomID) +
		"/?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(req, &res)
	return
}

// LookupStateIDs retrieves the room state for a room at an event from a
// remote matrix server as lists of matrix event IDs.
func (ac *FederationClient) LookupStateIDs(s ServerName, roomID, eventID string) (res StateIDsResponse, err error) {
	path := "/_matrix/federation/v1/state_ids/" +
		url.PathEscape(roomID) +
		"/?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(req, &res)
	return
}
