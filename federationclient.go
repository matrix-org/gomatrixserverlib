package gomatrixserverlib

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// A FederationClient is a matrix federation client that adds
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
		Client:           *NewClient(),
		serverName:       serverName,
		serverKeyID:      keyID,
		serverPrivateKey: privateKey,
	}
}

// NewFederationClientWithTransport makes a new FederationClient with a custom
// transport.
func NewFederationClientWithTransport(
	serverName ServerName, keyID KeyID, privateKey ed25519.PrivateKey, transport *http.Transport,
) *FederationClient {
	return &FederationClient{
		Client:           *NewClientWithTransport(transport),
		serverName:       serverName,
		serverKeyID:      keyID,
		serverPrivateKey: privateKey,
	}
}

func (ac *FederationClient) doRequest(ctx context.Context, r FederationRequest, resBody interface{}) error {
	if err := r.Sign(ac.serverName, ac.serverKeyID, ac.serverPrivateKey); err != nil {
		return err
	}

	req, err := r.HTTPRequest()
	if err != nil {
		return err
	}

	return ac.Client.DoRequestAndParseResponse(ctx, req, resBody)
}

var federationPathPrefixV1 = "/_matrix/federation/v1"
var federationPathPrefixV2 = "/_matrix/federation/v2"

// SendTransaction sends a transaction
func (ac *FederationClient) SendTransaction(
	ctx context.Context, t Transaction,
) (res RespSend, err error) {
	path := federationPathPrefixV1 + "/send/" + string(t.TransactionID)
	req := NewFederationRequest("PUT", t.Destination, path)
	if err = req.SetContent(t); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// MakeJoin makes a join m.room.member event for a room on a remote matrix server.
// This is used to join a room the local server isn't a member of.
// We need to query a remote server because if we aren't in the room we don't
// know what to use for the "prev_events" in the join event.
// The remote server should return us a m.room.member event for our local user
// with the "prev_events" filled out.
// If this successfully returns an acceptable event we will sign it with our
// server's key and pass it to SendJoin.
// See https://matrix.org/docs/spec/server_server/unstable.html#joining-rooms
func (ac *FederationClient) MakeJoin(
	ctx context.Context, s ServerName, roomID, userID string,
	roomVersions []RoomVersion,
) (res RespMakeJoin, err error) {
	versionQueryString := ""
	if len(roomVersions) > 0 {
		var vqs []string
		for _, v := range roomVersions {
			vqs = append(vqs, fmt.Sprintf("ver=%s", v))
		}
		versionQueryString = "?" + strings.Join(vqs, "&")
	}
	path := federationPathPrefixV1 + "/make_join/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(userID) + versionQueryString
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendJoin sends a join m.room.member event obtained using MakeJoin via a
// remote matrix server.
// This is used to join a room the local server isn't a member of.
// See https://matrix.org/docs/spec/server_server/unstable.html#joining-rooms
func (ac *FederationClient) SendJoin(
	ctx context.Context, s ServerName, event Event,
) (res RespSendJoin, err error) {
	path := federationPathPrefixV2 + "/send_join/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// MakeLeave makes a leave m.room.member event for a room on a remote matrix server.
// This is used to reject a remote invite and is similar to MakeJoin.
// If this successfully returns an acceptable event we will sign it, replace
// the event_id with our own, and pass it to SendLeave.
// See https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-make-leave-roomid-userid
func (ac *FederationClient) MakeLeave(
	ctx context.Context, s ServerName, roomID, userID string,
) (res RespMakeLeave, err error) {
	path := federationPathPrefixV1 + "/make_leave/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(userID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendLeave sends a leave m.room.member event obtained using MakeLeave via a
// remote matrix server.
// This is used to reject a remote invite.
// See https://matrix.org/docs/spec/server_server/r0.1.1.html#put-matrix-federation-v1-send-leave-roomid-eventid
func (ac *FederationClient) SendLeave(
	ctx context.Context, s ServerName, event Event,
) (err error) {
	path := federationPathPrefixV2 + "/send_leave/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, nil)
	return
}

// SendInvite sends an invite m.room.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
func (ac *FederationClient) SendInvite(
	ctx context.Context, s ServerName, event Event,
) (res RespInvite, err error) {
	path := federationPathPrefixV1 + "/invite/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// ExchangeThirdPartyInvite sends the builder of a m.room.member event of
// "invite" membership derived from a response from invites sent by an identity
// server.
// This is used to exchange a m.room.third_party_invite event for a m.room.member
// one in a room the local server isn't a member of.
func (ac *FederationClient) ExchangeThirdPartyInvite(
	ctx context.Context, s ServerName, builder EventBuilder,
) (err error) {
	path := federationPathPrefixV1 + "/exchange_third_party_invite/" +
		url.PathEscape(builder.RoomID)
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(builder); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, nil)
	return
}

// LookupState retrieves the room state for a room at an event from a
// remote matrix server as full matrix events.
func (ac *FederationClient) LookupState(
	ctx context.Context, s ServerName, roomID, eventID string,
) (res RespState, err error) {
	path := federationPathPrefixV1 + "/state/" +
		url.PathEscape(roomID) +
		"?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupStateIDs retrieves the room state for a room at an event from a
// remote matrix server as lists of matrix event IDs.
func (ac *FederationClient) LookupStateIDs(
	ctx context.Context, s ServerName, roomID, eventID string,
) (res RespStateIDs, err error) {
	path := federationPathPrefixV1 + "/state_ids/" +
		url.PathEscape(roomID) +
		"?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupRoomAlias looks up a room alias hosted on the remote server.
// The domain part of the roomAlias must match the name of the server it is
// being looked up on.
// If the room alias doesn't exist on the remote server then a 404 gomatrix.HTTPError
// is returned.
func (ac *FederationClient) LookupRoomAlias(
	ctx context.Context, s ServerName, roomAlias string,
) (res RespDirectory, err error) {
	path := federationPathPrefixV1 + "/query/directory?room_alias=" +
		url.QueryEscape(roomAlias)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetPublicRooms gets all public rooms listed on the target homeserver's directory.
// Spec: https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-publicrooms
// thirdPartyInstanceID can only be non-empty if includeAllNetworks is false.
func (ac *FederationClient) GetPublicRooms(
	ctx context.Context, s ServerName, limit int, since string,
	includeAllNetworks bool, thirdPartyInstanceID string,
) (res RespPublicRooms, err error) {
	if includeAllNetworks && thirdPartyInstanceID != "" {
		panic("thirdPartyInstanceID can only be used if includeAllNetworks is false")
	}

	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("since", since)
	query.Set("include_all_networks", strconv.FormatBool(includeAllNetworks))
	if !includeAllNetworks {
		query.Set("third_party_instance_id", thirdPartyInstanceID)
	}

	u := url.URL{
		Path:     federationPathPrefixV1 + "/publicRooms",
		RawQuery: query.Encode(),
	}
	path := u.RequestURI()

	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupProfile queries the profile of a user.
// If field is empty, the server returns the full profile of the user.
// Otherwise, it must be one of: ["displayname", "avatar_url"], indicating
// which field of the profile should be returned.
// Spec: https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-query-profile
func (ac *FederationClient) LookupProfile(
	ctx context.Context, s ServerName, userID string, field string,
) (res RespProfile, err error) {
	path := federationPathPrefixV1 + "/query/profile?user_id=" +
		url.QueryEscape(userID)
	if field != "" {
		path += "&field=" + url.QueryEscape(field)
	}
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetEvent gets an event by ID from a remote server.
// See https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-event-eventid
func (ac *FederationClient) GetEvent(
	ctx context.Context, s ServerName, eventID string,
) (res Transaction, err error) {
	path := federationPathPrefixV1 + "/event/" + url.PathEscape(eventID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// Backfill asks a homeserver for events early enough for them to not be in the
// local database.
// See https://matrix.org/docs/spec/server_server/unstable.html#get-matrix-federation-v1-backfill-roomid
func (ac *FederationClient) Backfill(
	ctx context.Context, s ServerName, roomID string, limit int, eventIDs []string,
) (res Transaction, err error) {
	// Parse the limit into a string so that we can include it in the URL's query.
	limitStr := strconv.Itoa(limit)

	// Define the URL's query.
	query := url.Values{}
	query["v"] = eventIDs
	query.Set("limit", limitStr)

	// Use the url.URL structure to easily generate the request's URI (path?query).
	u := url.URL{
		Path:     "/_matrix/federation/v1/backfill/" + roomID,
		RawQuery: query.Encode(),
	}
	path := u.RequestURI()

	// Send the request.
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}
