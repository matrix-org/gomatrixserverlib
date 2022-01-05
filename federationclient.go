package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/matrix-org/gomatrix"
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

// NewFederationClient makes a new FederationClient. You can supply
// zero or more ClientOptions which control the transport, timeout,
// TLS validation etc - see WithTransport, WithTimeout, WithSkipVerify,
// WithDNSCache etc.
func NewFederationClient(
	serverName ServerName, keyID KeyID, privateKey ed25519.PrivateKey,
	options ...ClientOption,
) *FederationClient {
	return &FederationClient{
		Client:           *NewClient(options...),
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
			vqs = append(vqs, fmt.Sprintf("ver=%s", url.QueryEscape(string(v))))
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
	ctx context.Context, s ServerName, event *Event, roomVersion RoomVersion,
) (res RespSendJoin, err error) {
	res.roomVersion = roomVersion
	path := federationPathPrefixV2 + "/send_join/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	var intermediate struct {
		StateEvents []json.RawMessage `json:"state"`
		AuthEvents  []json.RawMessage `json:"auth_chain"`
		Origin      ServerName        `json:"origin"`
	}
	process := func() {
		res.StateEvents = make([]*Event, 0, len(intermediate.StateEvents))
		res.AuthEvents = make([]*Event, 0, len(intermediate.AuthEvents))
		res.Origin = intermediate.Origin
		for _, se := range intermediate.StateEvents {
			if ev, err := NewEventFromUntrustedJSON(se, roomVersion); err == nil {
				res.StateEvents = append(res.StateEvents, ev)
			}
		}
		for _, ae := range intermediate.AuthEvents {
			if ev, err := NewEventFromUntrustedJSON(ae, roomVersion); err == nil {
				res.AuthEvents = append(res.AuthEvents, ev)
			}
		}
	}
	if err = ac.doRequest(ctx, req, &intermediate); err == nil {
		process()
	}
	gerr, ok := err.(gomatrix.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		v1path := federationPathPrefixV1 + "/send_join/" +
			url.PathEscape(event.RoomID()) + "/" +
			url.PathEscape(event.EventID())
		v1req := NewFederationRequest("PUT", s, v1path)
		if err = v1req.SetContent(event); err != nil {
			return
		}
		var v1Res []json.RawMessage
		err = ac.doRequest(ctx, v1req, &v1Res)
		if err == nil && len(v1Res) == 2 {
			if err = json.Unmarshal(v1Res[1], &intermediate); err != nil {
				return
			}
			process()
		}
	}
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
	ctx context.Context, s ServerName, event *Event,
) (err error) {
	path := federationPathPrefixV2 + "/send_leave/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	res := struct{}{}
	err = ac.doRequest(ctx, req, &res)
	gerr, ok := err.(gomatrix.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		v1path := federationPathPrefixV1 + "/send_leave/" +
			url.PathEscape(event.RoomID()) + "/" +
			url.PathEscape(event.EventID())
		v1req := NewFederationRequest("PUT", s, v1path)
		if err = v1req.SetContent(event); err != nil {
			return
		}
		var v1Res []json.RawMessage
		err = ac.doRequest(ctx, v1req, &v1Res)
		if err == nil && len(v1Res) == 2 {
			err = json.Unmarshal(v1Res[1], &res)
		}
	}
	return
}

// SendInvite sends an invite m.room.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
func (ac *FederationClient) SendInvite(
	ctx context.Context, s ServerName, event *Event,
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

// SendInviteV2 sends an invite m.room.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
func (ac *FederationClient) SendInviteV2(
	ctx context.Context, s ServerName, request InviteV2Request,
) (res RespInviteV2, err error) {
	res.roomVersion = request.RoomVersion()
	event := request.Event()
	path := federationPathPrefixV2 + "/invite/" +
		url.PathEscape(event.RoomID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", s, path)
	if err = req.SetContent(request); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)

	gerr, ok := err.(gomatrix.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		var resp RespInvite
		resp, err = ac.SendInvite(ctx, s, request.Event())
		if err != nil {
			return
		}
		// assume v1 as per spec: https://matrix.org/docs/spec/server_server/latest#put-matrix-federation-v1-invite-roomid-eventid
		// Servers which receive a v1 invite request must assume that the room version is either "1" or "2".
		res = RespInviteV2{
			Event:       resp.Event,
			roomVersion: RoomVersionV1,
		}
	}
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
	res := struct{}{}
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupState retrieves the room state for a room at an event from a
// remote matrix server as full matrix events.
func (ac *FederationClient) LookupState(
	ctx context.Context, s ServerName, roomID, eventID string, roomVersion RoomVersion,
) (res RespState, err error) {
	res.roomVersion = roomVersion
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

// LookupMissingEvents asks a remote server for missing events within a
// given bracket.
// https://matrix.org/docs/spec/server_server/r0.1.3#post-matrix-federation-v1-get-missing-events-roomid
func (ac *FederationClient) LookupMissingEvents(
	ctx context.Context, s ServerName, roomID string,
	missing MissingEvents, roomVersion RoomVersion,
) (res RespMissingEvents, err error) {
	res.roomVersion = roomVersion
	path := federationPathPrefixV1 + "/get_missing_events/" +
		url.PathEscape(roomID)
	req := NewFederationRequest("POST", s, path)
	if err = req.SetContent(missing); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// Peek starts a peek on a remote server: see MSC2753
func (ac *FederationClient) Peek(
	ctx context.Context, s ServerName, roomID, peekID string,
	roomVersions []RoomVersion,
) (res RespPeek, err error) {
	versionQueryString := ""
	if len(roomVersions) > 0 {
		var vqs []string
		for _, v := range roomVersions {
			vqs = append(vqs, fmt.Sprintf("ver=%s", url.QueryEscape(string(v))))
		}
		versionQueryString = "?" + strings.Join(vqs, "&")
	}
	path := federationPathPrefixV1 + "/peek/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(peekID) + versionQueryString
	req := NewFederationRequest("PUT", s, path)
	var empty struct{}
	if err = req.SetContent(empty); err != nil {
		return
	}
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

// ClaimKeys claims E2E one-time keys from a remote server.
// `oneTimeKeys` are the keys to be claimed. A map from user ID, to a map from device ID to algorithm name. E.g:
//    {
//      "@alice:example.com": {
//        "JLAFKJWSCS": "signed_curve25519"
//      }
//    }
// https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-claim
func (ac *FederationClient) ClaimKeys(ctx context.Context, s ServerName, oneTimeKeys map[string]map[string]string) (res RespClaimKeys, err error) {
	path := federationPathPrefixV1 + "/user/keys/claim"
	req := NewFederationRequest("POST", s, path)
	if err = req.SetContent(map[string]interface{}{
		"one_time_keys": oneTimeKeys,
	}); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// QueryKeys queries E2E device keys from a remote server.
// https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-query
func (ac *FederationClient) QueryKeys(ctx context.Context, s ServerName, keys map[string][]string) (res RespQueryKeys, err error) {
	path := federationPathPrefixV1 + "/user/keys/query"
	req := NewFederationRequest("POST", s, path)
	if err = req.SetContent(map[string]interface{}{
		"device_keys": keys,
	}); err != nil {
		return
	}
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

// GetEventAuth gets an event auth chain from a remote server.
// See https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-event-auth-roomid-eventid
func (ac *FederationClient) GetEventAuth(
	ctx context.Context, s ServerName, roomVersion RoomVersion, roomID, eventID string,
) (res RespEventAuth, err error) {
	res.roomVersion = roomVersion
	path := federationPathPrefixV1 + "/event_auth/" + url.PathEscape(roomID) + "/" + url.PathEscape(eventID)
	req := NewFederationRequest("GET", s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetUserDevices returns a list of the user's devices from a remote server.
// See https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-user-devices-userid
func (ac *FederationClient) GetUserDevices(
	ctx context.Context, s ServerName, userID string,
) (res RespUserDevices, err error) {
	path := federationPathPrefixV1 + "/user/devices/" + url.PathEscape(userID)
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

// MSC2836EventRelationships performs an MSC2836 /event_relationships request.
func (ac *FederationClient) MSC2836EventRelationships(
	ctx context.Context, dst ServerName, r MSC2836EventRelationshipsRequest, roomVersion RoomVersion,
) (res MSC2836EventRelationshipsResponse, err error) {
	res.roomVersion = roomVersion
	path := "/_matrix/federation/unstable/event_relationships"
	req := NewFederationRequest("POST", dst, path)
	if err = req.SetContent(r); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

func (ac *FederationClient) MSC2946Spaces(
	ctx context.Context, dst ServerName, roomID string, r MSC2946SpacesRequest,
) (res MSC2946SpacesResponse, err error) {
	path := "/_matrix/federation/unstable/org.matrix.msc2946/spaces/" + url.PathEscape(roomID)
	req := NewFederationRequest("POST", dst, path)
	if err = req.SetContent(r); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}
