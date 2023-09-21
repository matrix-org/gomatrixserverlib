package fclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/matrix-org/gomatrix"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"golang.org/x/crypto/ed25519"
)

// an interface for gmsl.FederationClient - contains functions called by federationapi only.
type FederationClient interface {
	gomatrixserverlib.KeyClient

	DoRequestAndParseResponse(ctx context.Context, req *http.Request, result interface{}) error

	SendTransaction(ctx context.Context, t gomatrixserverlib.Transaction) (res RespSend, err error)

	// Perform operations
	LookupRoomAlias(ctx context.Context, origin, s spec.ServerName, roomAlias string) (res RespDirectory, err error)
	Peek(ctx context.Context, origin, s spec.ServerName, roomID, peekID string, roomVersions []gomatrixserverlib.RoomVersion) (res RespPeek, err error)
	MakeJoin(ctx context.Context, origin, s spec.ServerName, roomID, userID string) (res RespMakeJoin, err error)
	SendJoin(ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU) (res RespSendJoin, err error)
	SendJoinPartialState(ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU) (res RespSendJoin, err error)
	MakeLeave(ctx context.Context, origin, s spec.ServerName, roomID, userID string) (res RespMakeLeave, err error)
	SendLeave(ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU) (err error)
	SendInviteV2(ctx context.Context, origin, s spec.ServerName, request InviteV2Request) (res RespInviteV2, err error)
	SendInviteV3(ctx context.Context, origin, s spec.ServerName, request InviteV3Request, userID spec.UserID) (res RespInviteV2, err error)
	MakeKnock(ctx context.Context, origin, s spec.ServerName, roomID, userID string, roomVersions []gomatrixserverlib.RoomVersion) (res RespMakeKnock, err error)
	SendKnock(ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU) (res RespSendKnock, err error)

	GetEvent(ctx context.Context, origin, s spec.ServerName, eventID string) (res gomatrixserverlib.Transaction, err error)

	GetEventAuth(ctx context.Context, origin, s spec.ServerName, roomVersion gomatrixserverlib.RoomVersion, roomID, eventID string) (res RespEventAuth, err error)
	GetUserDevices(ctx context.Context, origin, s spec.ServerName, userID string) (RespUserDevices, error)
	ClaimKeys(ctx context.Context, origin, s spec.ServerName, oneTimeKeys map[string]map[string]string) (RespClaimKeys, error)
	QueryKeys(ctx context.Context, origin, s spec.ServerName, keys map[string][]string) (RespQueryKeys, error)
	Backfill(ctx context.Context, origin, s spec.ServerName, roomID string, limit int, eventIDs []string) (res gomatrixserverlib.Transaction, err error)
	MSC2836EventRelationships(ctx context.Context, origin, dst spec.ServerName, r MSC2836EventRelationshipsRequest, roomVersion gomatrixserverlib.RoomVersion) (res MSC2836EventRelationshipsResponse, err error)
	RoomHierarchy(ctx context.Context, origin, dst spec.ServerName, roomID string, suggestedOnly bool) (res RoomHierarchyResponse, err error)

	ExchangeThirdPartyInvite(ctx context.Context, origin, s spec.ServerName, builder gomatrixserverlib.ProtoEvent) (err error)
	LookupState(ctx context.Context, origin, s spec.ServerName, roomID string, eventID string, roomVersion gomatrixserverlib.RoomVersion) (res RespState, err error)
	LookupStateIDs(ctx context.Context, origin, s spec.ServerName, roomID string, eventID string) (res RespStateIDs, err error)
	LookupMissingEvents(ctx context.Context, origin, s spec.ServerName, roomID string, missing MissingEvents, roomVersion gomatrixserverlib.RoomVersion) (res RespMissingEvents, err error)

	GetPublicRooms(
		ctx context.Context, origin, s spec.ServerName, limit int, since string,
		includeAllNetworks bool, thirdPartyInstanceID string,
	) (res RespPublicRooms, err error)
	GetPublicRoomsFiltered(
		ctx context.Context, origin, s spec.ServerName, limit int, since, filter string,
		includeAllNetworks bool, thirdPartyInstanceID string,
	) (res RespPublicRooms, err error)

	LookupProfile(
		ctx context.Context, origin, s spec.ServerName, userID string, field string,
	) (res RespProfile, err error)

	P2PSendTransactionToRelay(ctx context.Context, u spec.UserID, t gomatrixserverlib.Transaction, forwardingServer spec.ServerName) (res EmptyResp, err error)
	P2PGetTransactionFromRelay(ctx context.Context, u spec.UserID, prev RelayEntry, relayServer spec.ServerName) (res RespGetRelayTransaction, err error)
}

// A FederationClient is a matrix federation client that adds
// "Authorization: X-Matrix" headers to requests that need ed25519 signatures
type federationClient struct {
	Client
	identities []*SigningIdentity
}

type SigningIdentity struct {
	// YAML annotations so it can be used directly in Dendrite config.
	ServerName spec.ServerName         `yaml:"server_name"`
	KeyID      gomatrixserverlib.KeyID `yaml:"key_id"`
	PrivateKey ed25519.PrivateKey      `yaml:"-"`
}

// NewFederationClient makes a new FederationClient. You can supply
// zero or more ClientOptions which control the transport, timeout,
// TLS validation etc - see WithTransport, WithTimeout, WithSkipVerify,
// WithDNSCache etc.
func NewFederationClient(
	identities []*SigningIdentity,
	options ...ClientOption,
) FederationClient {
	return &federationClient{
		Client: *NewClient(
			append(options, WithWellKnownSRVLookups(true))...,
		),
		identities: append([]*SigningIdentity{}, identities...),
	}
}

func (ac *federationClient) DoRequestAndParseResponse(ctx context.Context, req *http.Request, result interface{}) error {
	return ac.Client.DoRequestAndParseResponse(ctx, req, result)
}

func (ac *federationClient) doRequest(ctx context.Context, r FederationRequest, resBody interface{}) error {
	var identity *SigningIdentity
	for _, id := range ac.identities {
		if id.ServerName == r.Origin() {
			identity = id
			break
		}
	}
	if identity == nil {
		return fmt.Errorf("no signing identity for server name %q", r.Origin())
	}
	if err := r.Sign(identity.ServerName, identity.KeyID, identity.PrivateKey); err != nil {
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
var federationPathPrefixV3 = "/_matrix/federation/v3"

// SendTransaction sends a transaction
func (ac *federationClient) SendTransaction(
	ctx context.Context, t gomatrixserverlib.Transaction,
) (res RespSend, err error) {
	path := federationPathPrefixV1 + "/send/" + string(t.TransactionID)
	req := NewFederationRequest("PUT", t.Origin, t.Destination, path)
	if err = req.SetContent(t); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// P2PSendTransactionToRelay sends a transaction for forwarding to the destination.
func (ac *federationClient) P2PSendTransactionToRelay(
	ctx context.Context, u spec.UserID, t gomatrixserverlib.Transaction, forwardingServer spec.ServerName,
) (res EmptyResp, err error) {
	path := federationPathPrefixV1 + "/send_relay/" +
		string(t.TransactionID) + "/" +
		url.PathEscape(u.String())
	req := NewFederationRequest("PUT", t.Origin, forwardingServer, path)
	if err = req.SetContent(t); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// P2PGetTransactionFromRelay requests a transaction from a relay destined for this server.
func (ac *federationClient) P2PGetTransactionFromRelay(
	ctx context.Context, u spec.UserID, prev RelayEntry, relayServer spec.ServerName,
) (res RespGetRelayTransaction, err error) {
	path := federationPathPrefixV1 + "/relay_txn/" + url.PathEscape(u.String())
	req := NewFederationRequest("GET", u.Domain(), relayServer, path)
	if err = req.SetContent(prev); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// Creates a version query string with all the specified room versions, typically
// the list of all supported room versions.
// Needed when making a /make_knock or /make_join request.
func makeVersionQueryString(roomVersions []gomatrixserverlib.RoomVersion) string {
	versionQueryString := ""
	if len(roomVersions) > 0 {
		vqs := make([]string, 0, len(roomVersions))
		for _, v := range roomVersions {
			vqs = append(vqs, fmt.Sprintf("ver=%s", url.QueryEscape(string(v))))
		}
		versionQueryString = "?" + strings.Join(vqs, "&")
	}
	return versionQueryString
}

// Takes the map of room version implementations and converts it into a list of
// room version strings.
func roomVersionsToList(
	versionsMap map[gomatrixserverlib.RoomVersion]gomatrixserverlib.IRoomVersion,
) []gomatrixserverlib.RoomVersion {
	var supportedVersions []gomatrixserverlib.RoomVersion
	for version := range versionsMap {
		supportedVersions = append(supportedVersions, version)
	}
	return supportedVersions
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
func (ac *federationClient) MakeJoin(
	ctx context.Context, origin, s spec.ServerName, roomID, userID string,
) (res RespMakeJoin, err error) {
	roomVersions := roomVersionsToList(gomatrixserverlib.RoomVersions())
	versionQueryString := makeVersionQueryString(roomVersions)
	path := federationPathPrefixV1 + "/make_join/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(userID) + versionQueryString
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendJoin sends a join m.room.member event obtained using MakeJoin via a
// remote matrix server.
// This is used to join a room the local server isn't a member of.
// See https://matrix.org/docs/spec/server_server/unstable.html#joining-rooms
func (ac *federationClient) SendJoin(
	ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU,
) (res RespSendJoin, err error) {
	return ac.sendJoin(ctx, origin, s, event, false)
}

// SendJoinPartialState sends a join m.room.member event obtained using MakeJoin via a
// remote matrix server, with a parameter indicating we support partial state in
// the response.
// This is used to join a room the local server isn't a member of.
// See https://matrix.org/docs/spec/server_server/unstable.html#joining-rooms
func (ac *federationClient) SendJoinPartialState(
	ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU,
) (res RespSendJoin, err error) {
	return ac.sendJoin(ctx, origin, s, event, true)
}

// sendJoin is an internal implementation shared between SendJoin and SendJoinPartialState
func (ac *federationClient) sendJoin(
	ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU, partialState bool,
) (res RespSendJoin, err error) {
	path := federationPathPrefixV2 + "/send_join/" +
		url.PathEscape(event.RoomID().String()) + "/" +
		url.PathEscape(event.EventID())
	if partialState {
		path += "?omit_members=true"
	}

	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	gerr, ok := err.(gomatrix.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		v1path := federationPathPrefixV1 + "/send_join/" +
			url.PathEscape(event.RoomID().String()) + "/" +
			url.PathEscape(event.EventID())
		v1req := NewFederationRequest("PUT", origin, s, v1path)
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

// MakeKnock makes a join m.room.member event for a room on a remote matrix server.
// This is used to knock upon a room the local server isn't a member of.
// We need to query a remote server because if we aren't in the room we don't
// know what to use for the `prev_events` and `auth_events` in the knock event.
// The remote server should return us a populated m.room.member event for our local user.
// If this successfully returns an acceptable event we will sign it with our
// server's key and pass it to SendKnock.
// See https://spec.matrix.org/v1.3/server-server-api/#knocking-upon-a-room
func (ac *federationClient) MakeKnock(
	ctx context.Context, origin, s spec.ServerName, roomID, userID string,
	roomVersions []gomatrixserverlib.RoomVersion,
) (res RespMakeKnock, err error) {
	versionQueryString := makeVersionQueryString(roomVersions)
	path := federationPathPrefixV1 + "/make_knock/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(userID) + versionQueryString
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendKnock sends a join m.room.member event obtained using MakeKnock via a
// remote matrix server.
// This is used to ask to join a room the local server isn't a member of.
// See https://spec.matrix.org/v1.3/server-server-api/#knocking-upon-a-room
func (ac *federationClient) SendKnock(
	ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU,
) (res RespSendKnock, err error) {
	path := federationPathPrefixV1 + "/send_knock/" +
		url.PathEscape(event.RoomID().String()) + "/" +
		url.PathEscape(event.EventID())

	req := NewFederationRequest("PUT", origin, s, path)
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
func (ac *federationClient) MakeLeave(
	ctx context.Context, origin, s spec.ServerName, roomID, userID string,
) (res RespMakeLeave, err error) {
	path := federationPathPrefixV1 + "/make_leave/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(userID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendLeave sends a leave m.room.member event obtained using MakeLeave via a
// remote matrix server.
// This is used to reject a remote invite.
// See https://matrix.org/docs/spec/server_server/r0.1.1.html#put-matrix-federation-v1-send-leave-roomid-eventid
func (ac *federationClient) SendLeave(
	ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU,
) (err error) {
	path := federationPathPrefixV2 + "/send_leave/" +
		url.PathEscape(event.RoomID().String()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	res := struct{}{}
	err = ac.doRequest(ctx, req, &res)
	gerr, ok := err.(gomatrix.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		v1path := federationPathPrefixV1 + "/send_leave/" +
			url.PathEscape(event.RoomID().String()) + "/" +
			url.PathEscape(event.EventID())
		v1req := NewFederationRequest("PUT", origin, s, v1path)
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
func (ac *federationClient) SendInvite(
	ctx context.Context, origin, s spec.ServerName, event gomatrixserverlib.PDU,
) (res RespInvite, err error) {
	path := federationPathPrefixV1 + "/invite/" +
		url.PathEscape(event.RoomID().String()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendInviteV2 sends an invite m.room.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
func (ac *federationClient) SendInviteV2(
	ctx context.Context, origin, s spec.ServerName, request InviteV2Request,
) (res RespInviteV2, err error) {
	event := request.Event()
	path := federationPathPrefixV2 + "/invite/" +
		url.PathEscape(event.RoomID().String()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(request); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)

	gerr, ok := err.(gomatrix.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		var resp RespInvite
		resp, err = ac.SendInvite(ctx, origin, s, request.Event())
		if err != nil {
			return
		}
		// assume v1 as per spec: https://matrix.org/docs/spec/server_server/latest#put-matrix-federation-v1-invite-roomid-eventid
		// Servers which receive a v1 invite request must assume that the room version is either "1" or "2".
		res = RespInviteV2{ // nolint:gosimple
			Event: resp.Event,
		}
	}
	return
}

// SendInviteV3 sends an invite m.room.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
// V3 sends a partial event to allow the invitee to populate the mxid_mapping.
func (ac *federationClient) SendInviteV3(
	ctx context.Context, origin, s spec.ServerName, request InviteV3Request, userID spec.UserID,
) (res RespInviteV2, err error) {
	path := federationPathPrefixV3 + "/invite/" +
		url.PathEscape(request.Event().RoomID) + "/" +
		url.PathEscape(userID.String())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(request); err != nil {
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
func (ac *federationClient) ExchangeThirdPartyInvite(
	ctx context.Context, origin, s spec.ServerName, proto gomatrixserverlib.ProtoEvent,
) (err error) {
	path := federationPathPrefixV1 + "/exchange_third_party_invite/" +
		url.PathEscape(proto.RoomID)
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(proto); err != nil {
		return
	}
	res := struct{}{}
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupState retrieves the room state for a room at an event from a
// remote matrix server as full matrix events.
func (ac *federationClient) LookupState(
	ctx context.Context, origin, s spec.ServerName, roomID, eventID string, roomVersion gomatrixserverlib.RoomVersion,
) (res RespState, err error) {
	path := federationPathPrefixV1 + "/state/" +
		url.PathEscape(roomID) +
		"?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupStateIDs retrieves the room state for a room at an event from a
// remote matrix server as lists of matrix event IDs.
func (ac *federationClient) LookupStateIDs(
	ctx context.Context, origin, s spec.ServerName, roomID, eventID string,
) (res RespStateIDs, err error) {
	path := federationPathPrefixV1 + "/state_ids/" +
		url.PathEscape(roomID) +
		"?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupMissingEvents asks a remote server for missing events within a
// given bracket.
// https://matrix.org/docs/spec/server_server/r0.1.3#post-matrix-federation-v1-get-missing-events-roomid
func (ac *federationClient) LookupMissingEvents(
	ctx context.Context, origin, s spec.ServerName, roomID string,
	missing MissingEvents, roomVersion gomatrixserverlib.RoomVersion,
) (res RespMissingEvents, err error) {
	path := federationPathPrefixV1 + "/get_missing_events/" +
		url.PathEscape(roomID)
	req := NewFederationRequest("POST", origin, s, path)
	if err = req.SetContent(missing); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// Peek starts a peek on a remote server: see MSC2753
func (ac *federationClient) Peek(
	ctx context.Context, origin, s spec.ServerName, roomID, peekID string,
	roomVersions []gomatrixserverlib.RoomVersion,
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
	req := NewFederationRequest("PUT", origin, s, path)
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
func (ac *federationClient) LookupRoomAlias(
	ctx context.Context, origin, s spec.ServerName, roomAlias string,
) (res RespDirectory, err error) {
	path := federationPathPrefixV1 + "/query/directory?room_alias=" +
		url.QueryEscape(roomAlias)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetPublicRooms gets all public rooms listed on the target homeserver's directory.
// Spec: https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-publicrooms
// thirdPartyInstanceID can only be non-empty if includeAllNetworks is false.
func (ac *federationClient) GetPublicRooms(
	ctx context.Context, origin, s spec.ServerName, limit int, since string,
	includeAllNetworks bool, thirdPartyInstanceID string,
) (res RespPublicRooms, err error) {
	return ac.GetPublicRoomsFiltered(ctx, origin, s, limit, since, "", includeAllNetworks, thirdPartyInstanceID)
}

// searchTerm is used when querying e.g. remote public rooms
type searchTerm struct {
	GenericSearchTerm string `json:"generic_search_term,omitempty"`
}

// postPublicRoomsReq is a request to /publicRooms
type postPublicRoomsReq struct {
	PublicRoomsFilter    searchTerm `json:"filter,omitempty"`
	Limit                int        `json:"limit,omitempty"`
	IncludeAllNetworks   bool       `json:"include_all_networks,omitempty"`
	ThirdPartyInstanceID string     `json:"third_party_instance_id,omitempty"`
	Since                string     `json:"since,omitempty"`
}

// GetPublicRoomsFiltered gets a filtered public rooms list from the target homeserver's directory.
// Spec: https://spec.matrix.org/v1.1/server-server-api/#post_matrixfederationv1publicrooms
// thirdPartyInstanceID can only be non-empty if includeAllNetworks is false.
func (ac *federationClient) GetPublicRoomsFiltered(
	ctx context.Context, origin, s spec.ServerName, limit int, since, filter string,
	includeAllNetworks bool, thirdPartyInstanceID string,
) (res RespPublicRooms, err error) {
	if includeAllNetworks && thirdPartyInstanceID != "" {
		return res, fmt.Errorf("thirdPartyInstanceID can only be used if includeAllNetworks is false")
	}

	roomsReq := postPublicRoomsReq{
		PublicRoomsFilter:    searchTerm{GenericSearchTerm: filter},
		Limit:                limit,
		IncludeAllNetworks:   includeAllNetworks,
		ThirdPartyInstanceID: thirdPartyInstanceID,
		Since:                since,
	}
	path := federationPathPrefixV1 + "/publicRooms"
	req := NewFederationRequest("POST", origin, s, path)
	if err = req.SetContent(roomsReq); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupProfile queries the profile of a user.
// If field is empty, the server returns the full profile of the user.
// Otherwise, it must be one of: ["displayname", "avatar_url"], indicating
// which field of the profile should be returned.
// Spec: https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-query-profile
func (ac *federationClient) LookupProfile(
	ctx context.Context, origin, s spec.ServerName, userID string, field string,
) (res RespProfile, err error) {
	path := federationPathPrefixV1 + "/query/profile?user_id=" +
		url.QueryEscape(userID)
	if field != "" {
		path += "&field=" + url.QueryEscape(field)
	}
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// ClaimKeys claims E2E one-time keys from a remote server.
// `oneTimeKeys` are the keys to be claimed. A map from user ID, to a map from device ID to algorithm name. E.g:
//
//	{
//	  "@alice:example.com": {
//	    "JLAFKJWSCS": "signed_curve25519"
//	  }
//	}
//
// https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-claim
func (ac *federationClient) ClaimKeys(ctx context.Context, origin, s spec.ServerName, oneTimeKeys map[string]map[string]string) (res RespClaimKeys, err error) {
	path := federationPathPrefixV1 + "/user/keys/claim"
	req := NewFederationRequest("POST", origin, s, path)
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
func (ac *federationClient) QueryKeys(ctx context.Context, origin, s spec.ServerName, keys map[string][]string) (res RespQueryKeys, err error) {
	path := federationPathPrefixV1 + "/user/keys/query"
	req := NewFederationRequest("POST", origin, s, path)
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
func (ac *federationClient) GetEvent(
	ctx context.Context, origin, s spec.ServerName, eventID string,
) (res gomatrixserverlib.Transaction, err error) {
	path := federationPathPrefixV1 + "/event/" + url.PathEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetEventAuth gets an event auth chain from a remote server.
// See https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-event-auth-roomid-eventid
func (ac *federationClient) GetEventAuth(
	ctx context.Context, origin, s spec.ServerName, roomVersion gomatrixserverlib.RoomVersion, roomID, eventID string,
) (res RespEventAuth, err error) {
	path := federationPathPrefixV1 + "/event_auth/" + url.PathEscape(roomID) + "/" + url.PathEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetUserDevices returns a list of the user's devices from a remote server.
// See https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-user-devices-userid
func (ac *federationClient) GetUserDevices(
	ctx context.Context, origin, s spec.ServerName, userID string,
) (res RespUserDevices, err error) {
	path := federationPathPrefixV1 + "/user/devices/" + url.PathEscape(userID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// Backfill asks a homeserver for events early enough for them to not be in the
// local database.
// See https://matrix.org/docs/spec/server_server/unstable.html#get-matrix-federation-v1-backfill-roomid
func (ac *federationClient) Backfill(
	ctx context.Context, origin, s spec.ServerName, roomID string, limit int, eventIDs []string,
) (res gomatrixserverlib.Transaction, err error) {
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
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// MSC2836EventRelationships performs an MSC2836 /event_relationships request.
func (ac *federationClient) MSC2836EventRelationships(
	ctx context.Context, origin, dst spec.ServerName, r MSC2836EventRelationshipsRequest, roomVersion gomatrixserverlib.RoomVersion,
) (res MSC2836EventRelationshipsResponse, err error) {
	path := "/_matrix/federation/unstable/event_relationships"
	req := NewFederationRequest("POST", origin, dst, path)
	if err = req.SetContent(r); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

func (ac *federationClient) RoomHierarchy(
	ctx context.Context, origin, dst spec.ServerName, roomID string, suggestedOnly bool,
) (res RoomHierarchyResponse, err error) {
	path := "/_matrix/federation/v1/hierarchy/" + url.PathEscape(roomID)
	if suggestedOnly {
		path += "?suggested_only=true"
	}
	req := NewFederationRequest("GET", origin, dst, path)
	err = ac.doRequest(ctx, req, &res)
	if err != nil {
		gerr, ok := err.(gomatrix.HTTPError)
		if ok && gerr.Code == 404 {
			// fallback to unstable endpoint
			path = "/_matrix/federation/unstable/org.matrix.msc2946/hierarchy/" + url.PathEscape(roomID)
			if suggestedOnly {
				path += "?suggested_only=true"
			}
			req := NewFederationRequest("GET", origin, dst, path)
			err = ac.doRequest(ctx, req, &res)
		}
	}
	return
}
