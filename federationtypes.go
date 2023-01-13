package gomatrixserverlib

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// A ServerName is the name a matrix homeserver is identified by.
// It is a DNS name or IP address optionally followed by a port.
//
// https://matrix.org/docs/spec/appendices.html#server-name
type ServerName string

// ParseAndValidateServerName splits a ServerName into a host and port part,
// and checks that it is a valid server name according to the spec.
//
// if there is no explicit port, returns '-1' as the port.
func ParseAndValidateServerName(serverName ServerName) (host string, port int, valid bool) {
	// Don't go any further if the server name is an empty string.
	if len(serverName) == 0 {
		return
	}

	host, port = splitServerName(serverName)

	// the host part must be one of:
	//  - a valid (ascii) dns name
	//  - an IPv4 address
	//  - an IPv6 address

	if host[0] == '[' {
		// must be a valid IPv6 address
		if host[len(host)-1] != ']' {
			return
		}
		ip := host[1 : len(host)-1]
		if net.ParseIP(ip) == nil {
			return
		}
		valid = true
		return
	}

	// try parsing as an IPv4 address
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		valid = true
		return
	}

	// must be a valid DNS Name
	for _, r := range host {
		if !isDNSNameChar(r) {
			return
		}
	}

	valid = true
	return
}

func isDNSNameChar(r rune) bool {
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	if r == '-' || r == '.' {
		return true
	}
	return false
}

// splitServerName splits a ServerName into host and port, without doing
// any validation.
//
// if there is no explicit port, returns '-1' as the port
func splitServerName(serverName ServerName) (string, int) {
	nameStr := string(serverName)

	lastColon := strings.LastIndex(nameStr, ":")
	if lastColon < 0 {
		// no colon: no port
		return nameStr, -1
	}

	portStr := nameStr[lastColon+1:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		// invalid port (possibly an ipv6 host)
		return nameStr, -1
	}

	return nameStr[:lastColon], int(port)
}

// A RespSend is the content of a response to PUT /_matrix/federation/v1/send/{txnID}/
type RespSend struct {
	// Map of event ID to the result of processing that event.
	PDUs map[string]PDUResult `json:"pdus"`
}

// A PDUResult is the result of processing a matrix room event.
type PDUResult struct {
	// If not empty then this is a human readable description of a problem
	// encountered processing an event.
	Error string `json:"error,omitempty"`
}

// A RespStateIDs is the content of a response to GET /_matrix/federation/v1/state_ids/{roomID}/{eventID}
type RespStateIDs struct {
	// A list of state event IDs for the state of the room before the requested event.
	StateEventIDs []string `json:"pdu_ids"`
	// A list of event IDs needed to authenticate the state events.
	AuthEventIDs []string `json:"auth_chain_ids"`
}

// A RespState is the content of a response to GET /_matrix/federation/v1/state/{roomID}/{eventID}
type RespState struct {
	// A list of events giving the state of the room before the request event.
	StateEvents EventJSONs `json:"pdus"`
	// A list of events needed to authenticate the state events.
	AuthEvents EventJSONs `json:"auth_chain"`
}

// A RespPeek is the content of a response to GET /_matrix/federation/v1/peek/{roomID}/{peekID}
type RespPeek struct {
	// How often should we renew the peek?
	RenewalInterval int64 `json:"renewal_interval"`
	// A list of events giving the state of the room at the point of the request
	StateEvents EventJSONs `json:"state"`
	// A list of events needed to authenticate the state events.
	AuthEvents EventJSONs `json:"auth_chain"`
	// The room version that we're trying to peek.
	RoomVersion RoomVersion `json:"room_version"`
	// The ID of the event whose state snapshot this is - i.e. the
	// most recent forward extremity in the room.
	LatestEvent *Event `json:"latest_event"`
}

// MissingEvents represents a request for missing events.
// https://matrix.org/docs/spec/server_server/r0.1.3#post-matrix-federation-v1-get-missing-events-roomid
type MissingEvents struct {
	// The maximum number of events to retrieve.
	Limit int `json:"limit"`
	// The minimum depth of events to retrieve.
	MinDepth int `json:"min_depth"`
	// The latest event IDs that the sender already has.
	EarliestEvents []string `json:"earliest_events"`
	// The event IDs to retrieve the previous events for.
	LatestEvents []string `json:"latest_events"`
}

// A RespMissingEvents is the content of a response to GET /_matrix/federation/v1/get_missing_events/{roomID}
type RespMissingEvents struct {
	// The returned set of missing events.
	Events EventJSONs `json:"events"`
}

// RespPublicRooms is the content of a response to GET /_matrix/federation/v1/publicRooms
type RespPublicRooms struct {
	// A paginated chunk of public rooms.
	Chunk []PublicRoom `json:"chunk"`
	// A pagination token for the response. The absence of this token means there are no more results to fetch and the client should stop paginating.
	NextBatch string `json:"next_batch,omitempty"`
	// A pagination token that allows fetching previous results. The absence of this token means there are no results before this batch, i.e. this is the first batch.
	PrevBatch string `json:"prev_batch,omitempty"`
	// An estimate on the total number of public rooms, if the server has an estimate.
	TotalRoomCountEstimate int `json:"total_room_count_estimate,omitempty"`
}

// PublicRoom stores the info of a room returned by
// GET /_matrix/federation/v1/publicRooms
type PublicRoom struct {
	// Aliases of the room. May be empty.
	Aliases []string `json:"aliases,omitempty"`
	// The canonical alias of the room, if any.
	CanonicalAlias string `json:"canonical_alias,omitempty"`
	// The name of the room, if any.
	Name string `json:"name,omitempty"`
	// The number of members joined to the room.
	JoinedMembersCount int `json:"num_joined_members"`
	// The ID of the room.
	RoomID string `json:"room_id"`
	// The topic of the room, if any.
	Topic string `json:"topic,omitempty"`
	// Whether the room may be viewed by guest users without joining.
	WorldReadable bool `json:"world_readable"`
	// Whether guest users may join the room and participate in it. If they can, they will be subject to ordinary power level rules like any other user.
	GuestCanJoin bool `json:"guest_can_join"`
	// The URL for the room's avatar, if one is set.
	AvatarURL string `json:"avatar_url,omitempty"`
}

// A RespEventAuth is the content of a response to GET /_matrix/federation/v1/event_auth/{roomID}/{eventID}
type RespEventAuth struct {
	// A list of events needed to authenticate the state events.
	AuthEvents EventJSONs `json:"auth_chain"`
}

type respStateFields struct {
	StateEvents EventJSONs `json:"pdus"`
	AuthEvents  EventJSONs `json:"auth_chain"`
}

// RespUserDevices contains a response to /_matrix/federation/v1/user/devices/{userID}
// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-user-devices-userid
type RespUserDevices struct {
	UserID         string           `json:"user_id"`
	StreamID       int64            `json:"stream_id"`
	Devices        []RespUserDevice `json:"devices"`
	MasterKey      *CrossSigningKey `json:"master_key"`
	SelfSigningKey *CrossSigningKey `json:"self_signing_key"`
}

// UnmarshalJSON is used here because people on Synapses can apparently upload
// nonsense into their device keys in types that don't match the expected and
// that can cause the entire response to fail to unmarshal. This simply skips
// anything that fails to unmarshal and returns the rest.
func (r *RespUserDevices) UnmarshalJSON(data []byte) error {
	intermediate := struct {
		UserID         string            `json:"user_id"`
		StreamID       int64             `json:"stream_id"`
		Devices        []json.RawMessage `json:"devices"`
		MasterKey      json.RawMessage   `json:"master_key"`
		SelfSigningKey json.RawMessage   `json:"self_signing_key"`
	}{}
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}
	r.UserID = intermediate.UserID
	r.StreamID = intermediate.StreamID
	_ = json.Unmarshal(intermediate.MasterKey, &r.MasterKey)
	_ = json.Unmarshal(intermediate.SelfSigningKey, &r.SelfSigningKey)
	for _, deviceJSON := range intermediate.Devices {
		var device RespUserDevice
		if err := json.Unmarshal(deviceJSON, &device); err == nil {
			r.Devices = append(r.Devices, device)
		}
	}
	return nil
}

// RespUserDevice are embedded in RespUserDevices
// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-user-devices-userid
type RespUserDevice struct {
	DeviceID    string             `json:"device_id"`
	DisplayName string             `json:"device_display_name"`
	Keys        RespUserDeviceKeys `json:"keys"`
}

// RespUserDeviceKeys are embedded in RespUserDevice
// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-user-devices-userid
type RespUserDeviceKeys struct {
	UserID     string   `json:"user_id"`
	DeviceID   string   `json:"device_id"`
	Algorithms []string `json:"algorithms"`
	// E.g "curve25519:JLAFKJWSCS": "3C5BFWi2Y8MaVvjM8M22DBmh24PmgR0nPvJOIArzgyI"
	Keys map[KeyID]Base64Bytes `json:"keys"`
	// E.g "@alice:example.com": {
	//	"ed25519:JLAFKJWSCS": "dSO80A01XiigH3uBiDVx/EjzaoycHcjq9lfQX0uWsqxl2giMIiSPR8a4d291W1ihKJL/a+myXS367WT6NAIcBA"
	// }
	Signatures map[string]map[KeyID]Base64Bytes `json:"signatures"`
}

// MarshalJSON implements json.Marshaller
func (r RespPeek) MarshalJSON() ([]byte, error) {
	if len(r.StateEvents) == 0 {
		r.StateEvents = EventJSONs{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = EventJSONs{}
	}
	return json.Marshal(struct {
		RenewalInterval int64       `json:"renewal_interval"`
		StateEvents     EventJSONs  `json:"state"`
		AuthEvents      EventJSONs  `json:"auth_chain"`
		RoomVersion     RoomVersion `json:"room_version"`
		LatestEvent     *Event      `json:"latest_event"`
	}{
		RenewalInterval: r.RenewalInterval,
		StateEvents:     r.StateEvents,
		AuthEvents:      r.AuthEvents,
		RoomVersion:     r.RoomVersion,
		LatestEvent:     r.LatestEvent,
	})
}

// MarshalJSON implements json.Marshaller
func (r RespState) MarshalJSON() ([]byte, error) {
	if len(r.StateEvents) == 0 {
		r.StateEvents = EventJSONs{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = EventJSONs{}
	}
	return json.Marshal(respStateFields{ // nolint:gosimple
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
	})
}

// Events combines the auth events and the state events and returns
// them in an order where every event comes after its auth events.
// Each event will only appear once in the output list.
func (r RespState) Events(roomVersion RoomVersion) []*Event {
	authEvents := r.AuthEvents.UntrustedEvents(roomVersion)
	stateEvents := r.StateEvents.UntrustedEvents(roomVersion)
	eventsByID := make(map[string]*Event, len(authEvents)+len(stateEvents))
	for i, event := range authEvents {
		eventsByID[event.EventID()] = authEvents[i]
	}
	for i, event := range stateEvents {
		eventsByID[event.EventID()] = stateEvents[i]
	}
	allEvents := make([]*Event, 0, len(eventsByID))
	for _, event := range eventsByID {
		allEvents = append(allEvents, event)
	}
	return ReverseTopologicalOrdering(allEvents, TopologicalOrderByAuthEvents)
}

// Check that a response to /state is valid. This function mutates
// the RespState to remove any events from AuthEvents or StateEvents
// that do not have valid signatures, and also returns the unmarshalled
// auth events (first return parameter) and state events (second
// return parameter).
func (r *RespState) Check(ctx context.Context, roomVersion RoomVersion, keyRing JSONVerifier, missingAuth AuthChainProvider) ([]*Event, []*Event, error) {
	logger := util.GetLogger(ctx)
	authEvents := r.AuthEvents.UntrustedEvents(roomVersion)
	stateEvents := r.StateEvents.UntrustedEvents(roomVersion)
	var allEvents []*Event
	for _, event := range authEvents {
		if event.StateKey() == nil {
			return nil, nil, fmt.Errorf("gomatrixserverlib: event %q does not have a state key", event.EventID())
		}
		allEvents = append(allEvents, event)
	}

	stateTuples := map[StateKeyTuple]bool{}
	for _, event := range stateEvents {
		if event.StateKey() == nil {
			return nil, nil, fmt.Errorf("gomatrixserverlib: event %q does not have a state key", event.EventID())
		}
		stateTuple := StateKeyTuple{event.Type(), *event.StateKey()}
		if stateTuples[stateTuple] {
			return nil, nil, fmt.Errorf(
				"gomatrixserverlib: duplicate state key tuple (%q, %q)",
				event.Type(), *event.StateKey(),
			)
		}
		stateTuples[stateTuple] = true
		allEvents = append(allEvents, event)
	}

	// Check if the events pass signature checks.
	logger.Infof("Checking event signatures for %d events of room state", len(allEvents))
	errors := VerifyAllEventSignatures(ctx, allEvents, keyRing)
	if len(errors) != len(allEvents) {
		return nil, nil, fmt.Errorf("expected %d errors but got %d", len(allEvents), len(errors))
	}

	// Work out which events failed the signature checks.
	failures := map[string]error{}
	for i, e := range allEvents {
		if errors[i] != nil {
			logrus.WithError(errors[i]).Warnf("Signature validation failed for event %q", e.EventID())
			failures[e.EventID()] = errors[i]
		}
	}

	// Collect a map of event reference to event.
	eventsByID := map[string]*Event{}
	for i := range allEvents {
		if _, ok := failures[allEvents[i].EventID()]; !ok {
			eventsByID[allEvents[i].EventID()] = allEvents[i]
		}
	}

	// Check whether the events are allowed by the auth rules.
	for _, event := range allEvents {
		if err := checkAllowedByAuthEvents(event, eventsByID, missingAuth); err != nil {
			logrus.WithError(err).Warnf("Event %q is not allowed by its auth events", event.EventID())
			failures[event.EventID()] = err
		}
	}

	// For all of the events that weren't verified, remove them
	// from the RespState. This way they won't be passed onwards.
	if f := len(failures); f > 0 {
		logger.Warnf("Discarding %d auth/state event(s) due to invalid signatures", f)

		for i := 0; i < len(authEvents); i++ {
			if _, ok := failures[authEvents[i].EventID()]; ok {
				authEvents = append(authEvents[:i], authEvents[i+1:]...)
				i--
			}
		}
		for i := 0; i < len(stateEvents); i++ {
			if _, ok := failures[stateEvents[i].EventID()]; ok {
				stateEvents = append(stateEvents[:i], stateEvents[i+1:]...)
				i--
			}
		}
	}
	r.AuthEvents = NewEventJSONsFromEvents(authEvents)
	r.StateEvents = NewEventJSONsFromEvents(stateEvents)

	return authEvents, stateEvents, nil
}

// A RespMakeJoin is the content of a response to GET /_matrix/federation/v2/make_join/{roomID}/{userID}
type RespMakeJoin struct {
	// An incomplete m.room.member event for a user on the requesting server
	// generated by the responding server.
	// See https://matrix.org/docs/spec/server_server/unstable.html#joining-rooms
	JoinEvent   EventBuilder `json:"event"`
	RoomVersion RoomVersion  `json:"room_version"`
}

// A RespSendJoin is the content of a response to PUT /_matrix/federation/v2/send_join/{roomID}/{eventID}
type RespSendJoin struct {
	// A list of events giving the state of the room before the request event.
	StateEvents EventJSONs `json:"state"`
	// A list of events needed to authenticate the state events.
	AuthEvents EventJSONs `json:"auth_chain"`
	// The server that originated the event.
	Origin ServerName `json:"origin"`
	// The returned join event from the remote server. Used for restricted joins,
	// but not guaranteed to be present as it's only since MSC3083.
	Event RawJSON `json:"event,omitempty"`
	// true if the state is incomplete
	MembersOmitted bool `json:"members_omitted"`
	// a list of servers in the room. Only returned if partial_state is set.
	ServersInRoom []string `json:"servers_in_room"`
}

// MarshalJSON implements json.Marshaller
func (r RespSendJoin) MarshalJSON() ([]byte, error) {
	fields := respSendJoinFields{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
		Origin:      r.Origin,
		Event:       r.Event,
	}
	if len(fields.AuthEvents) == 0 {
		fields.AuthEvents = EventJSONs{}
	}
	if len(fields.StateEvents) == 0 {
		fields.StateEvents = EventJSONs{}
	}

	if !r.MembersOmitted {
		return json.Marshal(fields)
	}

	partialJoinFields := respSendJoinPartialStateFields{
		respSendJoinFields: fields,
		MembersOmitted:     true,
		ServersInRoom:      r.ServersInRoom,
	}
	return json.Marshal(partialJoinFields)
}

// A RespSendKnock is the content of a response to PUT /_matrix/federation/v2/send_knock/{roomID}/{eventID}
type RespSendKnock struct {
	// A list of stripped state events to help the initiator of the knock identify the room.
	KnockRoomState []InviteV2StrippedState `json:"knock_room_state"`
}

// A RespMakeKnock is the content of a response to GET /_matrix/federation/v2/make_knock/{roomID}/{userID}
type RespMakeKnock struct {
	// An incomplete m.room.member event for a user on the requesting server
	// generated by the responding server.
	// See https://spec.matrix.org/v1.3/server-server-api/#knocking-upon-a-room
	KnockEvent  EventBuilder `json:"event"`
	RoomVersion RoomVersion  `json:"room_version"`
}

// ToRespState returns a new RespState with the same data from the given RespPeek
func (r RespPeek) ToRespState() RespState {
	if len(r.StateEvents) == 0 {
		r.StateEvents = EventJSONs{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = EventJSONs{}
	}
	return RespState{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
	}
}

// respSendJoinFields is an intermediate struct used in RespSendJoin.MarshalJSON
type respSendJoinFields struct {
	StateEvents EventJSONs `json:"state"`
	AuthEvents  EventJSONs `json:"auth_chain"`
	Origin      ServerName `json:"origin"`
	Event       RawJSON    `json:"event,omitempty"`
}

// respSendJoinPartialStateFields extends respSendJoinFields with the fields added
// when the response has incomplete state.
type respSendJoinPartialStateFields struct {
	respSendJoinFields
	MembersOmitted bool     `json:"members_omitted"`
	ServersInRoom  []string `json:"servers_in_room"`
}

// ToRespState returns a new RespState with the same data from the given RespSendJoin
func (r RespSendJoin) ToRespState() RespState {
	if len(r.StateEvents) == 0 {
		r.StateEvents = EventJSONs{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = EventJSONs{}
	}
	return RespState{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
	}
}

// Check that a response to /send_join is valid. If it is then it
// returns a reference to the RespState that contains the room state
// excluding any events that failed signature checks.
// This checks that it would be valid as a response to /state.
// This also checks that the join event is allowed by the state.
// This function mutates the RespSendJoin to remove any events from
// AuthEvents or StateEvents that do not have valid signatures.
func (r *RespSendJoin) Check(ctx context.Context, roomVersion RoomVersion, keyRing JSONVerifier, joinEvent *Event, missingAuth AuthChainProvider) (*RespState, error) {
	// First check that the state is valid and that the events in the response
	// are correctly signed.
	//
	// The response to /send_join has the same data as a response to /state
	// and the checks for a response to /state also apply.
	rs := r.ToRespState()
	authEvents, stateEvents, err := rs.Check(ctx, roomVersion, keyRing, missingAuth)
	if err != nil {
		return nil, err
	}

	// The RespState check can mutate the auth events and state events by
	// removing events which didn't pass signature checks. Use those.
	r.AuthEvents = rs.AuthEvents
	r.StateEvents = rs.StateEvents

	eventsByID := map[string]*Event{}
	authEventProvider := NewAuthEvents(nil)

	// Since checkAllowedByAuthEvents needs to be able to look up any of the
	// auth events by ID only, we will build a map which contains references
	// to all of the auth events.
	for i, event := range authEvents {
		eventsByID[event.EventID()] = authEvents[i]
	}

	// Then we add the current state events too, since our newly formed
	// membership event will likely refer to these as auth events too.
	for i, event := range stateEvents {
		eventsByID[event.EventID()] = stateEvents[i]
	}

	// Now check that the join event is valid against its auth events.
	if err := checkAllowedByAuthEvents(joinEvent, eventsByID, missingAuth); err != nil {
		return nil, fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by its auth events: %w",
			joinEvent.EventID(), err,
		)
	}

	// Add all of the current state events to an auth provider, allowing us
	// to check specifically that the join event is allowed by the supplied
	// state (and not by former auth events).
	for i := range r.StateEvents {
		if err := authEventProvider.AddEvent(stateEvents[i]); err != nil {
			return nil, err
		}
	}

	// Now check that the join event is valid against the supplied state.
	if err := Allowed(joinEvent, &authEventProvider); err != nil {
		return nil, fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by the current room state: %w",
			joinEvent.EventID(), err,
		)
	}

	return &rs, nil
}

// A RespMakeLeave is the content of a response to GET /_matrix/federation/v2/make_leave/{roomID}/{userID}
type RespMakeLeave struct {
	// An incomplete m.room.member event for a user on the requesting server
	// generated by the responding server.
	// See https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-make-leave-roomid-userid
	LeaveEvent EventBuilder `json:"event"`
	// The room version that we're trying to leave.
	RoomVersion RoomVersion `json:"room_version"`
}

// A RespDirectory is the content of a response to GET  /_matrix/federation/v1/query/directory
// This is returned when looking up a room alias from a remote server.
// See https://matrix.org/docs/spec/server_server/unstable.html#directory
type RespDirectory struct {
	// The matrix room ID the room alias corresponds to.
	RoomID string `json:"room_id"`
	// A list of matrix servers that the directory server thinks could be used
	// to join the room. The joining server may need to try multiple servers
	// before it finds one that it can use to join the room.
	Servers []ServerName `json:"servers"`
}

// RespProfile is the content of a response to GET /_matrix/federation/v1/query/profile
type RespProfile struct {
	DisplayName string `json:"displayname,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

func checkAllowedByAuthEvents(event *Event, eventsByID map[string]*Event, missingAuth AuthChainProvider) error {
	authEvents := NewAuthEvents(nil)

	for _, ae := range event.AuthEventIDs() {
	retryEvent:
		authEvent, ok := eventsByID[ae]
		if !ok {
			// We don't have an entry in the eventsByID map - neither an event nor nil.
			if missingAuth != nil {
				// If we have a AuthChainProvider then ask it for the missing event.
				if ev, err := missingAuth(event.roomVersion, []string{ae}); err == nil && len(ev) > 0 {
					// It claims to have returned events - populate the eventsByID
					// map and the authEvents provider so that we can retry with the
					// new events.
					for _, e := range ev {
						if err := authEvents.AddEvent(e); err == nil {
							eventsByID[e.EventID()] = e
						} else {
							eventsByID[e.EventID()] = nil
						}
					}
				} else {
					// It claims to have not returned an event - put a nil into the
					// eventsByID map instead. This signals that we tried to retrieve
					// the event but failed, so we don't keep retrying.
					eventsByID[ae] = nil
				}
				goto retryEvent
			} else {
				// If we didn't have a AuthChainProvider then we can't get the event
				// so just carry on without it. If it was important for anything then
				// Check() below will catch it.
				continue
			}
		} else if authEvent != nil {
			// We had an entry in the map and it contains an actual event, so add it to
			// the auth events provider.
			if err := authEvents.AddEvent(authEvent); err != nil {
				return err
			}
		} else {
			// We had an entry in the map but it contains nil, which means that we tried
			// to use the AuthChainProvider to retrieve it and failed, so at this point
			// we just have to ignore the event.
			continue
		}
	}

	// If we made it this far then we've successfully got as many of the auth events as
	// as described by AuthEventIDs(). Check if they allow the event.
	if err := Allowed(event, &authEvents); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by its auth_events: %s",
			event.EventID(), err.Error(),
		)
	}
	return nil
}

// RespInvite is the content of a response to PUT /_matrix/federation/v1/invite/{roomID}/{eventID}
type RespInvite struct {
	// The invite event signed by recipient server.
	Event RawJSON `json:"event"`
}

// MarshalJSON implements json.Marshaller
func (r RespInvite) MarshalJSON() ([]byte, error) {
	// The wire format of a RespInvite is slightly is sent as the second element
	// of a two element list where the first element is the constant integer 200.
	// (This protocol oddity is the result of a typo in the synapse matrix
	//  server, and is preserved to maintain compatibility.)
	return json.Marshal([]interface{}{200, respInviteFields(r)})
}

// UnmarshalJSON implements json.Unmarshaller
func (r *RespInvite) UnmarshalJSON(data []byte) error {
	var tuple EventJSONs
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) != 2 {
		return fmt.Errorf("gomatrixserverlib: invalid invite response, invalid length: %d != 2", len(tuple))
	}
	if jr := gjson.GetBytes(tuple[1], "event"); jr.Exists() {
		r.Event = []byte(jr.Raw)
	}
	return nil
}

type respInviteFields struct {
	Event RawJSON `json:"event"`
}

// RespInvite is the content of a response to PUT /_matrix/federation/v2/invite/{roomID}/{eventID}
type RespInviteV2 struct {
	// The invite event signed by recipient server.
	Event RawJSON `json:"event"`
}

// RespClaimKeys is the response for https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-claim
type RespClaimKeys struct {
	// Required. One-time keys for the queried devices. A map from user ID, to a map from devices to a map
	// from <algorithm>:<key_id> to the key object or a string.
	OneTimeKeys map[string]map[string]map[string]json.RawMessage `json:"one_time_keys"`
}

// RespQueryKeys is the response for https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-query
type RespQueryKeys struct {
	DeviceKeys      map[string]map[string]DeviceKeys `json:"device_keys"`
	MasterKeys      map[string]CrossSigningKey       `json:"master_keys"`
	SelfSigningKeys map[string]CrossSigningKey       `json:"self_signing_keys"`
}

// DeviceKeys as per https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-query
type DeviceKeys struct {
	RespUserDeviceKeys
	// Additional data added to the device key information by intermediate servers, and not covered by the signatures.
	// E.g { "device_display_name": "Alice's mobile phone" }
	Unsigned map[string]interface{} `json:"unsigned"`
}

func (s *DeviceKeys) isCrossSigningBody() {} // implements CrossSigningBody

func (s *DeviceKeys) Scan(src interface{}) error {
	switch v := src.(type) {
	case string:
		return json.Unmarshal([]byte(v), s)
	case []byte:
		return json.Unmarshal(v, s)
	}
	return fmt.Errorf("unsupported source type")
}

func (s DeviceKeys) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// MSC2836EventRelationshipsRequest is a request to /event_relationships from
// https://github.com/matrix-org/matrix-doc/blob/kegan/msc/threading/proposals/2836-threading.md
// nolint:maligned
type MSC2836EventRelationshipsRequest struct {
	EventID         string `json:"event_id"`
	MaxDepth        int    `json:"max_depth"`
	MaxBreadth      int    `json:"max_breadth"`
	Limit           int    `json:"limit"`
	DepthFirst      bool   `json:"depth_first"`
	RecentFirst     bool   `json:"recent_first"`
	IncludeParent   bool   `json:"include_parent"`
	IncludeChildren bool   `json:"include_children"`
	Direction       string `json:"direction"`
	Batch           string `json:"batch"`
	AutoJoin        bool   `json:"auto_join"`
}

// NewMSC2836EventRelationshipsRequest creates a new MSC2836 /event_relationships request with defaults set.
// https://github.com/matrix-org/matrix-doc/blob/kegan/msc/threading/proposals/2836-threading.md
func NewMSC2836EventRelationshipsRequest(body io.Reader) (*MSC2836EventRelationshipsRequest, error) {
	var relation MSC2836EventRelationshipsRequest
	relation.Defaults()
	if err := json.NewDecoder(body).Decode(&relation); err != nil {
		return nil, err
	}
	return &relation, nil
}

// Defaults sets default values.
func (r *MSC2836EventRelationshipsRequest) Defaults() {
	r.Limit = 100
	r.MaxBreadth = 10
	r.MaxDepth = 3
	r.DepthFirst = false
	r.RecentFirst = true
	r.IncludeParent = false
	r.IncludeChildren = false
	r.Direction = "down"
}

// MSC2836EventRelationshipsResponse is a response to /event_relationships from
// https://github.com/matrix-org/matrix-doc/blob/kegan/msc/threading/proposals/2836-threading.md
type MSC2836EventRelationshipsResponse struct {
	Events    EventJSONs `json:"events"`
	NextBatch string     `json:"next_batch"`
	Limited   bool       `json:"limited"`
	AuthChain EventJSONs `json:"auth_chain"`
}

// MSC2946Room represents a public room with additional metadata on the space directory
type MSC2946Room struct {
	PublicRoom
	ChildrenState  []MSC2946StrippedEvent `json:"children_state"`
	AllowedRoomIDs []string               `json:"allowed_room_ids,omitempty"`
	RoomType       string                 `json:"room_type"`
}

// MSC2946SpacesResponse is the HTTP response body for the federation /unstable/spaces/{roomID} endpoint
// See https://github.com/matrix-org/matrix-doc/pull/2946
type MSC2946SpacesResponse struct {
	Room                 MSC2946Room   `json:"room"`
	Children             []MSC2946Room `json:"children"`
	InaccessibleChildren []string      `json:"inaccessible_children"`
}

// MSC2946StrippedEvent is the format of events returned in the HTTP response body
type MSC2946StrippedEvent struct {
	Type           string          `json:"type"`
	StateKey       string          `json:"state_key"`
	Content        json.RawMessage `json:"content"`
	Sender         string          `json:"sender"`
	OriginServerTS Timestamp       `json:"origin_server_ts"`
}
