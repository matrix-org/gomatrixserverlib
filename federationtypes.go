package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/matrix-org/util"
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
	// The room version that dictates the format of the state events.
	roomVersion RoomVersion
	// A list of events giving the state of the room before the request event.
	StateEvents []Event `json:"pdus"`
	// A list of events needed to authenticate the state events.
	AuthEvents []Event `json:"auth_chain"`
}

// A RespPeek is the content of a response to GET /_matrix/federation/v1/peek/{roomID}
type RespPeek struct {
	// The room version that dictates the format of the state events.
	roomVersion RoomVersion
	// How often should we renew the peek?
	RenewalInterval int `json:"renewal_interval"`
	// A list of events giving the state of the room at the point of the request
	StateEvents []Event `json:"pdus"`
	// A list of events needed to authenticate the state events.
	AuthEvents []Event `json:"auth_chain"`
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
	// The room version that dictates the format of the missing events.
	roomVersion RoomVersion
	// The returned set of missing events.
	Events []Event `json:"events"`
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
	AuthEvents []Event `json:"auth_chain"`
}

type respStateFields struct {
	StateEvents []Event `json:"pdus"`
	AuthEvents  []Event `json:"auth_chain"`
}

// RespUserDevices contains a response to /_matrix/federation/v1/user/devices/{userID}
// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-user-devices-userid
type RespUserDevices struct {
	UserID   string           `json:"user_id"`
	StreamID int              `json:"stream_id"`
	Devices  []RespUserDevice `json:"devices"`
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
	Keys map[string]string `json:"keys"`
	// E.g "@alice:example.com": {
	//	"ed25519:JLAFKJWSCS": "dSO80A01XiigH3uBiDVx/EjzaoycHcjq9lfQX0uWsqxl2giMIiSPR8a4d291W1ihKJL/a+myXS367WT6NAIcBA"
	// }
	Signatures map[string]map[string]string `json:"signatures"`
}

// UnmarshalJSON implements json.Unmarshaller
func (r *RespMissingEvents) UnmarshalJSON(data []byte) error {
	r.Events = []Event{}
	if _, err := r.roomVersion.EventFormat(); err != nil {
		return err
	}
	var intermediate struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}
	for _, raw := range intermediate.Events {
		event, err := NewEventFromUntrustedJSON([]byte(raw), r.roomVersion)
		if err != nil {
			return err
		}
		r.Events = append(r.Events, event)
	}
	return nil
}

// MarshalJSON implements json.Marshaller
func (r RespState) MarshalJSON() ([]byte, error) {
	if len(r.StateEvents) == 0 {
		r.StateEvents = []Event{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = []Event{}
	}
	return json.Marshal(respStateFields{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
	})
}

// UnmarshalJSON implements json.Unmarshaller
func (r *RespState) UnmarshalJSON(data []byte) error {
	r.AuthEvents = []Event{}
	r.StateEvents = []Event{}
	if _, err := r.roomVersion.EventFormat(); err != nil {
		return err
	}
	var intermediate struct {
		StateEvents []json.RawMessage `json:"pdus"`
		AuthEvents  []json.RawMessage `json:"auth_chain"`
	}
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}
	for _, raw := range intermediate.AuthEvents {
		event, err := NewEventFromUntrustedJSON([]byte(raw), r.roomVersion)
		if err != nil {
			return err
		}
		r.AuthEvents = append(r.AuthEvents, event)
	}
	for _, raw := range intermediate.StateEvents {
		event, err := NewEventFromUntrustedJSON([]byte(raw), r.roomVersion)
		if err != nil {
			return err
		}
		r.StateEvents = append(r.StateEvents, event)
	}
	return nil
}

// Events combines the auth events and the state events and returns
// them in an order where every event comes after its auth events.
// Each event will only appear once in the output list.
// Returns an error if there are missing auth events or if there is
// a cycle in the auth events.
func (r RespState) Events() ([]Event, error) {
	if len(r.StateEvents) == 0 {
		r.StateEvents = []Event{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = []Event{}
	}
	eventsByID := map[string]*Event{}
	// Collect a map of event reference to event
	for i := range r.StateEvents {
		eventsByID[r.StateEvents[i].EventID()] = &r.StateEvents[i]
	}
	for i := range r.AuthEvents {
		eventsByID[r.AuthEvents[i].EventID()] = &r.AuthEvents[i]
	}

	queued := map[*Event]bool{}
	outputted := map[*Event]bool{}
	var result []Event
	for _, event := range eventsByID {
		if outputted[event] {
			// If we've already written the event then we can skip it.
			continue
		}

		// The code below does a depth first scan through the auth events
		// looking for events that can be appended to the output.

		// We use an explicit stack rather than using recursion so
		// that we can check we aren't creating cycles.
		stack := []*Event{event}

	LoopProcessTopOfStack:
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			// Check if we can output the top of the stack.
			// We can output it if we have outputted all of its auth_events.
			for _, ref := range top.AuthEvents() {
				authEvent := eventsByID[ref.EventID]
				if authEvent == nil {
					return nil, MissingAuthEventError{ref.EventID, top.EventID()}
				}
				if outputted[authEvent] {
					continue
				}
				if queued[authEvent] {
					return nil, fmt.Errorf(
						"gomatrixserverlib: auth event cycle for ID %q",
						ref.EventID,
					)
				}
				// If we haven't visited the auth event yet then we need to
				// process it before processing the event currently on top of
				// the stack.
				stack = append(stack, authEvent)
				queued[authEvent] = true
				continue LoopProcessTopOfStack
			}
			// If we've processed all the auth events for the event on top of
			// the stack then we can append it to the result and try processing
			// the item below it in the stack.
			result = append(result, *top)
			outputted[top] = true
			stack = stack[:len(stack)-1]
		}
	}

	return result, nil
}

// Check that a response to /state is valid.
func (r RespState) Check(ctx context.Context, keyRing JSONVerifier, missingAuth AuthChainProvider) error {
	logger := util.GetLogger(ctx)
	var allEvents []Event
	for _, event := range r.AuthEvents {
		if event.StateKey() == nil {
			return fmt.Errorf("gomatrixserverlib: event %q does not have a state key", event.EventID())
		}
		allEvents = append(allEvents, event)
	}

	stateTuples := map[StateKeyTuple]bool{}
	for _, event := range r.StateEvents {
		if event.StateKey() == nil {
			return fmt.Errorf("gomatrixserverlib: event %q does not have a state key", event.EventID())
		}
		stateTuple := StateKeyTuple{event.Type(), *event.StateKey()}
		if stateTuples[stateTuple] {
			return fmt.Errorf(
				"gomatrixserverlib: duplicate state key tuple (%q, %q)",
				event.Type(), *event.StateKey(),
			)
		}
		stateTuples[stateTuple] = true
		allEvents = append(allEvents, event)
	}

	// Check if the events pass signature checks.
	logger.Infof("Checking event signatures for %d events of room state", len(allEvents))
	errors, err := VerifyEventSignatures(ctx, allEvents, keyRing)
	if err != nil {
		return err
	}
	if len(errors) != len(allEvents) {
		return fmt.Errorf("expected %d errors but got %d", len(allEvents), len(errors))
	}

	// Work out which events failed the signature checks.
	failures := map[string]struct{}{}
	for i, e := range allEvents {
		if errors[i] != nil {
			failures[e.EventID()] = struct{}{}
		}
	}

	// Collect a map of event reference to event.
	eventsByID := map[string]*Event{}
	for i := range allEvents {
		if _, ok := failures[allEvents[i].EventID()]; !ok {
			eventsByID[allEvents[i].EventID()] = &allEvents[i]
		}
	}

	// Check whether the events are allowed by the auth rules.
	for _, event := range allEvents {
		if err := checkAllowedByAuthEvents(event, eventsByID, missingAuth); err != nil {
			return err
		}
	}

	// For all of the events that weren't verified, remove them
	// from the RespState. This way they won't be passed onwards.
	logger.Infof("Discarding %d auth/state events due to invalid signatures", len(failures))
	for i := range r.AuthEvents {
		if _, ok := failures[r.AuthEvents[i].EventID()]; ok {
			r.AuthEvents = append(r.AuthEvents[:i], r.AuthEvents[i+1:]...)
		}
	}
	for i := range r.StateEvents {
		if _, ok := failures[r.StateEvents[i].EventID()]; ok {
			r.StateEvents = append(r.StateEvents[:i], r.StateEvents[i+1:]...)
		}
	}

	return nil
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
	// The room version that dictates the format of the state events.
	roomVersion RoomVersion
	// A list of events giving the state of the room before the request event.
	StateEvents []Event `json:"state"`
	// A list of events needed to authenticate the state events.
	AuthEvents []Event `json:"auth_chain"`
	// The server that originated the event.
	Origin ServerName `json:"origin"`
}

// MarshalJSON implements json.Marshaller
func (r RespSendJoin) MarshalJSON() ([]byte, error) {
	fields := respSendJoinFields{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
		Origin:      r.Origin,
	}
	if len(fields.AuthEvents) == 0 {
		fields.AuthEvents = []Event{}
	}
	if len(fields.StateEvents) == 0 {
		fields.StateEvents = []Event{}
	}
	return json.Marshal(fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (r *RespSendJoin) UnmarshalJSON(data []byte) error {
	r.AuthEvents = []Event{}
	r.StateEvents = []Event{}
	if _, err := r.roomVersion.EventFormat(); err != nil {
		return err
	}
	var intermediate struct {
		StateEvents []json.RawMessage `json:"state"`
		AuthEvents  []json.RawMessage `json:"auth_chain"`
		Origin      ServerName        `json:"origin"`
	}
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}
	for _, raw := range intermediate.AuthEvents {
		event, err := NewEventFromUntrustedJSON([]byte(raw), r.roomVersion)
		if err != nil {
			return err
		}
		r.AuthEvents = append(r.AuthEvents, event)
	}
	for _, raw := range intermediate.StateEvents {
		event, err := NewEventFromUntrustedJSON([]byte(raw), r.roomVersion)
		if err != nil {
			return err
		}
		r.StateEvents = append(r.StateEvents, event)
	}
	return nil
}

// ToRespState returns a new RespState with the same data from the given RespPeek
func (r RespPeek) ToRespState() RespState {
	if len(r.StateEvents) == 0 {
		r.StateEvents = []Event{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = []Event{}
	}
	return RespState{
		StateEvents: r.StateEvents,
		AuthEvents: r.AuthEvents,
	}
}

type respSendJoinFields struct {
	StateEvents []Event    `json:"state"`
	AuthEvents  []Event    `json:"auth_chain"`
	Origin      ServerName `json:"origin"`
}

// ToRespState returns a new RespState with the same data from the given RespSendJoin
func (r RespSendJoin) ToRespState() RespState {
	if len(r.StateEvents) == 0 {
		r.StateEvents = []Event{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = []Event{}
	}
	return RespState{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
	}
}

// Check that a response to /send_join is valid.
// This checks that it would be valid as a response to /state
// This also checks that the join event is allowed by the state.
func (r RespSendJoin) Check(ctx context.Context, keyRing JSONVerifier, joinEvent Event, missingAuth AuthChainProvider) error {
	// First check that the state is valid and that the events in the response
	// are correctly signed.
	//
	// The response to /send_join has the same data as a response to /state
	// and the checks for a response to /state also apply.
	if err := r.ToRespState().Check(ctx, keyRing, missingAuth); err != nil {
		return err
	}

	eventsByID := map[string]*Event{}
	authEventProvider := NewAuthEvents(nil)

	// Since checkAllowedByAuthEvents needs to be able to look up any of the
	// auth events by ID only, we will build a map which contains references
	// to all of the auth events.
	for i, event := range r.AuthEvents {
		eventsByID[event.EventID()] = &r.AuthEvents[i]
	}

	// Then we add the current state events too, since our newly formed
	// membership event will likely refer to these as auth events too.
	for i, event := range r.StateEvents {
		eventsByID[event.EventID()] = &r.StateEvents[i]
	}

	// Add all of the current state events to an auth provider, allowing us
	// to check specifically that the join event is allowed by the supplied
	// state (and not by former auth events).
	for i := range r.StateEvents {
		if err := authEventProvider.AddEvent(&r.StateEvents[i]); err != nil {
			return err
		}
	}

	// Now check that the join event is valid against its auth events.
	if err := checkAllowedByAuthEvents(joinEvent, eventsByID, missingAuth); err != nil {
		return err
	}

	// Now check that the join event is valid against the supplied state.
	if err := Allowed(joinEvent, &authEventProvider); err != nil {
		return fmt.Errorf(
			"gomatrixserverlib: event with ID %q is not allowed by the supplied state: %s",
			joinEvent.EventID(), err.Error(),
		)
	}

	return nil
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

func checkAllowedByAuthEvents(event Event, eventsByID map[string]*Event, missingAuth AuthChainProvider) error {
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
						if err := authEvents.AddEvent(&e); err == nil {
							eventsByID[e.EventID()] = &e
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
				// If we didn't have a AuthChainProvider then just stop at this
				// point - we can't do anything better than to notify the caller.
				return MissingAuthEventError{ae, event.EventID()}
			}
		} else if authEvent != nil {
			// We had an entry in the map and it contains an actual event, so add it to
			// the auth events provider.
			if err := authEvents.AddEvent(authEvent); err != nil {
				return err
			}
		} else {
			// We had an entry in the map but it contains nil, which means that we tried
			// to use the AuthChainProvider to retrieve it and failed, so at this
			// point there's nothing better to do than to notify the caller.
			return MissingAuthEventError{ae, event.EventID()}
		}
	}

	// If we made it this far then we've successfully got all of the events as required
	// by AuthEventIDs(). Check if they allow the event.
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
	Event Event
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
	var tuple []RawJSON
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) != 2 {
		return fmt.Errorf("gomatrixserverlib: invalid invite response, invalid length: %d != 2", len(tuple))
	}
	if jr := gjson.GetBytes(tuple[1], "event"); jr.Exists() {
		event, err := NewEventFromUntrustedJSON([]byte(jr.Raw), RoomVersionV1)
		if err != nil {
			return err
		}
		r.Event = event
	}
	return nil
}

type respInviteFields struct {
	Event Event `json:"event"`
}

// RespInvite is the content of a response to PUT /_matrix/federation/v2/invite/{roomID}/{eventID}
type RespInviteV2 struct {
	// The room version that dictates the format of the state events.
	roomVersion RoomVersion
	// The invite event signed by recipient server.
	Event Event `json:"event"`
}

// UnmarshalJSON implements json.Unmarshaller
func (r *RespInviteV2) UnmarshalJSON(data []byte) error {
	if _, err := r.roomVersion.EventFormat(); err != nil {
		return err
	}
	var intermediate struct {
		Event json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}
	event, err := NewEventFromUntrustedJSON([]byte(intermediate.Event), r.roomVersion)
	if err != nil {
		return err
	}
	r.Event = event
	return nil
}

// RespClaimKeys is the response for https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-claim
type RespClaimKeys struct {
	// Required. One-time keys for the queried devices. A map from user ID, to a map from devices to a map
	// from <algorithm>:<key_id> to the key object or a string.
	OneTimeKeys map[string]map[string]map[string]json.RawMessage `json:"one_time_keys"`
}

// RespQueryKeys is the response for https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-query
type RespQueryKeys struct {
	DeviceKeys map[string]map[string]DeviceKeys `json:"device_keys"`
}

// DeviceKeys as per https://matrix.org/docs/spec/server_server/latest#post-matrix-federation-v1-user-keys-query
type DeviceKeys struct {
	RespUserDeviceKeys
	// Additional data added to the device key information by intermediate servers, and not covered by the signatures.
	// E.g { "device_display_name": "Alice's mobile phone" }
	Unsigned map[string]interface{} `json:"unsigned"`
}
