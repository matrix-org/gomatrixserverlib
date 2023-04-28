package gomatrixserverlib

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/sirupsen/logrus"
)

type PerformJoinInput struct {
	UserID     *spec.UserID
	RoomID     *spec.RoomID
	ServerName spec.ServerName
	Content    map[string]interface{}
	Unsigned   map[string]interface{}

	PrivateKey ed25519.PrivateKey
	KeyID      KeyID
	KeyRing    *KeyRing

	EventProvider EventProvider
}

type PerformJoinResponse struct {
	JoinEvent     *Event
	StateSnapshot StateResponse
}

// PerformJoin provides high level functionality that will attempt a federated room
// join. On success it will return the new join event and the state snapshot returned
// as part of the join.
func PerformJoin(
	ctx context.Context,
	fedClient FederatedJoinClient,
	input PerformJoinInput,
) (*PerformJoinResponse, *FederationError) {
	if input.UserID == nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  false,
			Err:        fmt.Errorf("UserID is nil"),
		}
	}
	if input.RoomID == nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  false,
			Err:        fmt.Errorf("RoomID is nil"),
		}
	}
	if input.KeyRing == nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  false,
			Err:        fmt.Errorf("KeyRing is nil"),
		}
	}

	origin := input.UserID.Domain()

	// Try to perform a make_join using the information supplied in the
	// request.
	respMakeJoin, err := fedClient.MakeJoin(
		ctx,
		origin,
		input.ServerName,
		input.RoomID.String(),
		input.UserID.String(),
	)
	if err != nil {
		// TODO: Check if the user was not allowed to join the room.
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  true,
			Reachable:  false,
			Err:        fmt.Errorf("r.federation.MakeJoin: %w", err),
		}
	}

	// Set all the fields to be what they should be, this should be a no-op
	// but it's possible that the remote server returned us something "odd"
	stateKey := input.UserID.String()
	joinEvent := respMakeJoin.GetJoinEvent()
	joinEvent.Type = spec.MRoomMember
	joinEvent.Sender = input.UserID.String()
	joinEvent.StateKey = &stateKey
	joinEvent.RoomID = input.RoomID.String()
	joinEvent.Redacts = ""
	if input.Content == nil {
		input.Content = map[string]interface{}{}
	}
	_ = json.Unmarshal(joinEvent.Content, &input.Content)
	input.Content["membership"] = spec.Join
	if err = joinEvent.SetContent(input.Content); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.SetContent: %w", err),
		}
	}
	if err = joinEvent.SetUnsigned(struct{}{}); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.SetUnsigned: %w", err),
		}
	}

	// Work out if we support the room version that has been supplied in
	// the make_join response.
	// "If not provided, the room version is assumed to be either "1" or "2"."
	// https://matrix.org/docs/spec/server_server/unstable#get-matrix-federation-v1-make-join-roomid-userid
	roomVersion := respMakeJoin.GetRoomVersion()
	if roomVersion == "" {
		roomVersion = setDefaultRoomVersionFromJoinEvent(joinEvent)
	}
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        err,
		}
	}

	// Build the join event.
	event, err := joinEvent.Build(
		time.Now(),
		origin,
		input.KeyID,
		input.PrivateKey,
		roomVersion,
	)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.Build: %w", err),
		}
	}

	var respState StateResponse
	// Try to perform a send_join using the newly built event.
	respSendJoin, err := fedClient.SendJoin(
		context.Background(),
		origin,
		input.ServerName,
		event,
	)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  true,
			Reachable:  false,
			Err:        fmt.Errorf("r.federation.SendJoin: %w", err),
		}
	}

	// If the remote server returned an event in the "event" key of
	// the send_join response then we should use that instead. It may
	// contain signatures that we don't know about.
	if len(respSendJoin.GetJoinEvent()) > 0 {
		var remoteEvent *Event
		remoteEvent, err = verImpl.NewEventFromUntrustedJSON(respSendJoin.GetJoinEvent())
		if err == nil && isWellFormedJoinMemberEvent(
			remoteEvent, input.RoomID, input.UserID,
		) {
			event = remoteEvent
		}
	}

	// Sanity-check the join response to ensure that it has a create
	// event, that the room version is known, etc.
	authEvents := respSendJoin.GetAuthEvents().UntrustedEvents(roomVersion)
	if err = checkEventsContainCreateEvent(authEvents); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("sanityCheckAuthChain: %w", err),
		}
	}

	// Process the send_join response. The idea here is that we'll try and wait
	// for as long as possible for the work to complete by using a background
	// context instead of the provided ctx. If the client does give up waiting,
	// we'll still continue to process the join anyway so that we don't waste the effort.
	// TODO: Can we expand Check here to return a list of missing auth
	// events rather than failing one at a time?
	respState, err = CheckSendJoinResponse(
		context.Background(),
		roomVersion, StateResponse(respSendJoin),
		input.KeyRing,
		event,
		input.EventProvider,
	)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respSendJoin.Check: %w", err),
		}
	}

	// If we successfully performed a send_join above then the other
	// server now thinks we're a part of the room. Send the newly
	// returned state to the roomserver to update our local view.
	if input.Unsigned != nil {
		event, err = event.SetUnsigned(input.Unsigned)
		if err != nil {
			// non-fatal, log and continue
			logrus.WithError(err).Errorf("Failed to set unsigned content")
		}
	}

	return &PerformJoinResponse{
		JoinEvent:     event,
		StateSnapshot: respState,
	}, nil
}

func setDefaultRoomVersionFromJoinEvent(
	joinEvent EventBuilder,
) RoomVersion {
	// if auth events are not event references we know it must be v3+
	// we have to do these shenanigans to satisfy sytest, specifically for:
	// "Outbound federation rejects m.room.create events with an unknown room version"
	hasEventRefs := true
	authEvents, ok := joinEvent.AuthEvents.([]interface{})
	if ok {
		if len(authEvents) > 0 {
			_, ok = authEvents[0].(string)
			if ok {
				// event refs are objects, not strings, so we know we must be dealing with a v3+ room.
				hasEventRefs = false
			}
		}
	}

	if hasEventRefs {
		return RoomVersionV1
	}
	return RoomVersionV4
}

// isWellFormedJoinMemberEvent returns true if the event looks like a legitimate
// membership event.
func isWellFormedJoinMemberEvent(event *Event, roomID *spec.RoomID, userID *spec.UserID) bool { // nolint: interfacer
	if membership, err := event.Membership(); err != nil {
		return false
	} else if membership != spec.Join {
		return false
	}
	if event.RoomID() != roomID.String() {
		return false
	}
	if !event.StateKeyEquals(userID.String()) {
		return false
	}
	return true
}

func checkEventsContainCreateEvent(events []*Event) error {
	// sanity check we have a create event and it has a known room version
	for _, ev := range events {
		if ev.Type() == spec.MRoomCreate && ev.StateKeyEquals("") {
			// make sure the room version is known
			content := ev.Content()
			verBody := struct {
				Version string `json:"room_version"`
			}{}
			err := json.Unmarshal(content, &verBody)
			if err != nil {
				return err
			}
			if verBody.Version == "" {
				// https://matrix.org/docs/spec/client_server/r0.6.0#m-room-create
				// The version of the room. Defaults to "1" if the key does not exist.
				verBody.Version = "1"
			}
			knownVersions := RoomVersions()
			if _, ok := knownVersions[RoomVersion(verBody.Version)]; !ok {
				return fmt.Errorf("m.room.create event has an unknown room version: %s", verBody.Version)
			}
			return nil
		}
	}
	return fmt.Errorf("response is missing m.room.create event")
}
