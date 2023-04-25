package fclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/sirupsen/logrus"
)

type PerformJoinInput struct {
	UserID     *spec.UserID
	RoomID     string
	ServerName spec.ServerName
	Content    map[string]interface{}
	Unsigned   map[string]interface{}

	PrivateKey ed25519.PrivateKey
	KeyID      gomatrixserverlib.KeyID
	KeyRing    *gomatrixserverlib.KeyRing

	EventProvider gomatrixserverlib.EventProvider
}

type PerformJoinCallbacks struct {
	FederationFailure func(serverName spec.ServerName)
	FederationSuccess func(serverName spec.ServerName)
}

// PerformJoin provides high level functionality that will attempt a federated room
// join. On success it will return the new join event and the state snapshot returned
// as part of the join.
func PerformJoin(
	ctx context.Context,
	fedClient FederationClient,
	input PerformJoinInput,
	callbacks PerformJoinCallbacks,
) (*gomatrixserverlib.HeaderedEvent, gomatrixserverlib.StateResponse, error) {
	origin := input.UserID.Domain()

	// Try to perform a make_join using the information supplied in the
	// request.
	respMakeJoin, err := fedClient.MakeJoin(
		ctx,
		origin,
		input.ServerName,
		input.RoomID,
		input.UserID.Raw(),
	)
	if err != nil {
		// TODO: Check if the user was not allowed to join the room.
		callbacks.FederationFailure(input.ServerName)
		return nil, nil, fmt.Errorf("r.federation.MakeJoin: %w", err)
	}
	callbacks.FederationSuccess(input.ServerName)

	// Set all the fields to be what they should be, this should be a no-op
	// but it's possible that the remote server returned us something "odd"
	stateKey := input.UserID.Raw()
	respMakeJoin.JoinEvent.Type = spec.MRoomMember
	respMakeJoin.JoinEvent.Sender = input.UserID.Raw()
	respMakeJoin.JoinEvent.StateKey = &stateKey
	respMakeJoin.JoinEvent.RoomID = input.RoomID
	respMakeJoin.JoinEvent.Redacts = ""
	if input.Content == nil {
		input.Content = map[string]interface{}{}
	}
	_ = json.Unmarshal(respMakeJoin.JoinEvent.Content, &input.Content)
	input.Content["membership"] = spec.Join
	if err = respMakeJoin.JoinEvent.SetContent(input.Content); err != nil {
		return nil, nil, fmt.Errorf("respMakeJoin.JoinEvent.SetContent: %w", err)
	}
	if err = respMakeJoin.JoinEvent.SetUnsigned(struct{}{}); err != nil {
		return nil, nil, fmt.Errorf("respMakeJoin.JoinEvent.SetUnsigned: %w", err)
	}

	// Work out if we support the room version that has been supplied in
	// the make_join response.
	// "If not provided, the room version is assumed to be either "1" or "2"."
	// https://matrix.org/docs/spec/server_server/unstable#get-matrix-federation-v1-make-join-roomid-userid
	if respMakeJoin.RoomVersion == "" {
		respMakeJoin.RoomVersion = setDefaultRoomVersionFromJoinEvent(respMakeJoin.JoinEvent)
	}
	verImpl, err := gomatrixserverlib.GetRoomVersion(respMakeJoin.RoomVersion)
	if err != nil {
		return nil, nil, err
	}

	// Build the join event.
	event, err := respMakeJoin.JoinEvent.Build(
		time.Now(),
		origin,
		input.KeyID,
		input.PrivateKey,
		respMakeJoin.RoomVersion,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("respMakeJoin.JoinEvent.Build: %w", err)
	}

	var respState gomatrixserverlib.StateResponse
	// Try to perform a send_join using the newly built event.
	respSendJoin, err := fedClient.SendJoin(
		context.Background(),
		origin,
		input.ServerName,
		event,
	)
	if err != nil {
		callbacks.FederationFailure(input.ServerName)
		return nil, nil, fmt.Errorf("r.federation.SendJoin: %w", err)
	}
	callbacks.FederationSuccess(input.ServerName)

	// If the remote server returned an event in the "event" key of
	// the send_join request then we should use that instead. It may
	// contain signatures that we don't know about.
	if len(respSendJoin.Event) > 0 {
		var remoteEvent *gomatrixserverlib.Event
		remoteEvent, err = verImpl.NewEventFromUntrustedJSON(respSendJoin.Event)
		if err == nil && isWellFormedMembershipEvent(
			remoteEvent, input.RoomID, input.UserID,
		) {
			event = remoteEvent
		}
	}

	// Sanity-check the join response to ensure that it has a create
	// event, that the room version is known, etc.
	authEvents := respSendJoin.AuthEvents.UntrustedEvents(respMakeJoin.RoomVersion)
	if err = checkEventsContainCreateEvent(authEvents); err != nil {
		return nil, nil, fmt.Errorf("sanityCheckAuthChain: %w", err)
	}

	// Process the join response in a goroutine. The idea here is
	// that we'll try and wait for as long as possible for the work
	// to complete, but if the client does give up waiting, we'll
	// still continue to process the join anyway so that we don't
	// waste the effort.
	// TODO: Can we expand Check here to return a list of missing auth
	// events rather than failing one at a time?
	respState, err = gomatrixserverlib.CheckSendJoinResponse(
		context.Background(),
		respMakeJoin.RoomVersion, &respSendJoin,
		input.KeyRing,
		event,
		input.EventProvider,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("respSendJoin.Check: %w", err)
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

	return event.Headered(respMakeJoin.RoomVersion), respState, nil
}

func setDefaultRoomVersionFromJoinEvent(
	joinEvent gomatrixserverlib.EventBuilder,
) gomatrixserverlib.RoomVersion {
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
		return gomatrixserverlib.RoomVersionV1
	}
	return gomatrixserverlib.RoomVersionV4
}

// isWellFormedMembershipEvent returns true if the event looks like a legitimate
// membership event.
func isWellFormedMembershipEvent(event *gomatrixserverlib.Event, roomID string, userID *spec.UserID) bool {
	if membership, err := event.Membership(); err != nil {
		return false
	} else if membership != spec.Join {
		return false
	}
	if event.RoomID() != roomID {
		return false
	}
	if !event.StateKeyEquals(userID.Raw()) {
		return false
	}
	return true
}

func checkEventsContainCreateEvent(events []*gomatrixserverlib.Event) error {
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
			knownVersions := gomatrixserverlib.RoomVersions()
			if _, ok := knownVersions[gomatrixserverlib.RoomVersion(verBody.Version)]; !ok {
				return fmt.Errorf("m.room.create event has an unknown room version: %s", verBody.Version)
			}
			return nil
		}
	}
	return fmt.Errorf("response is missing m.room.create event")
}
