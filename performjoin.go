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
	UserID     *spec.UserID           // The user joining the room
	RoomID     *spec.RoomID           // The room the user is joining
	ServerName spec.ServerName        // The server to attempt to join via
	Content    map[string]interface{} // The membership event content
	Unsigned   map[string]interface{} // The event unsigned content, if any

	PrivateKey ed25519.PrivateKey // Used to sign the join event
	KeyID      KeyID              // Used to sign the join event
	KeyRing    *KeyRing           // Used to verify the response from send_join

	EventProvider             EventProvider                  // Provides full events given a list of event IDs
	UserIDQuerier             spec.UserIDForSender           // Provides userID for a given senderID
	GetOrCreateSenderID       spec.CreateSenderID            // Creates, if needed, new senderID for this room.
	StoreSenderIDFromPublicID spec.StoreSenderIDFromPublicID // Creates the senderID -> userID for the room creator
}

type PerformJoinResponse struct {
	JoinEvent     PDU
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
	joinEvent := respMakeJoin.GetJoinEvent()
	joinEvent.Type = spec.MRoomMember
	joinEvent.RoomID = input.RoomID.String()
	joinEvent.Redacts = ""

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

	if input.Content == nil {
		input.Content = map[string]interface{}{}
	}

	var senderID spec.SenderID
	signingKey := input.PrivateKey
	keyID := input.KeyID
	origOrigin := origin
	switch respMakeJoin.GetRoomVersion() {
	case RoomVersionPseudoIDs:
		// we successfully did a make_join, create a senderID for this user now
		senderID, signingKey, err = input.GetOrCreateSenderID(ctx, *input.UserID, *input.RoomID, string(respMakeJoin.GetRoomVersion()))
		if err != nil {
			return nil, &FederationError{
				ServerName: input.ServerName,
				Transient:  false,
				Reachable:  true,
				Err:        fmt.Errorf("Cannot create user room key"),
			}
		}
		keyID = "ed25519:1"
		origin = spec.ServerName(senderID)

		mapping := MXIDMapping{
			UserRoomKey: senderID,
			UserID:      input.UserID.String(),
		}
		if err = mapping.Sign(origOrigin, input.KeyID, input.PrivateKey); err != nil {
			return nil, &FederationError{
				ServerName: input.ServerName,
				Transient:  false,
				Reachable:  true,
				Err:        fmt.Errorf("cannot sign mxid_mapping: %w", err),
			}
		}

		input.Content["mxid_mapping"] = mapping
	default:
		senderID = spec.SenderID(input.UserID.String())
	}

	stateKey := string(senderID)
	joinEvent.SenderID = string(senderID)
	joinEvent.StateKey = &stateKey

	joinEB := verImpl.NewEventBuilderFromProtoEvent(&joinEvent)

	_ = json.Unmarshal(joinEvent.Content, &input.Content)
	input.Content["membership"] = spec.Join
	if err = joinEB.SetContent(input.Content); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.SetContent: %w", err),
		}
	}
	if err = joinEB.SetUnsigned(struct{}{}); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.SetUnsigned: %w", err),
		}
	}

	// Build the join event.
	var event PDU
	event, err = joinEB.Build(
		time.Now(),
		origin,
		keyID,
		signingKey,
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
		origOrigin,
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
		var remoteEvent PDU
		remoteEvent, err = verImpl.NewEventFromUntrustedJSON(respSendJoin.GetJoinEvent())
		if err == nil && isWellFormedJoinMemberEvent(
			remoteEvent, input.RoomID, senderID,
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

	// get the membership events of all users, so we can store the mxid_mappings
	// TODO: better way?
	if roomVersion == RoomVersionPseudoIDs {
		stateEvents := respSendJoin.GetStateEvents().UntrustedEvents(roomVersion)
		events := append(authEvents, stateEvents...)
		err = storeMXIDMappings(ctx, events, *input.RoomID, input.KeyRing, input.StoreSenderIDFromPublicID)
		if err != nil {
			return nil, &FederationError{
				ServerName: input.ServerName,
				Transient:  false,
				Reachable:  true,
				Err:        fmt.Errorf("unable to store mxid_mapping: %w", err),
			}
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
		input.UserIDQuerier,
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

func storeMXIDMappings(
	ctx context.Context,
	events []PDU,
	roomID spec.RoomID,
	keyRing JSONVerifier,
	storeSenderID spec.StoreSenderIDFromPublicID,
) error {
	for _, ev := range events {
		if ev.Type() != spec.MRoomMember {
			continue
		}
		mapping, err := getMXIDMapping(ev)
		if err != nil {
			return err
		}
		// we already validated it is a valid roomversion, so this should be safe to use.
		verImpl := MustGetRoomVersion(ev.Version())
		if err := validateMXIDMappingSignatures(ctx, ev, *mapping, keyRing, verImpl); err != nil {
			logrus.WithError(err).Error("invalid signature for mxid_mapping")
			continue
		}
		if err := storeSenderID(ctx, ev.SenderID(), mapping.UserID, roomID); err != nil {
			return err
		}
	}
	return nil
}

func setDefaultRoomVersionFromJoinEvent(
	joinEvent ProtoEvent,
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
func isWellFormedJoinMemberEvent(event PDU, roomID *spec.RoomID, senderID spec.SenderID) bool { // nolint: interfacer
	if membership, err := event.Membership(); err != nil {
		return false
	} else if membership != spec.Join {
		return false
	}
	if event.RoomID().String() != roomID.String() {
		return false
	}
	if !event.StateKeyEquals(string(senderID)) {
		return false
	}
	return true
}

func checkEventsContainCreateEvent(events []PDU) error {
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
