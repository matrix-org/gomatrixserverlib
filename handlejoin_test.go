package gomatrixserverlib

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

type TestJoinRoomQuerier struct {
	roomInfoErr       bool
	stateEventErr     bool
	serverInRoomErr   bool
	membershipErr     bool
	getJoinedUsersErr bool
	invitePendingErr  bool
	roomExists        bool
	serverInRoom      map[string]bool

	pendingInvite bool
	joinerInRoom  bool
	joinedUsers   []PDU

	joinRulesEvent   PDU
	powerLevelsEvent PDU
}

func (r *TestJoinRoomQuerier) RoomInfo(ctx context.Context, roomID spec.RoomID) (*RoomInfo, error) {
	if r.roomInfoErr {
		return nil, fmt.Errorf("err")
	}
	return &RoomInfo{Version: RoomVersionV10}, nil
}

func (r *TestJoinRoomQuerier) StateEvent(ctx context.Context, roomID spec.RoomID, eventType spec.MatrixEventType, stateKey string) (PDU, error) {
	if r.stateEventErr {
		return nil, fmt.Errorf("err")
	}
	var event PDU
	if eventType == spec.MRoomJoinRules {
		event = r.joinRulesEvent
	} else if eventType == spec.MRoomPowerLevels {
		event = r.powerLevelsEvent
	}
	return event, nil
}

func (r *TestJoinRoomQuerier) ServerInRoom(ctx context.Context, server spec.ServerName, roomID spec.RoomID) (*JoinedToRoomResponse, error) {
	if r.serverInRoomErr {
		return nil, fmt.Errorf("err")
	}
	serverInRoom := false
	if inRoom, ok := r.serverInRoom[roomID.String()]; ok {
		serverInRoom = inRoom
	}
	return &JoinedToRoomResponse{
		RoomExists:   r.roomExists,
		ServerInRoom: serverInRoom,
	}, nil
}

func (r *TestJoinRoomQuerier) UserJoinedToRoom(ctx context.Context, roomNID int64, userID spec.UserID) (bool, error) {
	if r.membershipErr {
		return false, fmt.Errorf("err")
	}
	return r.joinerInRoom, nil
}

func (r *TestJoinRoomQuerier) GetJoinedUsers(ctx context.Context, roomVersion RoomVersion, roomNID int64) ([]PDU, error) {
	if r.getJoinedUsersErr {
		return nil, fmt.Errorf("err")
	}
	return r.joinedUsers, nil
}

func (r *TestJoinRoomQuerier) InvitePending(ctx context.Context, roomID spec.RoomID, userID spec.UserID) (bool, error) {
	if r.invitePendingErr {
		return false, fmt.Errorf("err")
	}
	return r.pendingInvite, nil
}

func TestHandleJoin(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validUser, err := spec.NewUserID("@user:remote", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)
	joinedUser, err := spec.NewUserID("@joined:local", true)
	assert.Nil(t, err)
	allowedRoom, err := spec.NewRoomID("!allowed:local")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	stateKey := ""
	eb := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomCreate,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"creator":"@user:local","m.federate":true,"room_version":"10"}`),
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := eb.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	stateKey = ""
	joinRulesEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    spec.RawJSON(`{"join_rule":"public"}`),
		Unsigned:   spec.RawJSON(""),
	})
	joinRulesEvent, err := joinRulesEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join_rules event: %v", err)
	}

	stateKey = ""
	joinRulesPrivateEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    spec.RawJSON(`{"join_rule":"private"}`),
		Unsigned:   spec.RawJSON(""),
	})
	joinRulesPrivateEvent, err := joinRulesPrivateEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building private join_rules event: %v", err)
	}

	stateKey = ""
	joinRulesRestrictedEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    spec.RawJSON(`{"join_rule":"restricted","allow":[{"room_id":"!allowed:local","type":"m.room_membership"}]}`),
		Unsigned:   spec.RawJSON(""),
	})
	joinRulesRestrictedEvent, err := joinRulesRestrictedEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building restricted join_rules event: %v", err)
	}

	stateKey = ""
	powerLevelsEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      2,
		Content:    spec.RawJSON(`{"users":{"@joined:local":100}}`),
		Unsigned:   spec.RawJSON(""),
	})
	powerLevelsEvent, err := powerLevelsEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building power_levels event: %v", err)
	}

	stateKey = validUser.String()
	joinEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{powerLevelsEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID(), powerLevelsEvent.EventID()},
		Depth:      3,
		Content:    spec.RawJSON(`{"membership":"join"}`),
		Unsigned:   spec.RawJSON(""),
	})
	joinEvent, err := joinEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join event: %v", err)
	}

	stateKey = joinedUser.String()
	joinedUserEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     joinedUser.String(),
		RoomID:     allowedRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{powerLevelsEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID(), powerLevelsEvent.EventID()},
		Depth:      3,
		Content:    spec.RawJSON(`{"membership":"join"}`),
		Unsigned:   spec.RawJSON(""),
	})
	joinedUserEvent, err := joinedUserEB.Build(time.Now(), joinedUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join event: %v", err)
	}

	tests := map[string]struct {
		input       HandleMakeJoinInput
		expectedErr bool
		errCode     int
	}{
		"nil_context": {
			input: HandleMakeJoinInput{
				Context:            nil,
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusInternalServerError,
		},
		"unsupported_room_version": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusBadRequest,
		},
		"mismatched_user_and_origin": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      "random.server",
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusForbidden,
		},
		"server_in_room_error": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{serverInRoomErr: true},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusNotFound,
		},
		"server_room_doesnt_exist": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{serverInRoom: map[string]bool{validRoom.String(): true}},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusNotFound,
		},
		"server_not_in_room": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, []PDU{}, nil },
			},
			expectedErr: true,
			errCode:     http.StatusNotFound,
		},
		"cant_join_private_room": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: map[string]bool{validRoom.String(): true}},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesPrivateEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     403,
		},
		"invalid_template_state": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: map[string]bool{validRoom.String(): true}},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, nil, nil
				},
			},
			expectedErr: true,
			errCode:     500,
		},
		"invalid_template_event": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: map[string]bool{validRoom.String(): true}},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return nil, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     500,
		},
		"template_event_not_join": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: map[string]bool{validRoom.String(): true}},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return createEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     500,
		},
		"success_no_join_rules": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: map[string]bool{validRoom.String(): true}},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"success_with_public_join_rules": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier: &TestJoinRoomQuerier{
					roomExists:     true,
					serverInRoom:   map[string]bool{validRoom.String(): true},
					joinRulesEvent: joinRulesEvent,
				},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"success_restricted_join_pending_invite": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier: &TestJoinRoomQuerier{
					roomExists:     true,
					serverInRoom:   map[string]bool{validRoom.String(): true},
					pendingInvite:  true,
					joinRulesEvent: joinRulesRestrictedEvent,
				},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"success_restricted_join_member_with_invite_power": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier: &TestJoinRoomQuerier{
					roomExists: true,
					serverInRoom: map[string]bool{validRoom.String(): true,
						allowedRoom.String(): true},
					joinerInRoom:     true,
					joinedUsers:      []PDU{joinedUserEvent},
					joinRulesEvent:   joinRulesRestrictedEvent,
					powerLevelsEvent: powerLevelsEvent,
				},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"failure_restricted_join_not_resident": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier: &TestJoinRoomQuerier{
					roomExists:       true,
					serverInRoom:     map[string]bool{validRoom.String(): true},
					joinerInRoom:     true,
					joinedUsers:      []PDU{joinedUserEvent},
					joinRulesEvent:   joinRulesRestrictedEvent,
					powerLevelsEvent: powerLevelsEvent,
				},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     400,
		},
		"failure_restricted_join_no_member_with_invite_power": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier: &TestJoinRoomQuerier{
					roomExists: true,
					serverInRoom: map[string]bool{validRoom.String(): true,
						allowedRoom.String(): true},
					joinedUsers:      []PDU{joinedUserEvent},
					joinRulesEvent:   joinRulesRestrictedEvent,
					powerLevelsEvent: powerLevelsEvent,
				},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     403,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleMakeJoin(tc.input)
			if tc.expectedErr {
				pass := assert.NotNil(t, joinErr)
				if pass {
					assert.Equal(t, tc.errCode, joinErr.Code)
				}
			} else {
				jsonBytes, err := json.Marshal(&joinErr)
				assert.Nil(t, err)
				assert.Nil(t, joinErr, string(jsonBytes))
			}
		})
	}
}

func TestHandleJoinNilQuerier(t *testing.T) {
	assert.Panics(t, func() { HandleMakeJoin(HandleMakeJoinInput{}) })
}
