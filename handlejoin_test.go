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
	serverInRoom      bool
}

func (r *TestJoinRoomQuerier) RoomInfo(ctx context.Context, roomID *spec.RoomID) (*RoomInfo, error) {
	if r.roomInfoErr {
		return nil, fmt.Errorf("err")
	}
	return &RoomInfo{Version: RoomVersionV10}, nil
}

func (r *TestJoinRoomQuerier) StateEvent(ctx context.Context, roomID *spec.RoomID, eventType spec.MatrixEventType, stateKey string) (PDU, error) {
	if r.stateEventErr {
		return nil, fmt.Errorf("err")
	}
	return nil, nil
}

func (r *TestJoinRoomQuerier) ServerInRoom(ctx context.Context, server spec.ServerName, roomID *spec.RoomID) (*JoinedToRoomResponse, error) {
	if r.serverInRoomErr {
		return nil, fmt.Errorf("err")
	}
	return &JoinedToRoomResponse{
		RoomExists:   r.roomExists,
		ServerInRoom: r.serverInRoom,
	}, nil
}

func (r *TestJoinRoomQuerier) Membership(ctx context.Context, roomNID int64, userID *spec.UserID) (bool, error) {
	if r.membershipErr {
		return false, fmt.Errorf("err")
	}
	return false, nil
}

func (r *TestJoinRoomQuerier) GetJoinedUsers(ctx context.Context, roomVersion RoomVersion, roomNID int64) ([]PDU, error) {
	if r.getJoinedUsersErr {
		return nil, fmt.Errorf("err")
	}
	return []PDU{}, nil
}

func (r *TestJoinRoomQuerier) InvitePending(ctx context.Context, roomID *spec.RoomID, userID *spec.UserID) (bool, error) {
	if r.invitePendingErr {
		return false, fmt.Errorf("err")
	}
	return false, nil
}

func TestHandleJoin(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validUser, err := spec.NewUserID("@user:remote", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
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
	joinRulesProto := ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    spec.RawJSON(`{"join_rule":"public"}`), // TODO:
		Unsigned:   spec.RawJSON(""),
	}
	joinRulesEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&joinRulesProto)
	joinRulesEvent, err := joinRulesEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join_rules event: %v", err)
	}
	stateKey = ""
	joinRulesPrivateProto := ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    spec.RawJSON(`{"join_rule":"private"}`), // TODO:
		Unsigned:   spec.RawJSON(""),
	}
	joinRulesPrivateEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&joinRulesPrivateProto)
	joinRulesPrivateEvent, err := joinRulesPrivateEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building private join_rules event: %v", err)
	}

	stateKey = validUser.String()
	joinProto := ProtoEvent{
		Sender:     validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{joinRulesEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID()},
		Depth:      2,
		Content:    spec.RawJSON(`{"membership":"join"}`),
		Unsigned:   spec.RawJSON(""),
	}
	joinEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&joinProto)
	joinEvent, err := joinEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join event: %v", err)
	}

	tests := map[string]struct {
		input       HandleMakeJoinInput
		expectedErr bool
		errCode     int
	}{
		"empty_input": {
			input:       HandleMakeJoinInput{},
			expectedErr: true,
			errCode:     http.StatusBadRequest,
		},
		"nil_context": {
			input: HandleMakeJoinInput{
				Context:            nil,
				UserID:             validUser,
				RoomID:             validRoom,
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
		"nil_userID": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             nil,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusBadRequest,
		},
		"nil_roomID": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             validUser,
				RoomID:             nil,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusBadRequest,
		},
		"unsupported_room_version": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             validUser,
				RoomID:             validRoom,
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
				UserID:             validUser,
				RoomID:             validRoom,
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
		"nil_querier": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        nil,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusInternalServerError,
		},
		"server_in_room_error": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             validUser,
				RoomID:             validRoom,
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
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{serverInRoom: true},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     http.StatusNotFound,
		},
		"server_not_in_room": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             validUser,
				RoomID:             validRoom,
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
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: true},
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
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: true},
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
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: true},
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
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: true},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return createEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     500,
		},
		"successful": {
			input: HandleMakeJoinInput{
				Context:            context.Background(),
				UserID:             validUser,
				RoomID:             validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				RequestDestination: localServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestJoinRoomQuerier{roomExists: true, serverInRoom: true},
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, *util.JSONResponse) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleMakeJoin(tc.input)
			if tc.expectedErr {
				assert.NotNil(t, joinErr)
				assert.Equal(t, tc.errCode, joinErr.Code)
			} else {
				jsonBytes, err := json.Marshal(&joinErr)
				assert.Nil(t, err)
				assert.Nil(t, joinErr, string(jsonBytes))
			}
		})
	}
}
