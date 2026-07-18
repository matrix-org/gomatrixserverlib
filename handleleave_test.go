package gomatrixserverlib

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestHandleMakeLeave(t *testing.T) {
	validUser, err := spec.NewUserID("@user:remote", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)
	joinedUser, err := spec.NewUserID("@joined:local", true)
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")

	stateKey := ""
	eb := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
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
		SenderID:   validUser.String(),
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
	powerLevelsEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
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
		SenderID:   validUser.String(),
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

	stateKey = validUser.String()
	leaveEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{powerLevelsEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID(), powerLevelsEvent.EventID()},
		Depth:      3,
		Content:    spec.RawJSON(`{"membership":"leave"}`),
		Unsigned:   spec.RawJSON(""),
	})
	leaveEvent, err := leaveEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join event: %v", err)
	}

	tests := []struct {
		name    string
		input   HandleMakeLeaveInput
		want    *HandleMakeLeaveResponse
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "wrong destination",
			input: HandleMakeLeaveInput{
				UserID:        *joinedUser,
				RequestOrigin: "notLocalhost",
			},
			wantErr: assert.Error,
		},
		{
			name: "localhost not in room",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: false,
				UserIDQuerier:     UserIDForSenderTest,
			},
			wantErr: assert.Error,
		},
		{
			name: "template error",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return nil, nil, fmt.Errorf("error")
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "template error - no event",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return nil, nil, nil
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "template error - no state",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, nil, nil
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "template error - not a membership event",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return createEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "not allowed to leave, wrong state events",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return leaveEvent, []PDU{joinRulesEvent}, nil
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "allowed to leave",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return leaveEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HandleMakeLeave(tt.input)
			if !tt.wantErr(t, err, fmt.Sprintf("HandleMakeLeave(%v)", tt.input)) {
				return
			}
		})
	}
}

type dummyQuerier struct {
	pdu PDU
}

func (d dummyQuerier) CurrentStateEvent(ctx context.Context, roomID spec.RoomID, eventType string, stateKey string) (PDU, error) {
	return d.pdu, nil
}

type noopJSONVerifier struct {
	err     error
	results []VerifyJSONResult
}

func (v *noopJSONVerifier) VerifyJSONs(ctx context.Context, requests []VerifyJSONRequest) ([]VerifyJSONResult, error) {
	return v.results, v.err
}

func TestHandleSendLeave(t *testing.T) {
	type args struct {
		ctx            context.Context
		requestContent []byte
		origin         spec.ServerName
		roomVersion    RoomVersion
		eventID        string
		roomID         string
		querier        CurrentStateQuerier
		verifier       JSONVerifier
	}

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")

	validUser, _ := spec.NewUserID("@valid:localhost", true)

	stateKey := ""
	eb := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     "!valid:localhost",
		Type:       spec.MRoomCreate,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"creator":"@user:local","m.federate":true,"room_version":"10"}`),
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := eb.Build(time.Now(), "localhost", keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	stateKey = validUser.String()
	eb = MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     "!valid:localhost",
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"membership":"leave"}`),
		Unsigned:   spec.RawJSON(""),
	})
	leaveEvent, err := eb.Build(time.Now(), "localhost", keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	eb = MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     "!valid:localhost",
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"membership":"join"}`),
		Unsigned:   spec.RawJSON(""),
	})
	joinEvent, err := eb.Build(time.Now(), "localhost", keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	tests := []struct {
		name    string
		args    args
		want    PDU
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "invalid roomID",
			args:    args{roomID: "@notvalid:localhost"},
			wantErr: assert.Error,
		},
		{
			name:    "invalid room version",
			args:    args{roomID: "!notvalid:localhost", roomVersion: "-1"},
			wantErr: assert.Error,
		},
		{
			name:    "invalid content body",
			args:    args{roomID: "!notvalid:localhost", roomVersion: RoomVersionV1, requestContent: []byte("{")},
			wantErr: assert.Error,
		},
		{
			name:    "not canonical JSON",
			args:    args{roomID: "!notvalid:localhost", roomVersion: RoomVersionV10, requestContent: []byte(`{"int":9007199254740992}`)}, // number to large, not canonical json
			wantErr: assert.Error,
		},
		{
			name:    "wrong roomID in request",
			args:    args{roomID: "!notvalid:localhost", roomVersion: RoomVersionV10, requestContent: createEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "wrong eventID in request",
			args:    args{roomID: "!valid:localhost", roomVersion: RoomVersionV10, requestContent: createEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "empty statekey",
			args:    args{roomID: "!valid:localhost", roomVersion: RoomVersionV10, eventID: createEvent.EventID(), requestContent: createEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "wrong request origin",
			args:    args{roomID: "!valid:localhost", roomVersion: RoomVersionV10, eventID: leaveEvent.EventID(), requestContent: leaveEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "never joined the room no-ops",
			args:    args{roomID: "!valid:localhost", querier: dummyQuerier{}, origin: validUser.Domain(), roomVersion: RoomVersionV10, eventID: leaveEvent.EventID(), requestContent: leaveEvent.JSON()},
			wantErr: assert.NoError,
		},
		{
			name:    "already left the room no-ops",
			args:    args{roomID: "!valid:localhost", querier: dummyQuerier{pdu: leaveEvent}, origin: validUser.Domain(), roomVersion: RoomVersionV10, eventID: leaveEvent.EventID(), requestContent: leaveEvent.JSON()},
			wantErr: assert.NoError,
		},
		{
			name:    "JSON validation fails",
			args:    args{ctx: context.Background(), roomID: "!valid:localhost", querier: dummyQuerier{pdu: createEvent}, verifier: &noopJSONVerifier{err: fmt.Errorf("err")}, origin: validUser.Domain(), roomVersion: RoomVersionV10, eventID: leaveEvent.EventID(), requestContent: leaveEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "JSON validation fails 2",
			args:    args{ctx: context.Background(), roomID: "!valid:localhost", querier: dummyQuerier{pdu: createEvent}, verifier: &noopJSONVerifier{results: []VerifyJSONResult{{Error: fmt.Errorf("err")}}}, origin: validUser.Domain(), roomVersion: RoomVersionV10, eventID: leaveEvent.EventID(), requestContent: leaveEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "membership not set to leave",
			args:    args{ctx: context.Background(), roomID: "!valid:localhost", querier: dummyQuerier{pdu: createEvent}, verifier: &noopJSONVerifier{results: []VerifyJSONResult{{}}}, origin: validUser.Domain(), roomVersion: RoomVersionV10, eventID: joinEvent.EventID(), requestContent: joinEvent.JSON()},
			wantErr: assert.Error,
		},
		{
			name:    "membership set to leave",
			args:    args{ctx: context.Background(), roomID: "!valid:localhost", querier: dummyQuerier{pdu: createEvent}, verifier: &noopJSONVerifier{results: []VerifyJSONResult{{}}}, origin: validUser.Domain(), roomVersion: RoomVersionV10, eventID: leaveEvent.EventID(), requestContent: leaveEvent.JSON()},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HandleSendLeave(tt.args.ctx, tt.args.requestContent, tt.args.origin, tt.args.roomVersion, tt.args.eventID, tt.args.roomID, tt.args.querier, tt.args.verifier)
			if !tt.wantErr(t, err, fmt.Sprintf("HandleSendLeave(%v, %v, %v, %v, %v, %v, %v, %v)", tt.args.ctx, tt.args.requestContent, tt.args.origin, tt.args.roomVersion, tt.args.eventID, tt.args.roomID, tt.args.querier, tt.args.verifier)) {
				return
			}
		})
	}
}
