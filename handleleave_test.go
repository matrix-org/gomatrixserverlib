package gomatrixserverlib

import (
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

	stateKey = validUser.String()
	leaveEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     validUser.String(),
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
