package gomatrixserverlib

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

type TestFederatedInviteClient struct {
	shouldFail bool
}

func (f *TestFederatedInviteClient) SendInvite(ctx context.Context, event PDU, strippedState []InviteStrippedState) (PDU, error) {
	if f.shouldFail {
		return nil, fmt.Errorf("failed sending invite")
	}
	return nil, nil
}

func TestPerformInvite(t *testing.T) {
	inviteeID, err := spec.NewUserID("@invitee:server", true)
	assert.Nil(t, err)
	inviteeIDRemote, err := spec.NewUserID("@invitee:remote", true)
	assert.Nil(t, err)
	inviterID, err := spec.NewUserID("@inviter:server", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := inviteeID.String()
	eb := createMemberEventBuilder(inviterID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEvent, err := eb.Build(time.Now(), inviteeID.Domain(), keyID, sk)
	assert.Nil(t, err)

	stateKey = inviteeIDRemote.String()
	inviteRemoteEB := createMemberEventBuilder(inviterID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEventRemote, err := inviteRemoteEB.Build(time.Now(), inviteeIDRemote.Domain(), keyID, sk)
	assert.Nil(t, err)

	stateKey = inviterID.String()
	inviterMemberEventEB := createMemberEventBuilder(inviterID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"join"}`))
	inviterMemberEvent, err := inviterMemberEventEB.Build(time.Now(), inviteeID.Domain(), keyID, sk)
	assert.Nil(t, err)

	stateKey = ""
	createEventEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		Sender:     inviterID.String(),
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"creator":"@inviter:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := createEventEB.Build(time.Now(), inviterID.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       PerformInviteInput
		fedClient   FederatedInviteClient
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"not_allowed_by_auth_events": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeID,
				IsTargetLocal:     true,
				InviteEvent:       inviteEvent,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"auth_provider_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeID,
				IsTargetLocal:     true,
				InviteEvent:       inviteEvent,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{shouldFailAuth: true},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"state_provider_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeID,
				IsTargetLocal:     true,
				InviteEvent:       inviteEvent,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{shouldFailState: true},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     InternalErr,
		},
		"already_joined_failure": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeID,
				IsTargetLocal:     true,
				InviteEvent:       inviteEvent,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"remote_invite_federation_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeIDRemote,
				IsTargetLocal:     false,
				InviteEvent:       inviteEventRemote,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{createEvent: createEvent, inviterMemberEvent: inviterMemberEvent},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{shouldFail: true},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"success_local": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeID,
				IsTargetLocal:     true,
				InviteEvent:       inviteEvent,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{createEvent: createEvent, inviterMemberEvent: inviterMemberEvent},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: false,
		},
		"success_remote": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *inviteeIDRemote,
				IsTargetLocal:     false,
				InviteEvent:       inviteEventRemote,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{createEvent: createEvent, inviterMemberEvent: inviterMemberEvent},
				UserIDQuerier:     UserIDForSenderTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := PerformInvite(context.Background(), tc.input, tc.fedClient)
			if tc.expectedErr {
				switch e := joinErr.(type) {
				case nil:
					t.Fatalf("Error should not be nil")
				case spec.InternalServerError:
					assert.Equal(t, tc.errType, InternalErr)
				case spec.MatrixError:
					assert.Equal(t, tc.errType, MatrixErr)
					assert.Equal(t, tc.errCode, e.ErrCode)
				default:
					t.Fatalf("Unexpected Error Type")
				}
			} else {
				jsonBytes, err := json.Marshal(&joinErr)
				assert.Nil(t, err)
				assert.Nil(t, joinErr, string(jsonBytes))
			}
		})
	}
}

func TestPerformInviteNilMembershipQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	eb := createMemberEventBuilder(userID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	assert.Nil(t, err)

	assert.Panics(t, func() {
		_, _ = PerformInvite(context.Background(), PerformInviteInput{
			RoomID:            *validRoom,
			InvitedUser:       *userID,
			IsTargetLocal:     true,
			InviteEvent:       inviteEvent,
			StrippedState:     []InviteStrippedState{},
			MembershipQuerier: nil,
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilStateQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	eb := createMemberEventBuilder(userID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	assert.Nil(t, err)

	assert.Panics(t, func() {
		_, _ = PerformInvite(context.Background(), PerformInviteInput{
			RoomID:            *validRoom,
			InvitedUser:       *userID,
			IsTargetLocal:     true,
			InviteEvent:       inviteEvent,
			StrippedState:     []InviteStrippedState{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      nil,
			UserIDQuerier:     UserIDForSenderTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilUserIDQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	eb := createMemberEventBuilder(userID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	assert.Nil(t, err)

	assert.Panics(t, func() {
		_, _ = PerformInvite(context.Background(), PerformInviteInput{
			RoomID:            *validRoom,
			InvitedUser:       *userID,
			IsTargetLocal:     true,
			InviteEvent:       inviteEvent,
			StrippedState:     []InviteStrippedState{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     nil,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilContext(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	eb := createMemberEventBuilder(userID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	assert.Nil(t, err)

	assert.Panics(t, func() {
		_, _ = PerformInvite(nil, PerformInviteInput{ // nolint
			RoomID:            *validRoom,
			InvitedUser:       *userID,
			IsTargetLocal:     true,
			InviteEvent:       inviteEvent,
			StrippedState:     []InviteStrippedState{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
		}, &TestFederatedInviteClient{})
	})
}
