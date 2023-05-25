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

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       PerformInviteInput
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"not_allowed_by_auth_events": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				InvitedUser:       *userID,
				IsTargetLocal:     true,
				InviteEvent:       inviteEvent,
				StrippedState:     []InviteStrippedState{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := PerformInvite(context.Background(), tc.input, &TestFederatedInviteClient{})
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
		}, &TestFederatedInviteClient{})
	})
}
