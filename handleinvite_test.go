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

type TestRoomQuerier struct {
	shouldFail bool
}

func (r *TestRoomQuerier) IsKnownRoom(ctx context.Context, roomID spec.RoomID) (bool, error) {
	if r.shouldFail {
		return false, fmt.Errorf("failed finding room")
	}
	return false, nil
}

type TestStateQuerier struct{}

func (r *TestStateQuerier) GetAuthEvents(ctx context.Context, event PDU) (AuthEventProvider, error) {
	return nil, nil
}

func (r *TestStateQuerier) GetState(ctx context.Context, roomID spec.RoomID, stateWanted []StateKeyTuple) ([]PDU, error) {
	return nil, nil
}

func TestHandleInvite(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	assert.Nil(t, err)
	validRoom, err := spec.NewRoomID("!room:server")
	assert.Nil(t, err)
	badRoom, err := spec.NewRoomID("!bad:room")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

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
		input       HandleInviteInput
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"unsupported_room_version": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorUnsupportedRoomVersion,
		},
		"mismatched_room_ids": {
			input: HandleInviteInput{
				RoomID:            *badRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"room_querier_error": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{shouldFail: true},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"success_no_room_state": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleInvite(context.Background(), tc.input)
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

func TestHandleInviteNilVerifier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")

	assert.Panics(t, func() {
		_, _ = HandleInvite(context.Background(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          nil,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
		})
	})
}

func TestHandleInviteNilRoomQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(context.Background(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       nil,
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
		})
	})
}

func TestHandleInviteNilMembershipQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(context.Background(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: nil,
			StateQuerier:      &TestStateQuerier{},
		})
	})
}

func TestHandleInviteNilStateQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(context.Background(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      nil,
		})
	})
}

func TestHandleInviteNilContext(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(nil, HandleInviteInput{ // nolint
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
		})
	})
}
