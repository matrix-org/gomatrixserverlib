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
	knownRoom  bool
}

func (r *TestRoomQuerier) IsKnownRoom(ctx context.Context, roomID spec.RoomID) (bool, error) {
	if r.shouldFail {
		return false, fmt.Errorf("failed finding room")
	}
	return r.knownRoom, nil
}

type TestStateQuerier struct {
	shouldFailState    bool
	shouldFailAuth     bool
	state              []PDU
	createEvent        PDU
	inviterMemberEvent PDU
}

func (r *TestStateQuerier) GetAuthEvents(ctx context.Context, event PDU) (AuthEventProvider, error) {
	if r.shouldFailAuth {
		return nil, fmt.Errorf("failed getting auth provider")
	}

	eventProvider := AuthEvents{}
	if r.createEvent != nil {
		eventProvider = NewAuthEvents([]PDU{r.createEvent})
		if r.inviterMemberEvent != nil {
			err := eventProvider.AddEvent(r.inviterMemberEvent)
			if err != nil {
				return nil, err
			}
		}
	}
	return &eventProvider, nil
}

func (r *TestStateQuerier) GetState(ctx context.Context, roomID spec.RoomID, stateWanted []StateKeyTuple) ([]PDU, error) {
	if r.shouldFailState {
		return nil, fmt.Errorf("failed getting state")
	}
	return r.state, nil
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
	eb := createMemberEventBuilder(RoomVersionV10, userID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	inviteEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	assert.Nil(t, err)

	stateKey = ""
	createEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"creator":"@user:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := createEB.Build(time.Now(), userID.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

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
				UserIDQuerier:     UserIDForSenderTest,
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
				UserIDQuerier:     UserIDForSenderTest,
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
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_no_state": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_already_joined": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
				StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"known_room_state_query_error": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{membership: ""},
				StateQuerier:      &TestStateQuerier{shouldFailState: true},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined_membership_error": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{memberEventErr: true},
				StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{membership: ""},
				StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: false,
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
				UserIDQuerier:     UserIDForSenderTest,
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
			UserIDQuerier:     UserIDForSenderTest,
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
			UserIDQuerier:     UserIDForSenderTest,
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
			UserIDQuerier:     UserIDForSenderTest,
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
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteNilUserIDQuerier(t *testing.T) {
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
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     nil,
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
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteV3(t *testing.T) {
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
	inviteEvent := createMemberProtoEvent(userID.String(), validRoom.String(), &stateKey, spec.RawJSON(`{"membership":"invite"}`))
	assert.Nil(t, err)

	stateKey = ""
	createEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"creator":"@user:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := createEB.Build(time.Now(), userID.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       HandleInviteV3Input
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"unsupported_room_version": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       "",
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorUnsupportedRoomVersion,
		},
		"mismatched_room_ids": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *badRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"room_querier_error": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{shouldFail: true},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_no_state": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_already_joined": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
					StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"known_room_state_query_error": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{membership: ""},
					StateQuerier:      &TestStateQuerier{shouldFailState: true},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined_membership_error": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{memberEventErr: true},
					StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{membership: ""},
					StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: false,
		},
		"success_no_room_state": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleInviteV3(context.Background(), tc.input)
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

func TestHandleInviteV3NilVerifier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(context.Background(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          nil,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilRoomQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(context.Background(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       nil,
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilMembershipQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(context.Background(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: nil,
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilStateQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(context.Background(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      nil,
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilUserIDQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(context.Background(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     nil,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilContext(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	assert.Nil(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(nil, HandleInviteV3Input{ //nolint
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}
