package gomatrixserverlib

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/matrix-org/gomatrix"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
	ed255192 "golang.org/x/crypto/ed25519"
)

type TestMakeJoinResponse struct {
	roomVersion RoomVersion
	joinEvent   ProtoEvent
}

func (t *TestMakeJoinResponse) GetJoinEvent() ProtoEvent {
	return t.joinEvent
}

func (t *TestMakeJoinResponse) GetRoomVersion() RoomVersion {
	return t.roomVersion
}

type TestSendJoinResponse struct {
	createEvent PDU
	joinEvent   PDU
}

func (t *TestSendJoinResponse) GetAuthEvents() EventJSONs {
	return EventJSONs{t.createEvent.JSON(), t.joinEvent.JSON()}
}

func (t *TestSendJoinResponse) GetStateEvents() EventJSONs {
	return EventJSONs{t.createEvent.JSON()}
}

func (t *TestSendJoinResponse) GetOrigin() spec.ServerName {
	return "server"
}

func (t *TestSendJoinResponse) GetJoinEvent() spec.RawJSON {
	return t.joinEvent.JSON()
}

func (t *TestSendJoinResponse) GetMembersOmitted() bool {
	return true
}

func (t *TestSendJoinResponse) GetServersInRoom() []string {
	return []string{"server"}
}

type TestFederatedJoinClient struct {
	shouldMakeFail   bool
	shouldSendFail   bool
	roomVersion      RoomVersion
	createEvent      PDU
	joinEvent        PDU
	joinEventBuilder ProtoEvent
}

func (t *TestFederatedJoinClient) MakeJoin(ctx context.Context, origin, s spec.ServerName, roomID, userID string) (res MakeJoinResponse, err error) {
	if t.shouldMakeFail {
		return nil, gomatrix.HTTPError{}
	}

	return &TestMakeJoinResponse{joinEvent: t.joinEventBuilder, roomVersion: t.roomVersion}, nil
}
func (t *TestFederatedJoinClient) SendJoin(ctx context.Context, origin, s spec.ServerName, event PDU) (res SendJoinResponse, err error) {
	if t.shouldSendFail {
		return nil, gomatrix.HTTPError{}
	}

	return &TestSendJoinResponse{createEvent: t.createEvent, joinEvent: t.joinEvent}, nil
}

type joinKeyDatabase struct{ key ed25519.PublicKey }

func (db joinKeyDatabase) FetcherName() string {
	return "joinKeyDatabase"
}

func (db *joinKeyDatabase) FetchKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]spec.Timestamp,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}

	req1 := PublicKeyLookupRequest{"server", "ed25519:1234"}

	for req := range requests {
		if req == req1 {
			k, err := hex.DecodeString(hex.EncodeToString(db.key))
			vk := VerifyKey{Key: k}
			if err != nil {
				return nil, err
			}
			results[req] = PublicKeyLookupResult{
				VerifyKey:    vk,
				ValidUntilTS: spec.Timestamp(time.Now().Add(time.Hour).Unix() * 1000),
				ExpiredTS:    PublicKeyNotExpired,
			}
		}
	}
	return results, nil
}

func (db *joinKeyDatabase) StoreKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]PublicKeyLookupResult,
) error {
	return nil
}

func TestPerformJoin(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	userID, err := spec.NewUserID("@user:server", true)
	if err != nil {
		t.Fatalf("Invalid UserID: %v", err)
	}
	roomID, err := spec.NewRoomID("!room:server")
	if err != nil {
		t.Fatalf("Invalid RoomID: %v", err)
	}

	stateKey := ""
	eb := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     roomID.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    spec.RawJSON(`{"creator":"@user:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	stateKey = userID.String()
	joinProto := ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     roomID.String(),
		Type:       "m.room.member",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    spec.RawJSON(`{"membership":"join"}`),
		Unsigned:   spec.RawJSON(""),
	}
	joinEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&joinProto)
	joinEvent, err := joinEB.Build(time.Now(), userID.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	eventProvider := func(roomVer RoomVersion, eventIDs []string) ([]PDU, error) {
		for _, eventID := range eventIDs {
			if eventID == createEvent.EventID() {
				return []PDU{createEvent}, nil
			}
		}
		return []PDU{}, nil
	}

	tests := map[string]struct {
		FedClient           FederatedJoinClient
		Input               PerformJoinInput
		ExpectedErr         bool
		ExpectedHTTPErr     bool
		ExpectedRoomVersion RoomVersion
	}{
		"invalid_user_id": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionV10},
			Input: PerformJoinInput{
				UserID:        nil,
				RoomID:        roomID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_room_id": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionV10},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        nil,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_key_ring": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionV10},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				KeyRing:       nil,
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"make_join_http_err": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: true, shouldSendFail: false, roomVersion: RoomVersionV10},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"send_join_http_err": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: true, roomVersion: RoomVersionV10},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"default_room_version": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: "", createEvent: createEvent, joinEvent: joinEvent, joinEventBuilder: joinProto},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				EventProvider: eventProvider,
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         false,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: RoomVersionV4,
		},
		"successful_join": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionV10, createEvent: createEvent, joinEvent: joinEvent, joinEventBuilder: joinProto},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				EventProvider: eventProvider,
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         false,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := PerformJoin(context.Background(), tc.FedClient, tc.Input)
			if tc.ExpectedErr {
				if err == nil {
					t.Fatalf("Expected an error but none received")
				}
				if tc.ExpectedHTTPErr {
					var httpErr gomatrix.HTTPError
					if ok := errors.As(err.Err, &httpErr); !ok {
						t.Fatalf("Expected HTTPError, got: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected err: %v", err)
				}
				if res == nil {
					t.Fatalf("Nil response received")
				}

				if res.JoinEvent.EventID() != joinEvent.EventID() {
					t.Fatalf("Expected join eventID %v, got %v", joinEvent.EventID(), res.JoinEvent.EventID())
				}
				if res.JoinEvent.Version() != tc.ExpectedRoomVersion {
					t.Fatalf("Expected room version %v, got %v", tc.ExpectedRoomVersion, res.JoinEvent.Version())
				}
			}
		})
	}
}

func TestPerformJoinPseudoID(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
	keyID := KeyID("ed25519:1234")
	userID, err := spec.NewUserID("@user:server", true)
	if err != nil {
		t.Fatalf("Invalid UserID: %v", err)
	}
	roomID, err := spec.NewRoomID("!room:server")
	if err != nil {
		t.Fatalf("Invalid RoomID: %v", err)
	}

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	pseudoID := spec.SenderIDFromPseudoIDKey(userPriv)

	rv := RoomVersionPseudoIDs
	cr := CreateContent{Creator: string(pseudoID), RoomVersion: &rv}
	crBytes, err := json.Marshal(cr)
	assert.Nil(t, err)

	mapping := MXIDMapping{UserID: userID.String(), UserRoomKey: pseudoID}
	err = mapping.Sign("server", keyID, sk)
	assert.Nil(t, err)
	content := MemberContent{Membership: spec.Join, MXIDMapping: &mapping}
	contentBytes, err := json.Marshal(content)
	assert.Nil(t, err)

	stateKey := ""
	eb := MustGetRoomVersion(rv).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   string(mapping.UserRoomKey),
		RoomID:     roomID.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      1,
		Content:    crBytes,
		Unsigned:   spec.RawJSON(""),
	})
	createEvent, err := eb.Build(time.Now(), "self", "ed25519:1", userPriv)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	stateKey = string(pseudoID)
	joinProto := ProtoEvent{
		SenderID:   string(mapping.UserRoomKey),
		RoomID:     roomID.String(),
		Type:       "m.room.member",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      2,
		Content:    contentBytes,
		Unsigned:   spec.RawJSON(""),
	}
	joinEB := MustGetRoomVersion(rv).NewEventBuilderFromProtoEvent(&joinProto)
	joinEvent, err := joinEB.Build(time.Now(), "self", "ed25519:1", sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}
	eventProvider := func(roomVer RoomVersion, eventIDs []string) ([]PDU, error) {
		var res []PDU
		for _, eventID := range eventIDs {
			if eventID == createEvent.EventID() {
				res = append(res, createEvent)
			}
			if eventID == joinEvent.EventID() {
				res = append(res, joinEvent)
			}
		}
		return res, nil
	}

	idCreator := func(ctx context.Context, userID spec.UserID, roomID spec.RoomID, roomVersion string) (spec.SenderID, ed255192.PrivateKey, error) {
		return spec.SenderIDFromPseudoIDKey(userPriv), userPriv, nil
	}

	tests := map[string]struct {
		FedClient           FederatedJoinClient
		Input               PerformJoinInput
		ExpectedErr         bool
		ExpectedHTTPErr     bool
		ExpectedRoomVersion RoomVersion
	}{
		"invalid_user_id": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionPseudoIDs},
			Input: PerformJoinInput{
				UserID:          nil,
				RoomID:          roomID,
				KeyRing:         &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:   UserIDForSenderTest,
				SenderIDCreator: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_room_id": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionPseudoIDs},
			Input: PerformJoinInput{
				UserID:          userID,
				RoomID:          nil,
				KeyRing:         &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:   UserIDForSenderTest,
				SenderIDCreator: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_key_ring": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionPseudoIDs},
			Input: PerformJoinInput{
				UserID:          userID,
				RoomID:          roomID,
				KeyRing:         nil,
				UserIDQuerier:   UserIDForSenderTest,
				SenderIDCreator: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"make_join_http_err": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: true, shouldSendFail: false, roomVersion: RoomVersionPseudoIDs},
			Input: PerformJoinInput{
				UserID:          userID,
				RoomID:          roomID,
				KeyRing:         &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:   UserIDForSenderTest,
				SenderIDCreator: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"send_join_http_err": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: true, roomVersion: RoomVersionPseudoIDs},
			Input: PerformJoinInput{
				UserID:          userID,
				RoomID:          roomID,
				PrivateKey:      sk,
				KeyID:           keyID,
				KeyRing:         &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:   UserIDForSenderTest,
				SenderIDCreator: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"successful_join": {
			FedClient: &TestFederatedJoinClient{shouldMakeFail: false, shouldSendFail: false, roomVersion: RoomVersionPseudoIDs, createEvent: createEvent, joinEvent: joinEvent, joinEventBuilder: joinProto},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				EventProvider: eventProvider,
				UserIDQuerier: func(roomID spec.RoomID, senderID spec.SenderID) (*spec.UserID, error) {
					return userID, nil
				},
				StoreSenderIDFromPublicID: func(ctx context.Context, senderID spec.SenderID, userID string, id spec.RoomID) error {
					return nil
				},
				SenderIDCreator: idCreator,
			},
			ExpectedErr:         false,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := PerformJoin(context.Background(), tc.FedClient, tc.Input)
			if tc.ExpectedErr {
				if err == nil {
					t.Fatalf("Expected an error but none received")
				}
				if tc.ExpectedHTTPErr {
					var httpErr gomatrix.HTTPError
					if ok := errors.As(err.Err, &httpErr); !ok {
						t.Fatalf("Expected HTTPError, got: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected err: %v", err)
				}
				if res == nil {
					t.Fatalf("Nil response received")
				}

				if res.JoinEvent.EventID() != joinEvent.EventID() {
					t.Fatalf("Expected join eventID %v, got %v", joinEvent.EventID(), res.JoinEvent.EventID())
				}
				if res.JoinEvent.Version() != tc.ExpectedRoomVersion {
					t.Fatalf("Expected room version %v, got %v", tc.ExpectedRoomVersion, res.JoinEvent.Version())
				}
			}
		})
	}
}
