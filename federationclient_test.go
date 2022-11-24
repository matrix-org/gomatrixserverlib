package gomatrixserverlib_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"golang.org/x/crypto/ed25519"
)

type roundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.fn(req)
}

// The purpose of this test is to make sure that if /v2/send_join 404s we automatically
// fallback to /v1/send_join and seamlessly handle the different response format.
func TestSendJoinFallback(t *testing.T) {
	serverName := gomatrixserverlib.ServerName("local.server.name")
	targetServerName := gomatrixserverlib.ServerName("target.server.name")
	keyID := gomatrixserverlib.KeyID("ed25519:auto")
	_, privateKey, _ := ed25519.GenerateKey(nil)
	roomVer := gomatrixserverlib.RoomVersionV1
	// we don't care about the actual contents, just that it ferries data across fine.
	retEv := gomatrixserverlib.RawJSON(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`)
	wantRes := gomatrixserverlib.RespSendJoin{
		StateEvents: gomatrixserverlib.EventJSONs{
			retEv,
		},
	}
	v1Res := []interface{}{
		200, wantRes,
	}
	v1ResBytes, err := json.Marshal(v1Res)
	if err != nil {
		t.Fatalf("failed to marshal RespSendJoin: %s", err)
	}
	fc := gomatrixserverlib.NewFederationClient(
		serverName, keyID, privateKey,
		gomatrixserverlib.WithSkipVerify(true),
	)
	fc.Client = *gomatrixserverlib.NewClient(gomatrixserverlib.WithTransport(
		&roundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if strings.HasPrefix(req.URL.Path, "/_matrix/federation/v2/send_join") {
					return &http.Response{
						StatusCode: 404,
						Body:       ioutil.NopCloser(strings.NewReader("404 not found")),
					}, nil
				}
				if !strings.HasPrefix(req.URL.Path, "/_matrix/federation/v1/send_join") {
					return nil, fmt.Errorf("test: unexpected url path: %s", req.URL.Path)
				}
				t.Logf("Sending response: %s", string(v1ResBytes))
				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(bytes.NewReader(v1ResBytes)),
				}, nil
			},
		},
	))
	ev, err := gomatrixserverlib.NewEventFromTrustedJSON(
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		false, roomVer,
	)
	if err != nil {
		t.Fatalf("failed to read event json: %s", err)
	}
	res, err := fc.SendJoin(context.Background(), targetServerName, ev)
	if err != nil {
		t.Fatalf("SendJoin returned an error: %s", err)
	}
	if !reflect.DeepEqual(res.StateEvents, wantRes.StateEvents) {
		t.Fatalf("SendJoin response got %+v want %+v", res.StateEvents, wantRes.StateEvents)
	}
}

// The purpose of this test is to ensure that the federation client is capable of marshalling into
// a RespSendJoin response type. This is mostly a sanity check that EventJSON and EventJSONs behave
// correctly.
func TestSendJoinJSON(t *testing.T) {
	serverName := gomatrixserverlib.ServerName("local.server.name")
	targetServerName := gomatrixserverlib.ServerName("target.server.name")
	keyID := gomatrixserverlib.KeyID("ed25519:auto")
	_, privateKey, _ := ed25519.GenerateKey(nil)
	roomVer := gomatrixserverlib.RoomVersionV1
	// we don't care about the actual contents, just that it ferries data across fine.
	retEv := gomatrixserverlib.RawJSON(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`)
	respSendJoinResponseJSON := []byte(fmt.Sprintf(`{
		"state": [%s],
		"auth_chain": [%s]
	}`, string(retEv), string(retEv)))

	fc := gomatrixserverlib.NewFederationClient(
		serverName, keyID, privateKey,
		gomatrixserverlib.WithSkipVerify(true),
	)
	fc.Client = *gomatrixserverlib.NewClient(gomatrixserverlib.WithTransport(
		&roundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if strings.HasPrefix(req.URL.Path, "/_matrix/federation/v2/send_join") {
					t.Logf("Sending response: %s", string(respSendJoinResponseJSON))
					return &http.Response{
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewReader(respSendJoinResponseJSON)),
					}, nil
				}
				return &http.Response{
					StatusCode: 404,
					Body:       ioutil.NopCloser(strings.NewReader("404 not found")),
				}, nil
			},
		},
	))
	ev, err := gomatrixserverlib.NewEventFromTrustedJSON(
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		false, roomVer,
	)
	if err != nil {
		t.Fatalf("failed to read event json: %s", err)
	}
	res, err := fc.SendJoin(context.Background(), targetServerName, ev)
	if err != nil {
		t.Fatalf("SendJoin returned an error: %s", err)
	}
	wantStateEvents := gomatrixserverlib.EventJSONs{[]byte(retEv)}
	wantAuthChain := gomatrixserverlib.EventJSONs{[]byte(retEv)}
	if !reflect.DeepEqual(res.StateEvents, wantStateEvents) {
		t.Fatalf("SendJoin response got state %+v want %+v", jsonify(res.StateEvents), jsonify(wantStateEvents))
	}
	if !reflect.DeepEqual(res.AuthEvents, wantAuthChain) {
		t.Fatalf("SendJoin response got auth %+v want %+v", jsonify(res.AuthEvents), jsonify(wantAuthChain))
	}
}

func TestSendAsyncTransaction(t *testing.T) {
	user, err := gomatrixserverlib.NewUserID("@user:target.server.name", false)
	if err != nil {
		t.Fatalf("failed to read event json: %s", err)
	}
	serverName := gomatrixserverlib.ServerName("local.server.name")
	targetServerName := user.Domain()
	keyID := gomatrixserverlib.KeyID("ed25519:auto")
	_, privateKey, _ := ed25519.GenerateKey(nil)
	respSendAsyncResponseJSON := []byte(fmt.Sprintf(`{"error": ""}`))

	fc := gomatrixserverlib.NewFederationClient(
		serverName, keyID, privateKey,
		gomatrixserverlib.WithSkipVerify(true),
	)
	fc.Client = *gomatrixserverlib.NewClient(gomatrixserverlib.WithTransport(
		&roundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if strings.HasPrefix(req.URL.Path, "/_matrix/federation/v1/forward_async") {
					return &http.Response{
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewReader(respSendAsyncResponseJSON)),
					}, nil
				}
				return &http.Response{
					StatusCode: 404,
					Body:       ioutil.NopCloser(strings.NewReader("404 not found")),
				}, nil
			},
		},
	))

	txn := createTransaction(serverName, targetServerName, *user)
	forwardingServer := gomatrixserverlib.ServerName("mailbox.server")
	_, err = fc.SendAsyncTransaction(context.Background(), *user, txn, forwardingServer)
	if err != nil {
		t.Fatalf("SendAsyncTransaction returned an error: %s", err)
	}
}

func TestSendAsyncTransactionReportsFailure(t *testing.T) {
	user, err := gomatrixserverlib.NewUserID("@user:target.server.name", false)
	if err != nil {
		t.Fatalf("failed to read event json: %s", err)
	}
	serverName := gomatrixserverlib.ServerName("local.server.name")
	targetServerName := user.Domain()
	keyID := gomatrixserverlib.KeyID("ed25519:auto")
	_, privateKey, _ := ed25519.GenerateKey(nil)
	errorMessage := "Invalid transaction"
	respSendAsyncResponseJSON := []byte(fmt.Sprintf(`{"error": "%s"}`, errorMessage))

	fc := gomatrixserverlib.NewFederationClient(
		serverName, keyID, privateKey,
		gomatrixserverlib.WithSkipVerify(true),
	)
	fc.Client = *gomatrixserverlib.NewClient(gomatrixserverlib.WithTransport(
		&roundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if strings.HasPrefix(req.URL.Path, "/_matrix/federation/v1/forward_async") {
					return &http.Response{
						StatusCode: 400,
						Body:       ioutil.NopCloser(bytes.NewReader(respSendAsyncResponseJSON)),
					}, nil
				}
				return &http.Response{
					StatusCode: 404,
					Body:       ioutil.NopCloser(strings.NewReader("404 not found")),
				}, nil
			},
		},
	))

	txn := createTransaction(serverName, targetServerName, *user)
	forwardingServer := gomatrixserverlib.ServerName("mailbox.server")
	_, err = fc.SendAsyncTransaction(context.Background(), *user, txn, forwardingServer)
	if err == nil {
		t.Fatalf("SendAsyncTransaction didn't return an error")
	}
	if !strings.Contains(err.Error(), errorMessage) {
		t.Fatalf("Error doesn't contain correct message: %s", err.Error())
	}
}

func createTransaction(
	testOrigin gomatrixserverlib.ServerName,
	testDestination gomatrixserverlib.ServerName,
	userID gomatrixserverlib.UserID,
) gomatrixserverlib.Transaction {
	txn := gomatrixserverlib.Transaction{}
	txn.PDUs = []json.RawMessage{
		[]byte(`{"auth_events":[["$0ok8ynDp7kjc95e3:kaer.morhen",{"sha256":"sWCi6Ckp9rDimQON+MrUlNRkyfZ2tjbPbWfg2NMB18Q"}],["$LEwEu0kxrtu5fOiS:kaer.morhen",{"sha256":"1aKajq6DWHru1R1HJjvdWMEavkJJHGaTmPvfuERUXaA"}]],"content":{"body":"Test Message"},"depth":5,"event_id":"$gl2T9l3qm0kUbiIJ:kaer.morhen","hashes":{"sha256":"Qx3nRMHLDPSL5hBAzuX84FiSSP0K0Kju2iFoBWH4Za8"},"origin":"kaer.morhen","origin_server_ts":0,"prev_events":[["$UKNe10XzYzG0TeA9:kaer.morhen",{"sha256":"KtSRyMjt0ZSjsv2koixTRCxIRCGoOp6QrKscsW97XRo"}]],"room_id":"!roomid:kaer.morhen","sender":"@userid:kaer.morhen","signatures":{"kaer.morhen":{"ed25519:auto":"sqDgv3EG7ml5VREzmT9aZeBpS4gAPNIaIeJOwqjDhY0GPU/BcpX5wY4R7hYLrNe5cChgV+eFy/GWm1Zfg5FfDg"}},"type":"m.room.message"}`),
	}
	txn.Origin = testOrigin
	txn.TransactionID = gomatrixserverlib.TransactionID(fmt.Sprintf("%d", time.Now().UnixNano()))
	txn.Destination = testDestination
	var federationPathPrefixV1 = "/_matrix/federation/v1"
	path := federationPathPrefixV1 + "/forward_async/" + string(txn.TransactionID) + "/" + userID.Raw()
	request := gomatrixserverlib.NewFederationRequest("PUT", txn.Destination, path)
	request.SetContent(txn)

	return txn
}

func jsonify(x interface{}) string {
	b, _ := json.Marshal(x)
	return string(b)
}
