package gomatrixserverlib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"
)

type testBackfillRequester struct {
	servers                         []ServerName
	backfillFn                      func(server ServerName, roomID string, fromEventIDs []string, limit int) (*Transaction, error)
	authEventsToProvide             [][]byte
	stateIDsAtEvent                 map[string][]string
	callOrderForStateIDsBeforeEvent []string // event IDs called
}

func (t *testBackfillRequester) StateIDsBeforeEvent(ctx context.Context, atEvent *HeaderedEvent) ([]string, error) {
	t.callOrderForStateIDsBeforeEvent = append(t.callOrderForStateIDsBeforeEvent, atEvent.EventID())
	return t.stateIDsAtEvent[atEvent.EventID()], nil
}
func (t *testBackfillRequester) StateBeforeEvent(ctx context.Context, roomVer RoomVersion, event *HeaderedEvent, eventIDs []string) (map[string]*Event, error) {
	return nil, fmt.Errorf("not implemented")
}
func (t *testBackfillRequester) ServersAtEvent(ctx context.Context, roomID, eventID string) []ServerName {
	return t.servers
}
func (t *testBackfillRequester) Backfill(ctx context.Context, server ServerName, roomID string, limit int, fromEventIDs []string) (Transaction, error) {
	txn, err := t.backfillFn(server, roomID, fromEventIDs, limit)
	if err != nil {
		return Transaction{}, err
	}
	return *txn, nil
}
func (t *testBackfillRequester) ProvideEvents(roomVer RoomVersion, eventIDs []string) (result []*Event, err error) {
	eventMap := make(map[string]*Event)
	for _, eventBytes := range t.authEventsToProvide {
		ev, err := NewEventFromTrustedJSON(eventBytes, false, RoomVersionV1)
		if err != nil {
			panic("Failed to load event: " + err.Error())
		}
		eventMap[ev.EventID()] = ev
	}
	for _, id := range eventIDs {
		if ev, ok := eventMap[id]; ok {
			result = append(result, ev)
		}
	}
	return
}

type testNopJSONVerifier struct {
	// this verifier verifies nothing
}

func (t *testNopJSONVerifier) VerifyJSONs(ctx context.Context, requests []VerifyJSONRequest) ([]VerifyJSONResult, error) {
	result := make([]VerifyJSONResult, len(requests))
	return result, nil
}

// The purpose of this test is to make sure that RequestBackfill is hitting multiple servers if one server
// is returning a partial response. In this test, server A returns fewer than `limit` events, causing server B
// to be asked next, which returns a different set of events with a small amount of overlapping events.
// Together, the events from server A and server B exceed the `limit` criteria which then gets returned to the caller.
func TestRequestBackfillMultipleServers(t *testing.T) {
	ctx := context.Background()
	testRoomID := "!roomid:baba.is.you"
	serverA := ServerName("wall.is.stop")
	serverB := ServerName("baba.is.you")
	// currently we have no way of checking that the events returned link back to the from event, so anything works here.
	testFromEventIDs := []string{"foo"}
	testLimit := 3
	// To regenerate from Dendrite: $ ./create-room-events -Format Event -server-name baba.is.you
	// TODO: If /backfill is forced to only return prev_events then this test will fail,
	//       in which case we need to force a split in the DAG to test multi messages.
	testBackfillEvents := [][]byte{
		[]byte(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":3,"event_id":"$4Kp0G1yWZ6tNpeI7:baba.is.you","hashes":{"sha256":"B+MjcGZRh72iaGOgyNbIxgFkHDJo6NO8NQDgiKDKDBA"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$xOJZshi3NeKKJiCf:baba.is.you",{"sha256":"5PGENImHC863Yz9sO6IJX+bIQthZFI2RMhFZyFy+bC0"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"rP+Ybp17GPCqQBrTQ3yz+q6PihdaMWvNY3SngV8aDLHv8wdDlH4ULGnjsB+Az7trqYdCE3rZVo9M7Hy5tOObDg"}},"type":"m.room.message"}`),
	}
	keyRing := &testNopJSONVerifier{}
	tbr := &testBackfillRequester{
		servers:             []ServerName{serverA, serverB},
		authEventsToProvide: testBackfillEvents,
		stateIDsAtEvent: map[string][]string{
			"$4Kp0G1yWZ6tNpeI7:baba.is.you": {"$fnwGrQEpiOIUoDU2:baba.is.you", "$WCraVpPZe5TtHAqs:baba.is.you"},
			"$xOJZshi3NeKKJiCf:baba.is.you": {"$fnwGrQEpiOIUoDU2:baba.is.you", "$WCraVpPZe5TtHAqs:baba.is.you"},
			"$fnwGrQEpiOIUoDU2:baba.is.you": {"$WCraVpPZe5TtHAqs:baba.is.you"},
			"$WCraVpPZe5TtHAqs:baba.is.you": nil,
		},
		backfillFn: func(server ServerName, roomID string, fromEventIDs []string, limit int) (*Transaction, error) {
			if roomID != testRoomID {
				return nil, fmt.Errorf("bad room id: %s", roomID)
			}
			if server == serverA {
				// server A returns events 1 and 3.
				return &Transaction{
					Origin:         serverA,
					OriginServerTS: AsTimestamp(time.Now()),
					PDUs: []json.RawMessage{
						testBackfillEvents[1], testBackfillEvents[3],
					},
				}, nil
			} else if server == serverB {
				// server B returns events 0 and 2 and 3.
				return &Transaction{
					Origin:         serverB,
					OriginServerTS: AsTimestamp(time.Now()),
					PDUs: []json.RawMessage{
						testBackfillEvents[0], testBackfillEvents[2], testBackfillEvents[3],
					},
				}, nil
			}
			return nil, fmt.Errorf("bad server name: %s", server)
		},
	}
	result, err := RequestBackfill(ctx, tbr, keyRing, testRoomID, RoomVersionV1, testFromEventIDs, testLimit)
	if err != nil {
		t.Fatalf("RequestBackfill got error: %s", err)
	}

	assertUnsortedEqual(t, result, testBackfillEvents)
}

// The purpose of this test is to ensure that the BackfillRequester calls StateProvider functions in
// topological order, regardless of how they are transmitted by the remote server.
func TestRequestBackfillTopologicalSort(t *testing.T) {
	ctx := context.Background()
	testRoomID := "!roomid:baba.is.you"
	serverA := ServerName("baba.is.you")
	// currently we have no way of checking that the events returned link back to the from event, so anything works here.
	testFromEventIDs := []string{"foo"}
	testLimit := 4
	wantOrder := []string{
		"$WCraVpPZe5TtHAqs:baba.is.you", "$fnwGrQEpiOIUoDU2:baba.is.you", "$xOJZshi3NeKKJiCf:baba.is.you", "$4Kp0G1yWZ6tNpeI7:baba.is.you",
	}
	// Mix the order up
	testBackfillEvents := [][]byte{
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`),
		// join event in the middle
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":3,"event_id":"$4Kp0G1yWZ6tNpeI7:baba.is.you","hashes":{"sha256":"B+MjcGZRh72iaGOgyNbIxgFkHDJo6NO8NQDgiKDKDBA"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$xOJZshi3NeKKJiCf:baba.is.you",{"sha256":"5PGENImHC863Yz9sO6IJX+bIQthZFI2RMhFZyFy+bC0"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"rP+Ybp17GPCqQBrTQ3yz+q6PihdaMWvNY3SngV8aDLHv8wdDlH4ULGnjsB+Az7trqYdCE3rZVo9M7Hy5tOObDg"}},"type":"m.room.message"}`),
		// create event is last
		[]byte(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`),
	}
	keyRing := &testNopJSONVerifier{}
	tbr := &testBackfillRequester{
		servers:             []ServerName{serverA},
		authEventsToProvide: testBackfillEvents,
		stateIDsAtEvent: map[string][]string{
			"$4Kp0G1yWZ6tNpeI7:baba.is.you": {"$fnwGrQEpiOIUoDU2:baba.is.you", "$WCraVpPZe5TtHAqs:baba.is.you"},
			"$xOJZshi3NeKKJiCf:baba.is.you": {"$fnwGrQEpiOIUoDU2:baba.is.you", "$WCraVpPZe5TtHAqs:baba.is.you"},
			"$fnwGrQEpiOIUoDU2:baba.is.you": {"$WCraVpPZe5TtHAqs:baba.is.you"},
			"$WCraVpPZe5TtHAqs:baba.is.you": nil,
		},
		backfillFn: func(server ServerName, roomID string, fromEventIDs []string, limit int) (*Transaction, error) {
			if roomID != testRoomID {
				return nil, fmt.Errorf("bad room id: %s", roomID)
			}
			if server == serverA {
				return &Transaction{
					Origin:         serverA,
					OriginServerTS: AsTimestamp(time.Now()),
					PDUs: []json.RawMessage{
						testBackfillEvents[0], testBackfillEvents[1], testBackfillEvents[2], testBackfillEvents[3],
					},
				}, nil
			}
			return nil, fmt.Errorf("bad server name: %s", server)
		},
	}
	result, err := RequestBackfill(ctx, tbr, keyRing, testRoomID, RoomVersionV1, testFromEventIDs, testLimit)
	if err != nil {
		t.Fatalf("RequestBackfill got error: %s", err)
	}
	assertUnsortedEqual(t, result, testBackfillEvents)

	if len(tbr.callOrderForStateIDsBeforeEvent) != 4 {
		t.Fatalf("Expected StateProvider.StateIDsBeforeEvent called 4 times, called %d times", len(tbr.callOrderForStateIDsBeforeEvent))
	}
	for i := 0; i < len(tbr.callOrderForStateIDsBeforeEvent); i++ {
		if tbr.callOrderForStateIDsBeforeEvent[i] != wantOrder[i] {
			t.Errorf("call %d of StateProvider.StateIDsBeforeEvent called with %s, want %s",
				i+1, tbr.callOrderForStateIDsBeforeEvent[i], wantOrder[i],
			)
		}
	}

}

func assertUnsortedEqual(t *testing.T, result []*HeaderedEvent, want [][]byte) {
	if len(result) != len(want) {
		t.Fatalf("RequestBackfill got %d events, want %d", len(result), len(want))
	}
	sortedWant := sortByteSlices(want)
	sort.Sort(sortedWant)
	var got [][]byte
	for _, e := range result {
		got = append(got, e.eventJSON)
	}
	sortedGot := sortByteSlices(got)
	sort.Sort(sortedGot)
	for i := range sortedWant {
		if !bytes.Equal(sortedGot[i], sortedWant[i]) {
			t.Errorf("RequestBackfill got:\n%s\nwant:\n%s", string(sortedGot[i]), string(sortedWant[i]))
		}
	}
}

type sortByteSlices [][]byte

func (b sortByteSlices) Len() int {
	return len(b)
}

func (b sortByteSlices) Less(i, j int) bool {
	return bytes.Compare(b[i], b[j]) < 0
}

func (b sortByteSlices) Swap(i, j int) {
	b[j], b[i] = b[i], b[j]
}
