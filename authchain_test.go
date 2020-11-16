package gomatrixserverlib_test

import (
	"context"
	"testing"

	"github.com/matrix-org/gomatrixserverlib"
)

// A basic sanity check of a linear sequence of common events
func TestVerifyEventAuthChain(t *testing.T) {
	ctx := context.Background()
	testEvents := [][]byte{
		[]byte(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":3,"event_id":"$4Kp0G1yWZ6tNpeI7:baba.is.you","hashes":{"sha256":"B+MjcGZRh72iaGOgyNbIxgFkHDJo6NO8NQDgiKDKDBA"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$xOJZshi3NeKKJiCf:baba.is.you",{"sha256":"5PGENImHC863Yz9sO6IJX+bIQthZFI2RMhFZyFy+bC0"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"rP+Ybp17GPCqQBrTQ3yz+q6PihdaMWvNY3SngV8aDLHv8wdDlH4ULGnjsB+Az7trqYdCE3rZVo9M7Hy5tOObDg"}},"type":"m.room.message"}`),
	}
	testEvent, _ := gomatrixserverlib.NewEventFromTrustedJSON(testEvents[len(testEvents)-1], false, gomatrixserverlib.RoomVersionV1)
	if err := gomatrixserverlib.VerifyEventAuthChain(ctx, testEvent.Headered(gomatrixserverlib.RoomVersionV1), provideEvents(t, testEvents)); err != nil {
		t.Fatalf("Expected event to pass auth chain checks, but failed: %s", err)
	}
}

// A basic check that missing events causes a failure, in this example the membership event.
func TestVerifyEventAuthChainMissing(t *testing.T) {
	ctx := context.Background()
	testEvents := [][]byte{
		[]byte(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`),
		// []byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":3,"event_id":"$4Kp0G1yWZ6tNpeI7:baba.is.you","hashes":{"sha256":"B+MjcGZRh72iaGOgyNbIxgFkHDJo6NO8NQDgiKDKDBA"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$xOJZshi3NeKKJiCf:baba.is.you",{"sha256":"5PGENImHC863Yz9sO6IJX+bIQthZFI2RMhFZyFy+bC0"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"rP+Ybp17GPCqQBrTQ3yz+q6PihdaMWvNY3SngV8aDLHv8wdDlH4ULGnjsB+Az7trqYdCE3rZVo9M7Hy5tOObDg"}},"type":"m.room.message"}`),
	}
	testEvent, _ := gomatrixserverlib.NewEventFromTrustedJSON(testEvents[len(testEvents)-1], false, gomatrixserverlib.RoomVersionV1)
	if err := gomatrixserverlib.VerifyEventAuthChain(ctx, testEvent.Headered(gomatrixserverlib.RoomVersionV1), provideEvents(t, testEvents)); err == nil {
		t.Fatalf("Expected event to fail auth chain checks, but passed")
	}
}

// A basic check that lying about which auth events are required to send the event results in failure, in this example lying and saying you don't need the membership event.
func TestVerifyEventAuthChainLying(t *testing.T) {
	ctx := context.Background()
	testEvents := [][]byte{
		[]byte(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`),
		// modified to remove $fnwGrQEpiOIUoDU2 from auth_events
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"body":"Test Message"},"depth":3,"event_id":"$4Kp0G1yWZ6tNpeI7:baba.is.you","hashes":{"sha256":"B+MjcGZRh72iaGOgyNbIxgFkHDJo6NO8NQDgiKDKDBA"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$xOJZshi3NeKKJiCf:baba.is.you",{"sha256":"5PGENImHC863Yz9sO6IJX+bIQthZFI2RMhFZyFy+bC0"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"rP+Ybp17GPCqQBrTQ3yz+q6PihdaMWvNY3SngV8aDLHv8wdDlH4ULGnjsB+Az7trqYdCE3rZVo9M7Hy5tOObDg"}},"type":"m.room.message"}`),
	}
	testEvent, _ := gomatrixserverlib.NewEventFromTrustedJSON(testEvents[len(testEvents)-1], false, gomatrixserverlib.RoomVersionV1)
	if err := gomatrixserverlib.VerifyEventAuthChain(ctx, testEvent.Headered(gomatrixserverlib.RoomVersionV1), provideEvents(t, testEvents)); err == nil {
		t.Fatalf("Expected event to fail auth chain checks, but passed")
	}
}

// A check to make sure that, even if the original specified event passes the check, if one of its auth events fails the check the whole thing fails.
// In this example, the membership event isn't valid as the membership is set to leave.
func TestVerifyEventAuthChainCascadeFailure(t *testing.T) {
	ctx := context.Background()
	testEvents := [][]byte{
		[]byte(`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`),
		// modified to set to 'leave'
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"leave"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`),
		[]byte(`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":3,"event_id":"$4Kp0G1yWZ6tNpeI7:baba.is.you","hashes":{"sha256":"B+MjcGZRh72iaGOgyNbIxgFkHDJo6NO8NQDgiKDKDBA"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$xOJZshi3NeKKJiCf:baba.is.you",{"sha256":"5PGENImHC863Yz9sO6IJX+bIQthZFI2RMhFZyFy+bC0"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"rP+Ybp17GPCqQBrTQ3yz+q6PihdaMWvNY3SngV8aDLHv8wdDlH4ULGnjsB+Az7trqYdCE3rZVo9M7Hy5tOObDg"}},"type":"m.room.message"}`),
	}
	testEvent, _ := gomatrixserverlib.NewEventFromTrustedJSON(testEvents[len(testEvents)-1], false, gomatrixserverlib.RoomVersionV1)
	if err := gomatrixserverlib.VerifyEventAuthChain(ctx, testEvent.Headered(gomatrixserverlib.RoomVersionV1), provideEvents(t, testEvents)); err == nil {
		t.Fatalf("Expected event to fail auth chain checks, but passed")
	}
}

func provideEvents(t *testing.T, events [][]byte) gomatrixserverlib.AuthChainProvider {
	eventMap := make(map[string]*gomatrixserverlib.Event)
	for _, eventBytes := range events {
		ev, err := gomatrixserverlib.NewEventFromTrustedJSON(eventBytes, false, gomatrixserverlib.RoomVersionV1)
		if err != nil {
			t.Fatalf("Failed to load event: %s", err)
		}
		eventMap[ev.EventID()] = ev
	}
	return func(roomVer gomatrixserverlib.RoomVersion, eventIDs []string) (result []*gomatrixserverlib.Event, err error) {
		for _, id := range eventIDs {
			if ev, ok := eventMap[id]; ok {
				result = append(result, ev)
			}
		}
		return
	}
}
