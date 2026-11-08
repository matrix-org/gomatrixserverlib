package gomatrixserverlib

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"golang.org/x/crypto/ed25519"
)

// v12Room builds signed room version 12 events: a room of alice, its creator, and bob, who holds
// power level 50.
type v12Room struct {
	t      *testing.T
	key    ed25519.PrivateKey
	roomID string
	ts     time.Time
	events map[string]PDU
}

func newV12Room(t *testing.T) *v12Room {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &v12Room{t: t, key: key, ts: time.Unix(1700000000, 0), events: map[string]PDU{}}
}

func (r *v12Room) event(name, sender, evType string, stateKey *string, content string, prev, auth []string) PDU {
	r.t.Helper()
	ids := func(names []string) []string {
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = append(out, r.events[n].EventID())
		}
		return out
	}
	r.ts = r.ts.Add(time.Second)
	ev, err := MustGetRoomVersion(RoomVersionV12).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   sender,
		RoomID:     r.roomID,
		Type:       evType,
		StateKey:   stateKey,
		PrevEvents: ids(prev),
		AuthEvents: ids(auth),
		Depth:      int64(len(r.events) + 1),
		Content:    []byte(content),
	}).Build(r.ts, "example.com", "ed25519:1", r.key)
	if err != nil {
		r.t.Fatalf("building %s: %v", name, err)
	}
	if evType == spec.MRoomCreate {
		r.roomID = ev.RoomID().String()
	}
	r.events[name] = ev
	return ev
}

// base builds create, alice's join, the power levels, the public join rule and bob's join.
func (r *v12Room) base() {
	r.event("create", ALICE, spec.MRoomCreate, &emptyStateKey, `{"room_version":"12"}`, nil, nil)
	r.event("alice", ALICE, spec.MRoomMember, &ALICE, `{"membership":"join"}`, []string{"create"}, nil)
	r.event("power", ALICE, spec.MRoomPowerLevels, &emptyStateKey,
		`{"users":{"`+BOB+`":50},"state_default":50,"events_default":0}`, []string{"alice"}, []string{"alice"})
	r.event("rules", ALICE, spec.MRoomJoinRules, &emptyStateKey, `{"join_rule":"public"}`,
		[]string{"power"}, []string{"alice", "power"})
	r.event("bob", BOB, spec.MRoomMember, &BOB, `{"membership":"join"}`, []string{"rules"}, []string{"power", "rules"})
}

func (r *v12Room) pdus(names ...string) []PDU {
	out := make([]PDU, 0, len(names))
	for _, n := range names {
		out = append(out, r.events[n])
	}
	return out
}

// resolve runs ResolveConflictsNew over the state sets, every event of the room passed as an auth
// event, and fails the test on a panic or on output to stdout.
func (r *v12Room) resolve(sets ...[]PDU) map[StateKeyTuple]string {
	r.t.Helper()
	var all []PDU
	for _, ev := range r.events {
		all = append(all, ev)
	}
	stdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		r.t.Fatal(err)
	}
	os.Stdout = write
	var resolved []PDU
	func() {
		defer func() {
			os.Stdout = stdout
			_ = write.Close()
			if p := recover(); p != nil {
				r.t.Fatalf("state resolution panicked: %v", p)
			}
		}()
		resolved, err = ResolveConflictsNew(RoomVersionV12, sets, all, UserIDForSenderTest, isRejectedTest)
	}()
	printed, _ := io.ReadAll(read)
	if err != nil {
		r.t.Fatal(err)
	}
	if len(printed) > 0 {
		r.t.Errorf("state resolution wrote to stdout: %q", printed)
	}
	out := map[StateKeyTuple]string{}
	for _, ev := range resolved {
		out[StateKeyTuple{ev.Type(), *ev.StateKey()}] = ev.EventID()
	}
	return out
}

func (r *v12Room) expect(state map[StateKeyTuple]string, evType, stateKey, name string) {
	r.t.Helper()
	if got, want := state[StateKeyTuple{evType, stateKey}], r.events[name].EventID(); got != want {
		r.t.Errorf("(%s, %q) resolved to %q, want %s (%s)", evType, stateKey, got, name, want)
	}
}

// A conflicted non-control event is authorized against its auth events and survives.
func TestStateResV2_1ConflictedTopic(t *testing.T) {
	r := newV12Room(t)
	r.base()
	r.event("topicA", ALICE, spec.MRoomTopic, &emptyStateKey, `{"topic":"A"}`, []string{"bob"}, []string{"alice", "power"})
	r.event("topicB", BOB, spec.MRoomTopic, &emptyStateKey, `{"topic":"B"}`, []string{"bob"}, []string{"bob", "power"})

	state := r.resolve(
		r.pdus("create", "alice", "power", "rules", "bob", "topicA"),
		r.pdus("create", "alice", "power", "rules", "bob", "topicB"),
	)
	// Both topics hang off the same power levels; the later origin_server_ts is applied last.
	r.expect(state, spec.MRoomTopic, "", "topicB")
	r.expect(state, spec.MRoomCreate, "", "create")
	r.expect(state, spec.MRoomMember, BOB, "bob")
}

// An event present in one state set alone is conflicted and survives when its auth events allow it.
func TestStateResV2_1OneSidedEvent(t *testing.T) {
	r := newV12Room(t)
	r.base()
	r.event("name", BOB, spec.MRoomName, &emptyStateKey, `{"name":"N"}`, []string{"bob"}, []string{"bob", "power"})

	state := r.resolve(
		r.pdus("create", "alice", "power", "rules", "bob"),
		r.pdus("create", "alice", "power", "rules", "bob", "name"),
	)
	r.expect(state, spec.MRoomName, "", "name")
}

// Conflicted control events of a room version with privileged creators resolve without a panic.
func TestStateResV2_1ConflictedControlEvents(t *testing.T) {
	r := newV12Room(t)
	r.base()
	r.event("power2", ALICE, spec.MRoomPowerLevels, &emptyStateKey,
		`{"users":{"`+BOB+`":50},"state_default":50,"events_default":0,"ban":40}`, []string{"bob"}, []string{"alice", "power"})
	r.event("rules2", BOB, spec.MRoomJoinRules, &emptyStateKey, `{"join_rule":"invite"}`,
		[]string{"bob"}, []string{"bob", "power"})

	state := r.resolve(
		r.pdus("create", "alice", "power2", "rules", "bob"),
		r.pdus("create", "alice", "power", "rules2", "bob"),
	)
	r.expect(state, spec.MRoomPowerLevels, "", "power2")
	r.expect(state, spec.MRoomJoinRules, "", "rules2")
}

// A conflicted event its auth events do not allow is dropped.
func TestStateResV2_1UnauthorizedEventDropped(t *testing.T) {
	r := newV12Room(t)
	r.base()
	// Bob's 50 is below the 100 a change of the power levels' "users" to 100 needs.
	r.event("power2", BOB, spec.MRoomPowerLevels, &emptyStateKey,
		`{"users":{"`+BOB+`":100},"state_default":50,"events_default":0}`, []string{"bob"}, []string{"bob", "power"})

	state := r.resolve(
		r.pdus("create", "alice", "power", "rules", "bob"),
		r.pdus("create", "alice", "power2", "rules", "bob"),
	)
	r.expect(state, spec.MRoomPowerLevels, "", "power")
}
