package eventauth

import (
	"encoding/json"
	"testing"
)

func stateNeededEquals(a, b StateNeeded) bool {
	if a.Create != b.Create {
		return false
	}
	if a.JoinRules != b.JoinRules {
		return false
	}
	if a.PowerLevels != b.PowerLevels {
		return false
	}
	if len(a.Member) != len(b.Member) {
		return false
	}
	if len(a.ThirdPartyInvite) != len(b.ThirdPartyInvite) {
		return false
	}
	for i := range a.Member {
		if a.Member[i] != b.Member[i] {
			return false
		}
	}
	for i := range a.ThirdPartyInvite {
		if a.ThirdPartyInvite[i] != b.ThirdPartyInvite[i] {
			return false
		}
	}
	return true
}

func testStateNeededForAuth(t *testing.T, eventdata string, want StateNeeded) {
	var events []Event
	if err := json.Unmarshal([]byte(eventdata), &events); err != nil {
		panic(err)
	}
	got := StateNeededForAuth(events)
	if !stateNeededEquals(got, want) {
		t.Errorf("Testing StateNeededForAuth(%#v), wanted %#v got %#v", events, want, got)
	}
}

func TestStateNeededForCreate(t *testing.T) {
	// Create events don't need anything.
	testStateNeededForAuth(t, `[{"type": "m.room.create"}]`, StateNeeded{})
}

func TestStateNeededForMessage(t *testing.T) {
	// Message events need the create event, the sender and the power_levels.
	testStateNeededForAuth(t, `[{
		"type": "m.room.message",
		"sender": "@u1:a"
	}]`, StateNeeded{
		Create:      true,
		PowerLevels: true,
		Member:      []string{"@u1:a"},
	})
}

func TestStateNeededForAlias(t *testing.T) {
	// Alias events need only the create event.
	testStateNeededForAuth(t, `[{"type": "m.room.aliases"}]`, StateNeeded{
		Create: true,
	})
}

func TestStateNeededForJoin(t *testing.T) {
	testStateNeededForAuth(t, `[{
		"type": "m.room.member",
		"state_key": "@u1:a",
		"sender": "@u1:a",
		"content": {"membership": "join"}
	}]`, StateNeeded{
		Create:      true,
		JoinRules:   true,
		PowerLevels: true,
		Member:      []string{"@u1:a"},
	})
}

func TestStateNeededForInvite(t *testing.T) {
	testStateNeededForAuth(t, `[{
		"type": "m.room.member",
		"state_key": "@u2:b",
		"sender": "@u1:a",
		"content": {"membership": "invite"}
	}]`, StateNeeded{
		Create:      true,
		PowerLevels: true,
		Member:      []string{"@u1:a", "@u2:b"},
	})
}

func TestStateNeededForInvite3PID(t *testing.T) {
	testStateNeededForAuth(t, `[{
		"type": "m.room.member",
		"state_key": "@u2:b",
		"sender": "@u1:a",
		"content": {
			"membership": "invite",
			"third_party_invite": {
				"signed": {
					"token": "my_token"
				}
			}
		}
	}]`, StateNeeded{
		Create:           true,
		PowerLevels:      true,
		Member:           []string{"@u1:a", "@u2:b"},
		ThirdPartyInvite: []string{"my_token"},
	})
}

type testAuthEvents struct {
	CreateJSON           json.RawMessage            `json:"create"`
	JoinRulesJSON        json.RawMessage            `json:"join_rules"`
	PowerLevelsJSON      json.RawMessage            `json:"power_levels"`
	MemberJSON           map[string]json.RawMessage `json:"member"`
	ThirdPartyInviteJSON map[string]json.RawMessage `json:"third_party_invite"`
}

func (tae *testAuthEvents) Create() (*Event, error) {
	if len(tae.CreateJSON) == 0 {
		return nil, nil
	}
	var event Event
	if err := json.Unmarshal(tae.CreateJSON, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

func (tae *testAuthEvents) JoinRules() (*Event, error) {
	if len(tae.JoinRulesJSON) == 0 {
		return nil, nil
	}
	var event Event
	if err := json.Unmarshal(tae.JoinRulesJSON, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

func (tae *testAuthEvents) PowerLevels() (*Event, error) {
	if len(tae.PowerLevelsJSON) == 0 {
		return nil, nil
	}
	var event Event
	if err := json.Unmarshal(tae.PowerLevelsJSON, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

func (tae *testAuthEvents) Member(stateKey string) (*Event, error) {
	if len(tae.MemberJSON[stateKey]) == 0 {
		return nil, nil
	}
	var event Event
	if err := json.Unmarshal(tae.MemberJSON[stateKey], &event); err != nil {
		return nil, err
	}
	return &event, nil
}

func (tae *testAuthEvents) ThirdPartyInvite(stateKey string) (*Event, error) {
	if len(tae.ThirdPartyInviteJSON[stateKey]) == 0 {
		return nil, nil
	}
	var event Event
	if err := json.Unmarshal(tae.ThirdPartyInviteJSON[stateKey], &event); err != nil {
		return nil, err
	}
	return &event, nil
}

type testCase struct {
	AuthEvents testAuthEvents    `json:"auth_events"`
	Allowed    []json.RawMessage `json:"allowed"`
	NotAllowed []json.RawMessage `json:"not_allowed"`
}

func testCaseJSON(t *testing.T, testCaseData string) {
	var tc testCase
	if err := json.Unmarshal([]byte(testCaseData), &tc); err != nil {
		t.Fatal(err)
	}
	for _, data := range tc.Allowed {
		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		if err := Allowed(event, &tc.AuthEvents); err != nil {
			t.Fatalf("Expected %q to be allowed but it was not: %q", string(data), err)
		}
	}
	for _, data := range tc.NotAllowed {
		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		if err := Allowed(event, &tc.AuthEvents); err == nil {
			t.Fatalf("Expected %q to not be allowed but it was: %q", string(data), err)
		}
	}
}

func TestAllowedEmptyRoom(t *testing.T) {
	// Test that only m.room.create events can be sent without auth events.
	// TODO: Test the events that aren't m.room.create
	testCaseJSON(t, `{
		"auth_events": {},
		"allowed": [{
			"type": "m.room.create",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e1:a",
			"content": {"creator": "@u1:a"}
		}],
		"not_allowed": [{
			"type": "m.room.create",
			"sender": "@u1:b",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"content": {"creator": "@u1:b"},
			"unsigned": {
				"not_allowed": "Sent by a different server than the one which made the room_id"
			}
		}, {
			"type": "m.room.create",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"prev_events": [["$e1", {}]],
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Was not the first event in the room"
			}
		}]
	}`)
}
