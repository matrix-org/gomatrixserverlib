package matrixeventauth

import (
	"encoding/json"
	"testing"
)

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

func testEventAuth(t *testing.T, testCaseData string) {
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

func TestEmptyRoom(t *testing.T) {
	testEventAuth(t, `{
		"auth_events": {},
		"allowed": [{
			"type": "m.room.create",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"content": {"creator": "@u1:a"}
		}],
		"not_allowed": [{
			"type": "m.room.create",
			"sender": "@u1:b",
			"room_id": "!r1:a",
			"content": {"creator": "@u1:b"}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"content": {"membership": "join"}
		}]
	}`)
}

func TestFirstJoin(t *testing.T) {
	testEventAuth(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]]
		}],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"content": {"membership": "join"},
			"prev_events": [["$e2:a", {}]]
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"content": {"membership": "invite"},
			"prev_events": [["$e1:a", {}]]
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r2:a",
			"state_key": "@u1:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]]
		}, {
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]]
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]]
		}]
	}`)
}

func TestFirstPowerLevels(t *testing.T) {
	testEventAuth(t, `{
		
	}`)
}
