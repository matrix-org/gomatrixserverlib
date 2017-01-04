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
				"reason": "Sent by a different server than the one which made the room_id"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"state_key": "@u1:a",
			"content": {"membership": "join"},
			"unsigned": {
				"reason": "All non-create events must reference a create event."
			}
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
			"event_id": "$e2:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]]
		}],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e3:a",
			"content": {"membership": "join"},
			"prev_events": [["$e2:a", {}]],
			"unsigned": {
				"reason": "The prev_event is not the create event."
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e4:a",
			"content": {"membership": "invite"},
			"prev_events": [["$e1:a", {}]],
			"unsigned": {
				"reason": "The membership key is not join"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r2:a",
			"state_key": "@u1:a",
			"event_id": "$e5:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]],
			"unsigned": {
				"reason": "The room_id doesn't match the create event"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e6:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]],
			"unsigned": {
				"reason": "The sender doesn't match the room creator"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e7:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]],
			"unsigned": {
				"reason": "The sender doesn't match the state_key"
			}
		}]
	}`)
}

func TestFirstPowerLevels(t *testing.T) {
	testEventAuth(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"},
					"prev_events": [["$e1:a", {}]]
				}
			}
		},
		"allowed": [{
			"type": "m.room.power_levels",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "",
			"event_id": "$e3:a",
			"content": {
				"ban": 50,
				"events": {
					"m.room.avatar": 50,
					"m.room.canonical_alias": 50,
					"m.room.history_visibility": 100,
					"m.room.name": 50,
					"m.room.power_levels": 100
				},
				"events_default": 0,
				"invite": 0,
				"kick": 50,
				"redact": 50,
				"state_default": 50,
				"users": {
					"@u1:a": 100,
					"@u2:a": 100,
					"@u3:a": 50
				},
				"users_default": 0
			}
		}, {
			"type": "m.room.power_levels",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "",
			"event_id": "$e4:a",
			"content": {
				"users": {
					"@u1:a": 1000
				}
			}
		}],
		"not_allowed": []
	}`)
}

func TestPowerLevels(t *testing.T) {

}
