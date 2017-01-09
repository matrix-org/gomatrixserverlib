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

func testEventAllowed(t *testing.T, testCaseJSON string) {
	var tc testCase
	if err := json.Unmarshal([]byte(testCaseJSON), &tc); err != nil {
		panic(err)
	}
	for _, data := range tc.Allowed {
		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			panic(err)
		}
		if err := Allowed(event, &tc.AuthEvents); err != nil {
			t.Fatalf("Expected %q to be allowed but it was not: %q", string(data), err)
		}
	}
	for _, data := range tc.NotAllowed {
		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			panic(err)
		}
		if err := Allowed(event, &tc.AuthEvents); err == nil {
			t.Fatalf("Expected %q to not be allowed but it was: %q", string(data), err)
		}
	}
}

func TestAllowedEmptyRoom(t *testing.T) {
	// Test that only m.room.create events can be sent without auth events.
	// TODO: Test the events that aren't m.room.create
	testEventAllowed(t, `{
		"auth_events": {},
		"allowed": [{
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e1:a",
			"content": {"creator": "@u1:a"}
		}],
		"not_allowed": [{
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:b",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"content": {"creator": "@u1:b"},
			"unsigned": {
				"not_allowed": "Sent by a different server than the one which made the room_id"
			}
		}, {
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"prev_events": [["$e1", {}]],
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Was not the first event in the room"
			}
		}, {
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"body": "Test"},
			"unsigned": {
				"not_allowed": "No create event"
			}
		}, {
			"type": "m.room.create",
			"state_key": "",
			"sender": "not_a_user_id",
			"room_id": "!r1:a",
			"event_id": "$e5:a",
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Sender is not a valid user ID"
			}
		}, {
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "not_a_room_id",
			"event_id": "$e6:a",
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Room is not a valid room ID"
			}
		}]
	}`)
}

func TestAllowedWithNoPowerLevels(t *testing.T) {
	testEventAllowed(t, `{
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
					"content": {"membership": "join"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"content": {"body": "Test"}
		}],
		"not_allowed": [{
			"type": "m.room.message",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"body": "Test"},
			"unsigned": {
				"not_allowed": "Sender is not in room"
			}
		}]
	}`)
}

func TestAllowedNoFederation(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {
					"creator": "@u1:a",
					"m.federate": false
				}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"content": {"body": "Test"}
		}],
		"not_allowed": [{
			"type": "m.room.message",
			"sender": "@u2:b",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"body": "Test"},
			"unsigned": {
				"not_allowed": "Sender is from a different server."
			}
		}]
	}`)
}

func TestAllowedWithPowerLevels(t *testing.T) {
	testEventAllowed(t, `{
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
					"content": {"membership": "join"}
				},
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e3:a",
					"content": {"membership": "join"}
				},
				"@u3:b": {
					"type": "m.room.member",
					"sender": "@u3:b",
					"room_id": "!r1:a",
					"state_key": "@u3:b",
					"event_id": "$e4:a",
					"content": {"membership": "join"}
				}
			},
			"power_levels": {
				"type": "m.room.power_levels",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e5:a",
				"content": {
					"users": {
						"@u1:a": 100,
						"@u2:a": 50
					},
					"users_default": 0,
					"events": {
						"m.room.join_rules": 100
					},
					"state_default": 50,
					"events_default": 0
				}
			}
		},
		"allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e6:a",
			"content": {"body": "Test from @u1:a"}
		}, {
			"type": "m.room.message",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e7:a",
			"content": {"body": "Test from @u2:a"}
		}, {
			"type": "m.room.message",
			"sender": "@u3:b",
			"room_id": "!r1:a",
			"event_id": "$e8:a",
			"content": {"body": "Test from @u3:a"}
		},{
			"type": "m.room.name",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e9:a",
			"content": {"name": "Name set by @u1:a"}
		}, {
			"type": "m.room.name",
			"state_key": "",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e10:a",
			"content": {"name": "Name set by @u2:a"}
		}, {
			"type": "m.room.join_rules",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e11:a",
			"content": {"join_rule": "public"}
		}, {
			"type": "my.custom.state",
			"state_key": "@u2:a",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "@e12:a",
			"content": {}
		}],
		"not_allowed": [{
			"type": "m.room.name",
			"state_key": "",
			"sender": "@u3:b",
			"room_id": "!r1:a",
			"event_id": "$e13:a",
			"content": {"name": "Name set by @u3:a"},
			"unsigned": {
				"not_allowed": "User @u3:a's level is too low to send a state event"
			}
		}, {
			"type": "m.room.join_rules",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e14:a",
			"content": {"name": "Name set by @u3:a"},
			"unsigned": {
				"not_allowed": "User @u2:a's level is too low to send m.room.join_rules"
			}
		}, {
			"type": "m.room.message",
			"sender": "@u4:a",
			"room_id": "!r1:a",
			"event_id": "$e15:a",
			"content": {"Body": "Test from @u4:a"},
			"unsigned": {
				"not_allowed": "User @u4:a is not in the room"
			}
		}, {
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r2:a",
			"event_id": "$e16:a",
			"content": {"body": "Test from @u4:a"},
			"unsigned": {
				"not_allowed": "Sent from a different room to the create event"
			}
		}, {
			"type": "my.custom.state",
			"state_key": "@u2:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "@e17:a",
			"content": {},
			"unsigned": {
				"not_allowed": "State key starts with '@' and is for a different user"
			}
		}]
	}`)
}
