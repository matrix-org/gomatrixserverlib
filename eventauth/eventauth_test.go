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
