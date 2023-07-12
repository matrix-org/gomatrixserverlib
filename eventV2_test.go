package gomatrixserverlib

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestCheckFields(t *testing.T) {
	roomID := "!room:localhost"
	senderID := "@sender:localhost"
	tooLargeStateKey := strings.Repeat("ä", 150)
	tooLongStateKey := strings.Repeat("b", 256)

	tests := []struct {
		name            string
		input           ProtoEvent
		wantErr         assert.ErrorAssertionFunc
		wantPersistable bool
	}{

		{
			name: "fail due to invalid roomID",
			input: ProtoEvent{
				SenderID:   senderID,
				RoomID:     "@invalid:room",
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr: assert.Error,
		},
		{
			name: "fail due to event size",
			input: ProtoEvent{
				SenderID:   senderID,
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON(fmt.Sprintf(`{"data":"%s"}`, strings.Repeat("x", maxEventLength))),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr: assert.Error,
		},
		{
			name: "fail due to senderID too long",
			input: ProtoEvent{
				SenderID:   fmt.Sprintf("@%s:localhost", strings.Repeat("a", 255)),
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr: assert.Error,
		},
		{
			name: "successfully check fields",
			input: ProtoEvent{
				SenderID:   senderID,
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr: assert.NoError,
		}, {
			name: "fail due to senderID too large",
			input: ProtoEvent{
				SenderID:   fmt.Sprintf("@%s:localhost", strings.Repeat("ä", 200)),
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr:         assert.Error,
			wantPersistable: true,
		},
		{
			name: "fail due to type too large",
			input: ProtoEvent{
				SenderID:   fmt.Sprintf("@%s:localhost", strings.Repeat("ä", 10)),
				Type:       strings.Repeat("ä", 150),
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr:         assert.Error,
			wantPersistable: true,
		},
		{
			name: "fail due to type too long",
			input: ProtoEvent{
				SenderID:   fmt.Sprintf("@%s:localhost", strings.Repeat("ä", 10)),
				Type:       strings.Repeat("b", 256),
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr:         assert.Error,
			wantPersistable: false,
		},
		{
			name: "fail due to state_key too large",
			input: ProtoEvent{
				SenderID:   fmt.Sprintf("@%s:localhost", strings.Repeat("ä", 10)),
				StateKey:   &tooLargeStateKey,
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr:         assert.Error,
			wantPersistable: true,
		},
		{
			name: "fail due to state_key too long",
			input: ProtoEvent{
				SenderID:   fmt.Sprintf("@%s:localhost", strings.Repeat("ä", 10)),
				StateKey:   &tooLongStateKey,
				RoomID:     roomID,
				PrevEvents: []string{},
				AuthEvents: []string{},
				Content:    spec.RawJSON("{}"),
				Unsigned:   spec.RawJSON("{}"),
			},
			wantErr:         assert.Error,
			wantPersistable: false,
		},
	}
	_, sk, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for roomVersion := range roomVersionMeta {
				if roomVersion == RoomVersionPseudoIDs {
					continue
				}
				t.Run(tt.name+"-"+string(roomVersion), func(t *testing.T) {
					ev, err := MustGetRoomVersion(roomVersion).NewEventBuilderFromProtoEvent(&tt.input).Build(time.Now(), "localhost", "ed25519:1", sk)
					tt.wantErr(t, err)
					err = CheckFields(ev)
					tt.wantErr(t, err, fmt.Sprintf("CheckFields(%v)", tt.input))
					t.Logf("%v", err)
					switch e := err.(type) {
					case EventValidationError:
						assert.Equalf(t, tt.wantPersistable, e.Persistable, "unexpected persistable")
					}
				})

			}

		})
	}
}
