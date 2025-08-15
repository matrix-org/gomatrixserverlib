package gomatrixserverlib

import (
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestEventCreationV3(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	verImpl := MustGetRoomVersion(RoomVersionV12)
	sender := "@alice:example.com"

	// Ensure we can make create events
	ev, err := verImpl.NewEventBuilderFromProtoEvent(&ProtoEvent{
		Type:     spec.MRoomCreate,
		StateKey: &emptyStateKey,
		Content:  []byte(`{"room_version":"12"}`),
		SenderID: sender,
		Depth:    1,
	}).Build(time.Now(), "localhost", "ed25519:1", sk)
	assert.NoError(t, err, "failed to build create event")
	assert.Equal(t, ev.EventID()[1:], ev.RoomID().String()[1:], "create event ID must equal the room ID")

	// ..and use the new room ID to make other events
	_, err = verImpl.NewEventBuilderFromProtoEvent(&ProtoEvent{
		Type:     spec.MRoomMember,
		StateKey: &sender,
		Content:  []byte(`{"membership":"join"}`),
		SenderID: sender,
		Depth:    1,
		RoomID:   ev.RoomID().String(),
	}).Build(time.Now(), "localhost", "ed25519:1", sk)
	assert.NoError(t, err, "failed to build member event")
}
