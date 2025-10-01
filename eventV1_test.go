package gomatrixserverlib

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/sjson"
)

func makeStickyEvent(t *testing.T, durationMS int64, originTS int64, stateKey *string) PDU {
	verImpl := MustGetRoomVersion(RoomVersionV12)

	m := map[string]interface{}{
		"sticky": map[string]int64{
			"duration_ms": durationMS,
		},
		"room_id": "!L6nFTAu28CEi9yn9up1SUiKtTNnKt2yomgy2JFRT2Zk",
		"type":    "m.room.message",
		"sender":  "@user:localhost",
		"content": map[string]interface{}{
			"body":    "Hello, World!",
			"msgtype": "m.text",
		},
		"origin_server_ts": originTS,
		"unsigned":         make(map[string]interface{}),
		"depth":            1,
		"origin":           "localhost",
		"prev_events":      []string{"$65vISquU7WNlFCaJeJ5uohlX4LVEPx5yEkAc1hpRf44"},
		"auth_events":      []string{"$65vISquU7WNlFCaJeJ5uohlX4LVEPx5yEkAc1hpRf44"},
		"hashes": map[string]string{
			"sha256": "1234567890",
		},
		"signatures": map[string]interface{}{
			"localhost": map[string]string{
				"ed25519:localhost": "doesn't matter because it's not checked",
			},
		},
	}
	if stateKey != nil {
		m["state_key"] = *stateKey
	}
	if durationMS < 0 {
		delete(m, "sticky")
	}

	b, err := json.Marshal(m)
	assert.NoError(t, err, "failed to marshal sticky message event")

	// we need to add hashes manually so we don't cause our event to become redacted
	cj, err := CanonicalJSON(b)
	assert.NoError(t, err, "failed to canonicalize sticky message event")
	for _, key := range []string{"signatures", "unsigned", "hashes"} {
		cj, err = sjson.DeleteBytes(cj, key)
		assert.NoErrorf(t, err, "failed to delete %s from sticky message event", key)
	}
	sum := sha256.Sum256(cj)
	b, err = sjson.SetBytes(b, "hashes.sha256", base64.RawURLEncoding.EncodeToString(sum[:]))

	ev, err := verImpl.NewEventFromUntrustedJSON(b)
	assert.NoError(t, err, "failed to create new untrusted sticky message event")
	assert.NotNil(t, ev)
	return ev
}

func TestIsSticky(t *testing.T) {
	// Note: IsSticky internally uses `time.Now()`, so we can't play with the time too much.

	// Happy path
	ev := makeStickyEvent(t, 20000, time.Now().UnixMilli(), nil)
	assert.True(t, ev.IsSticky(time.Now()))

	// Origin before now
	ev = makeStickyEvent(t, 20000, time.Now().UnixMilli()-10000, nil)
	assert.True(t, ev.IsSticky(time.Now())) // should use the -10s time from origin as the start time

	// Origin in the future
	ev = makeStickyEvent(t, 20000, time.Now().UnixMilli()+30000, nil)
	assert.True(t, ev.IsSticky(time.Now())) // This will switch to using Now() instead of the 30s future, so should be in range

	// Origin is well before now, leading to expiration upon receipt
	ev = makeStickyEvent(t, 20000, time.Now().UnixMilli()-30000, nil)
	assert.False(t, ev.IsSticky(time.Now()))
}

func TestStickyEndTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	nowTS := now.UnixMilli()
	received := now

	// Happy path: event is a message event, and origin and duration are within range
	ev := makeStickyEvent(t, 20000, nowTS, nil)
	assert.Equal(t, now.Add(20*time.Second), ev.StickyEndTime(received))

	// Origin before now, but duration still within range
	ev = makeStickyEvent(t, 20000, nowTS-10000, nil)
	assert.Equal(t, now.Add(10*time.Second), ev.StickyEndTime(received)) // +10 s because origin is -10s with a duration of 20s

	// Origin and duration before now
	ev = makeStickyEvent(t, 20000, nowTS-30000, nil)
	assert.Equal(t, received.Add(-10*time.Second), ev.StickyEndTime(received)) // 10s before received (-30+20 = -10)

	// Origin in the future (using received time instead), duration still within range
	ev = makeStickyEvent(t, 20000, nowTS+10000, nil)
	assert.Equal(t, now.Add(20*time.Second), ev.StickyEndTime(received)) // +20s because we'll use the received time as a start time

	// Origin is in the future, which places the start time before the origin
	ev = makeStickyEvent(t, 20000, nowTS+30000, nil)
	assert.Equal(t, received.Add(20*time.Second), ev.StickyEndTime(received)) // The origin is ignored, so +20s for the duration

	// Duration is more than an hour
	ev = makeStickyEvent(t, 3699999, nowTS, nil)
	assert.Equal(t, now.Add(1*time.Hour), ev.StickyEndTime(received))

	// Not a message event
	stateKey := "state_key"
	ev = makeStickyEvent(t, 20000, nowTS, &stateKey)
	assert.Equal(t, time.Time{}, ev.StickyEndTime(received))

	// Not a sticky event
	ev = makeStickyEvent(t, -1, nowTS, nil) // -1 creates a non-sticky event
	assert.Equal(t, time.Time{}, ev.StickyEndTime(received))
}
