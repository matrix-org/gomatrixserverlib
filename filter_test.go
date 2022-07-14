package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func Test_Filter(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  RoomEventFilter
	}{
		{
			name:  "empty types filter",
			input: []byte(`{ "types": [] }`),
			want: RoomEventFilter{
				Limit:                   0,
				NotSenders:              nil,
				NotTypes:                nil,
				Senders:                 nil,
				Types:                   &[]string{},
				LazyLoadMembers:         false,
				IncludeRedundantMembers: false,
				NotRooms:                nil,
				Rooms:                   nil,
				ContainsURL:             nil,
			},
		},
		{
			name:  "absent types filter",
			input: []byte(`{}`),
			want: RoomEventFilter{
				Limit:                   0,
				NotSenders:              nil,
				NotTypes:                nil,
				Senders:                 nil,
				Types:                   nil,
				LazyLoadMembers:         false,
				IncludeRedundantMembers: false,
				NotRooms:                nil,
				Rooms:                   nil,
				ContainsURL:             nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f RoomEventFilter
			if err := json.Unmarshal(tt.input, &f); err != nil {
				t.Fatalf("unable to parse filter: %v", err)
			}
			if !reflect.DeepEqual(f, tt.want) {
				t.Fatalf("Expected %+v\ngot %+v", tt.want, f)
			}
		})
	}

}

func TestFilterValidate(t *testing.T) {
	filterInvalidTimelineRoom := DefaultFilter()
	filterInvalidTimelineRoom.Room.Timeline.Rooms = &[]string{"not_a_room_id"}

	filterInvalidTimelineSender := DefaultFilter()
	filterInvalidTimelineSender.Room.Timeline.Senders = &[]string{"not_a_sender_id"}

	filterValidTimelineRoom := DefaultFilter()
	filterValidTimelineRoom.Room.Timeline.Rooms = &[]string{"!home:matrix.org"}

	filterValidTimelineSender := DefaultFilter()
	filterValidTimelineSender.Room.Timeline.Senders = &[]string{"@alice:matrix.org"}

	tests := []struct {
		name  string
		input Filter
		want  error
	}{
		{
			name:  "default filter",
			input: DefaultFilter(),
			want:  nil,
		},
		{
			name:  "invalid timeline room",
			input: filterInvalidTimelineRoom,
			want:  fmt.Errorf("Bad room value %q. Must be in the form !localpart:domain", (*filterInvalidTimelineRoom.Room.Timeline.Rooms)[0]),
		},
		{
			name:  "invalid timeline sender",
			input: filterInvalidTimelineSender,
			want:  fmt.Errorf("Bad user value %q. Must be in the form @localpart:domain", (*filterInvalidTimelineSender.Room.Timeline.Senders)[0]),
		},
		{
			name:  "valid timeline room",
			input: filterValidTimelineRoom,
			want:  nil,
		},
		{
			name:  "valid timeline sender",
			input: filterValidTimelineSender,
			want:  nil,
		},
	}

	extractCmpValue := func(err error) string {
		if err != nil {
			return err.Error()
		}
		return ""
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.Validate(); extractCmpValue(tt.want) != extractCmpValue(got) {
				t.Errorf("Expected \"%+v\"\ngot \"%+v\"", tt.want, got)
			}
		})
	}
}
