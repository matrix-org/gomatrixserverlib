package gomatrixserverlib

import (
	"testing"
)

func TestEventReference_UnmarshalJSON1(t *testing.T) {

	data := []interface{}{
		"abc", map[string]interface{}{
			"sha": "data",
		},
	}

	t.Logf("%#v", data)

	for _, x := range data {
		t.Logf("%#v", x)
	}

}
