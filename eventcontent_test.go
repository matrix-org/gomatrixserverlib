package gomatrixserverlib

import (
	"encoding/json"
	"testing"
)

func TestLevelJSONValueValid(t *testing.T) {
	var values []levelJSONValue
	input := `[0,"1",2.0]`
	if err := json.Unmarshal([]byte(input), &values); err != nil {
		t.Fatal("Unexpected error unmarshalling ", input, ": ", err)
	}
	for i, got := range values {
		want := i
		if !got.exists {
			t.Fatalf("Wanted entry %d to exist", want)
		}
		if int64(want) != got.value {
			t.Fatalf("Wanted %d got %q", want, got.value)
		}
	}
}

func TestLevelJSONValueInvalid(t *testing.T) {
	var values []levelJSONValue
	inputs := []string{
		`[{}]`, `[[]]`, `["not a number"]`, `["0.0"]`,
	}

	for _, input := range inputs {
		if err := json.Unmarshal([]byte(input), &values); err == nil {
			t.Fatalf("Unexpected success when unmarshalling %q", input)
		}
	}
}
