package gomatrixserverlib

import (
	"encoding/json"
	"testing"
)

const emptyRespStateResponse = `{"pdus":[],"auth_chain":[]}`
const emptyRespSendJoinResponse = `{"state":[],"auth_chain":[],"origin":""}`

func TestParseServerName(t *testing.T) {
	validTests := map[string][]interface{}{
		"www.example.org:1234":         {"www.example.org", 1234},
		"www.example.org":              {"www.example.org", -1},
		"1234.example.com":             {"1234.example.com", -1},
		"1.1.1.1:1234":                 {"1.1.1.1", 1234},
		"1.1.1.1":                      {"1.1.1.1", -1},
		"[1fff:0:a88:85a3::ac1f]:1234": {"[1fff:0:a88:85a3::ac1f]", 1234},
		"[2001:0db8::ff00:0042]":       {"[2001:0db8::ff00:0042]", -1},
	}

	for input, output := range validTests {
		host, port, isValid := ParseAndValidateServerName(ServerName(input))
		if !isValid {
			t.Errorf("Expected serverName '%s' to be parsed as valid, but was not", input)
		}

		if host != output[0] || port != output[1].(int) {
			t.Errorf(
				"Expected serverName '%s' to be cleaned and validated to '%s', %d, got '%s', %d",
				input, output[0], output[1], host, port,
			)
		}
	}

	invalidTests := []string{
		// ipv6 not in square brackets
		"2001:0db8::ff00:0042",

		// host with invalid characters
		"test_test.com",

		// ipv6 with insufficient parts
		"[2001:0db8:0000:0000:0000:ff00:0042]",
	}

	for _, input := range invalidTests {
		_, _, isValid := ParseAndValidateServerName(ServerName(input))
		if isValid {
			t.Errorf("Expected serverName '%s' to be rejected but was accepted", input)
		}
	}
}

func TestRespStateMarshalJSON(t *testing.T) {
	inputData := `{"pdus":[],"auth_chain":[]}`
	var input RespState
	input.roomVersion = RoomVersionV1
	if err := json.Unmarshal([]byte(inputData), &input); err != nil {
		t.Fatal(err)
	}

	gotBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)

	if emptyRespStateResponse != got {
		t.Errorf("json.Marshal(RespState(%q)): wanted %q, got %q", inputData, emptyRespStateResponse, got)
	}
}

func TestRespStateUnmarshalJSON(t *testing.T) {
	inputData := `{"pdus":[],"auth_chain":[]}`
	var input RespState
	input.roomVersion = RoomVersionV1
	if err := json.Unmarshal([]byte(inputData), &input); err != nil {
		t.Fatal(err)
	}

	gotBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)

	if emptyRespStateResponse != got {
		t.Errorf("json.Marshal(RespSendJoin(%q)): wanted %q, got %q", inputData, emptyRespStateResponse, got)
	}
}

func TestRespSendJoinMarshalJSON(t *testing.T) {
	inputData := `{"state":[],"auth_chain":[],"origin":""}`
	var input RespSendJoin
	input.roomVersion = RoomVersionV1
	if err := json.Unmarshal([]byte(inputData), &input); err != nil {
		t.Fatal(err)
	}

	gotBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)

	if emptyRespSendJoinResponse != got {
		t.Errorf("json.Marshal(RespSendJoin(%q)): wanted %q, got %q", inputData, emptyRespStateResponse, got)
	}
}

func TestRespSendJoinUnmarshalJSON(t *testing.T) {
	inputData := `{"state":[],"auth_chain":[],"origin":""}`
	var input RespSendJoin
	input.roomVersion = RoomVersionV1
	if err := json.Unmarshal([]byte(inputData), &input); err != nil {
		t.Fatal(err)
	}

	gotBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)

	if emptyRespSendJoinResponse != got {
		t.Errorf("json.Marshal(RespSendJoin(%q)): wanted %q, got %q", inputData, emptyRespStateResponse, got)
	}
}
