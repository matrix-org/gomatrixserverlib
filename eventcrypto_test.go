/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestEventSigning(t *testing.T) {
	input := []byte(`{"sender":"@matthew:matrix.org","room_id":"!fYdzbImUrZpwqvQNRs:matrix.org","hashes":{"sha256":"vNLlxDT9Efl6f6xvHDq+rUesSAOBVUrBrXwsGfOeV68"},"signatures":{"matrix.org":{"ed25519:a_RXGa":"vSSYo+Tpy7rXUBQXz8sjICbz5WicmTBSqIZwfKDm75UImBnf6D9d6mSNHWPa6Lli3YLiwwHcyjI9Xgrpjh1aCQ"}},"content":{"join_rule":"restricted"},"type":"m.room.join_rules","state_key":"","depth":11,"prev_events":["$2I2ytZ76HXDUjAVVMsNvupgxL5ECcp_kChlvvDkVgNU"],"prev_state":[],"auth_events":["$xqdFE_yQkiG6lJDBhB87pHTc4xvvz-mzGXKnSNdpep0","$ZnbkQTY5-m2m0fYgP2OP8Y920S3IUKevclHk5h_B9sE","$Sz6THDBYO7oS-y2VEBW2LrdBNLFYO1n56IiOsj7LYw0"],"origin":"matrix.org","origin_server_ts":1632834923159}`)
	origin, keyID, keyStr := `matrix.org`, KeyID(`ed25519:a_RXGa`), `gusQSADIDiAtI5sPfYWWBwwfnzew4/OaUTDihJmsPxQm7WJ24dL9uO+OOTdhEPkJ0hSUCl9D8Qlt6hAefxN/Dw`
	key := make([]byte, ed25519.PublicKeySize)
	if k, err := base64.RawStdEncoding.DecodeString(keyStr); err != nil {
		t.Fatal(err)
	} else {
		copy(key, k)
	}
	fmt.Println("Public key:", key)
	if err := VerifyJSON(origin, keyID, key, input); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEventSignatureTestVectors(t *testing.T) {
	// Check JSON verification using the test vectors from https://matrix.org/docs/spec/appendices.html
	seed, err := base64.RawStdEncoding.DecodeString("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1")
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewBuffer(seed)
	entityName := "domain" // nolint:goconst
	keyID := KeyID("ed25519:1")

	publicKey, _, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}

	testVerifyOK := func(input string) {
		redactedInput, err := redactEvent([]byte(input), RoomVersionV1)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyJSON(entityName, keyID, publicKey, redactedInput)
		if err != nil {
			t.Fatal(err)
		}
	}

	testVerifyNotOK := func(reason, input string) {
		redactedInput, err := redactEvent([]byte(input), RoomVersionV1)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyJSON(entityName, keyID, publicKey, redactedInput)
		if err == nil {
			t.Fatalf("Expected VerifyJSON to fail for input %v because %v", input, reason)
		}
	}

	testVerifyOK(`{
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "6tJjLpXtggfke8UxFhAKg82QVkJzvKOVOOSjUDK4ZSI"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"signatures": {
			"domain": {
				"ed25519:1": "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA"
			}
		},
		"type": "X",
		"unsigned": {
			"age_ts": 1000000
		}
	}`)

	// It should still pass signature checks, even if we remove the unsigned data.
	testVerifyOK(`{
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "6tJjLpXtggfke8UxFhAKg82QVkJzvKOVOOSjUDK4ZSI"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"signatures": {
			"domain": {
				"ed25519:1": "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA"
			}
		},
		"type": "X",
		"unsigned": {}
	}`)

	testVerifyOK(`{
		"content": {
			"body": "Here is the message content"
		},
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"signatures": {
			"domain": {
				"ed25519:1": "Wm+VzmOUOz08Ds+0NTWb1d4CZrVsJSikkeRxh6aCcUwu6pNC78FunoD7KNWzqFn241eYHYMGCA5McEiVPdhzBA"
			}
		},
		"unsigned": {
			"age_ts": 1000000
		}
	}`)

	// It should still pass signature checks, even if we redact the content.
	testVerifyOK(`{
		"content": {},
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"signatures": {
			"domain": {
				"ed25519:1": "Wm+VzmOUOz08Ds+0NTWb1d4CZrVsJSikkeRxh6aCcUwu6pNC78FunoD7KNWzqFn241eYHYMGCA5McEiVPdhzBA"
			}
		},
		"unsigned": {}
	}`)

	testVerifyNotOK("The event is modified", `{
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "6tJjLpXtggfke8UxFhAKg82QVkJzvKOVOOSjUDK4ZSI"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"signatures": {
			"domain": {
				"ed25519:1": "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA"
			}
		},
		"type": "modified",
		"unsigned": {}
	}`)

	testVerifyNotOK("The content hash is modified", `{
		"content": {},
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "adifferenthashvalueaP9SorVmRQNdN5aM2JYU2n/g"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"signatures": {
			"domain": {
				"ed25519:1": "Wm+VzmOUOz08Ds+0NTWb1d4CZrVsJSikkeRxh6aCcUwu6pNC78FunoD7KNWzqFn241eYHYMGCA5McEiVPdhzBA"
			}
		},
		"unsigned": {}
	}`)
}

func TestSignEventTestVectors(t *testing.T) {
	// Check matrix event signing using the test vectors from https://matrix.org/docs/spec/appendices.html
	seed, err := base64.RawStdEncoding.DecodeString("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1")
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewBuffer(seed)
	entityName := "domain"
	keyID := KeyID("ed25519:1")

	_, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}

	testSign := func(input string, want string) {
		hashed, err := addContentHashesToEvent([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signEvent(entityName, keyID, privateKey, hashed, RoomVersionV1)
		if err != nil {
			t.Fatal(err)
		}

		if !IsJSONEqual([]byte(want), signed) {
			t.Fatalf("SignEvent(%q): want %v got %v", input, want, string(signed))
		}
	}

	testSign(`
	{
		"room_id": "!x:domain",
		"sender": "@a:domain",
		"origin": "domain",
		"origin_server_ts": 1000000,
		"signatures": {},
		"hashes": {},
		"type": "X",
		"content": {},
		"prev_events": [],
		"auth_events": [],
		"depth": 3,
		"unsigned": {
			"age_ts": 1000000
		}
	}`, `{
		"auth_events": [],
		"content": {},
		"depth": 3,
		"hashes": {
			"sha256": "5jM4wQpv6lnBo7CLIghJuHdW+s2CMBJPUOGOC89ncos"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"prev_events": [],
		"room_id": "!x:domain",
		"sender": "@a:domain",
		"signatures": {
			"domain": {
				"ed25519:1": "KxwGjPSDEtvnFgU00fwFz+l6d2pJM6XBIaMEn81SXPTRl16AqLAYqfIReFGZlHi5KLjAWbOoMszkwsQma+lYAg"
			}
		},
		"type": "X",
		"unsigned": {
			"age_ts": 1000000
		}
	}`)

	testSign(`{
		"content": {
			"body": "Here is the message content"
		},
		"event_id": "$0:domain",
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"signatures": {},
		"unsigned": {
			"age_ts": 1000000
		}
	}`, `{
		"content": {
			"body": "Here is the message content"
		},
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"signatures": {
			"domain": {
				"ed25519:1": "Wm+VzmOUOz08Ds+0NTWb1d4CZrVsJSikkeRxh6aCcUwu6pNC78FunoD7KNWzqFn241eYHYMGCA5McEiVPdhzBA"
			}
		},
		"unsigned": {
			"age_ts": 1000000
		}
	}`)

	testSign(`{
		"event_id": "$0:domain",
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "X",
		"unsigned": {
			"age_ts": 1000000
		}
	}`, `{
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "6tJjLpXtggfke8UxFhAKg82QVkJzvKOVOOSjUDK4ZSI"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"signatures": {
			"domain": {
				"ed25519:1": "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA"
			}
		},
		"type": "X",
		"unsigned": {
			"age_ts": 1000000
		}
	}`)

	testSign(`{
		"content": {
			"body": "Here is the message content"
		},
		"event_id": "$0:domain",
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"unsigned": {
			"age_ts": 1000000
		}
	}`, `{
		"content": {
			"body": "Here is the message content"
		},
		"event_id": "$0:domain",
		"hashes": {
			"sha256": "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g"
		},
		"origin": "domain",
		"origin_server_ts": 1000000,
		"type": "m.room.message",
		"room_id": "!r:domain",
		"sender": "@u:domain",
		"signatures": {
			"domain": {
				"ed25519:1": "Wm+VzmOUOz08Ds+0NTWb1d4CZrVsJSikkeRxh6aCcUwu6pNC78FunoD7KNWzqFn241eYHYMGCA5McEiVPdhzBA"
			}
		},
		"unsigned": {
			"age_ts": 1000000
		}
	}`)
}

type StubVerifier struct {
	requests []VerifyJSONRequest
	results  []VerifyJSONResult
}

func (v *StubVerifier) VerifyJSONs(ctx context.Context, requests []VerifyJSONRequest) ([]VerifyJSONResult, error) {
	v.requests = append(v.requests, requests...)
	return v.results, nil
}

func TestVerifyAllEventSignatures(t *testing.T) {
	verifier := StubVerifier{
		results: make([]VerifyJSONResult, 2),
	}

	eventJSON := []byte(`{
		"type": "m.room.name",
		"state_key": "",
		"event_id": "$test:localhost",
		"room_id": "!test:localhost",
		"sender": "@test:localhost",
		"origin": "originserver",
		"content": {
			"name": "Hello World"
		},
		"origin_server_ts": 123456
	}`)

	event, err := NewEventFromTrustedJSON(eventJSON, false, RoomVersionV1)
	if err != nil {
		t.Error(err)
	}

	events := []*Event{event}
	errors := VerifyAllEventSignatures(context.Background(), events, &verifier)
	for _, err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	// There should be two verification requests
	if len(verifier.requests) != 2 {
		t.Fatalf("Number of requests: got %d, want 2", len(verifier.requests))
	}
	wantContent, err := redactEvent(eventJSON, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}

	servers := []string{}

	for i, rq := range verifier.requests {
		if !bytes.Equal(rq.Message, wantContent) {
			t.Errorf("Verify content %d: got %s, want %s", i, rq.Message, wantContent)
		}
		if rq.AtTS != 123456 {
			t.Errorf("Verify time %d: got %d, want %d", i, rq.AtTS, 123456)
		}
		servers = append(servers, string(rq.ServerName))
	}

	sort.Strings(servers)
	if servers[0] != "localhost" {
		t.Errorf("Verify server 0: got %s, want %s", servers[0], "localhost")
	}
	if servers[1] != "originserver" {
		t.Errorf("Verify server 1: got %s, want %s", servers[1], "originserver")
	}
}

func TestVerifyAllEventSignaturesForInvite(t *testing.T) {
	verifier := StubVerifier{
		results: make([]VerifyJSONResult, 2),
	}

	eventJSON := []byte(`{
		"type": "m.room.member",
		"state_key": "@bob:bobserver",
		"event_id": "$test:aliceserver",
		"room_id": "!test:room",
		"sender": "@alice:aliceserver",
		"origin": "aliceserver",
		"content": {
			"membership": "invite"
		},
		"origin_server_ts": 123456
	}`)

	event, err := NewEventFromTrustedJSON(eventJSON, false, RoomVersionV1)
	if err != nil {
		t.Error(err)
	}

	events := []*Event{event}
	errors := VerifyAllEventSignatures(context.Background(), events, &verifier)
	for _, err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	// There should be two verification requests
	if len(verifier.requests) != 2 {
		t.Fatalf("Number of requests: got %d, want 2", len(verifier.requests))
	}
	wantContent, err := redactEvent(eventJSON, RoomVersionV1)
	if err != nil {
		t.Fatal(err)
	}

	servers := []string{}

	for i, rq := range verifier.requests {
		if !bytes.Equal(rq.Message, wantContent) {
			t.Errorf("Verify content %d: got %s, want %s", i, rq.Message, wantContent)
		}
		if rq.AtTS != 123456 {
			t.Errorf("Verify time %d: got %d, want %d", i, rq.AtTS, 123456)
		}
		servers = append(servers, string(rq.ServerName))
	}

	sort.Strings(servers)
	if servers[0] != "aliceserver" {
		t.Errorf("Verify server 0: got %s, want %s", servers[0], "aliceserver")
	}
	if servers[1] != "bobserver" {
		t.Errorf("Verify server 1: got %s, want %s", servers[1], "bobserver")
	}
}
