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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

func VerifyAllEventSignatures(ctx context.Context, events []*Event, verifier JSONVerifier) []error {
	errors := make([]error, 0, len(events))
	for _, e := range events {
		errors = append(errors, e.VerifyEventSignatures(ctx, verifier))
	}
	return errors
}

func (e *Event) VerifyEventSignatures(ctx context.Context, verifier JSONVerifier) error {
	needed := map[ServerName]struct{}{}

	// The sender should have signed the event in all cases.
	_, serverName, err := SplitID('@', e.Sender())
	if err != nil {
		return fmt.Errorf("failed to split sender: %w", err)
	}
	needed[serverName] = struct{}{}

	// In room versions 1 and 2, we should also check that the server
	// that created the event is included too. This is probably the
	// same as the sender.
	if format, err := e.roomVersion.EventIDFormat(); err != nil {
		return fmt.Errorf("failed to get event ID format: %w", err)
	} else if format == EventIDFormatV1 {
		_, serverName, err = SplitID('$', e.EventID())
		if err != nil {
			return fmt.Errorf("failed to split event ID: %w", err)
		}
		needed[serverName] = struct{}{}
	}

	// Special checks for membership events.
	if e.Type() == MRoomMember {
		membership, err := e.Membership()
		if err != nil {
			return fmt.Errorf("failed to get membership of membership event: %w", err)
		}

		// For invites, the invited server should have signed the event.
		if membership == Invite {
			_, serverName, err = SplitID('@', *e.StateKey())
			if err != nil {
				return fmt.Errorf("failed to split state key: %w", err)
			}
			needed[serverName] = struct{}{}
		}

		// For restricted join rules, the authorising server should have signed.
		if restricted, err := e.roomVersion.MayAllowRestrictedJoinsInEventAuth(); err != nil {
			return fmt.Errorf("failed to check if restricted joins allowed: %w", err)
		} else if restricted && membership == Join {
			if v := gjson.GetBytes(e.Content(), "join_authorised_via_users_server"); v.Exists() {
				_, serverName, err = SplitID('@', v.String())
				if err != nil {
					return fmt.Errorf("failed to split authorised server: %w", err)
				}
				needed[serverName] = struct{}{}
			}
		}
	}

	strictValidityChecking, err := e.roomVersion.StrictValidityChecking()
	if err != nil {
		return fmt.Errorf("failed to check strict validity checking: %w", err)
	}

	redactedJSON, err := RedactEventJSON(e.eventJSON, e.roomVersion)
	if err != nil {
		return fmt.Errorf("failed to redact event: %w", err)
	}

	var toVerify []VerifyJSONRequest
	for serverName := range needed {
		v := VerifyJSONRequest{
			Message:                redactedJSON,
			AtTS:                   e.OriginServerTS(),
			ServerName:             serverName,
			StrictValidityChecking: strictValidityChecking,
		}
		toVerify = append(toVerify, v)
	}

	results, err := verifier.VerifyJSONs(ctx, toVerify)
	if err != nil {
		return fmt.Errorf("failed to verify JSONs: %w", err)
	}

	for _, result := range results {
		if result.Error != nil {
			return result.Error
		}
	}

	return nil
}

// addContentHashesToEvent sets the "hashes" key of the event with a SHA-256 hash of the unredacted event content.
// This hash is used to detect whether the unredacted content of the event is valid.
// Returns the event JSON with a "hashes" key added to it.
func addContentHashesToEvent(eventJSON []byte) ([]byte, error) {
	var event map[string]RawJSON

	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}

	unsignedJSON := event["unsigned"]
	signatures := event["signatures"]

	delete(event, "signatures")
	delete(event, "unsigned")
	delete(event, "hashes")

	hashableEventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	hashableEventJSON, err = CanonicalJSON(hashableEventJSON)
	if err != nil {
		return nil, err
	}

	sha256Hash := sha256.Sum256(hashableEventJSON)
	hashes := struct {
		Sha256 Base64Bytes `json:"sha256"`
	}{Base64Bytes(sha256Hash[:])}
	hashesJSON, err := json.Marshal(&hashes)
	if err != nil {
		return nil, err
	}

	if len(unsignedJSON) > 0 {
		event["unsigned"] = unsignedJSON
	}
	if len(signatures) > 0 {
		event["signatures"] = signatures
	}
	event["hashes"] = RawJSON(hashesJSON)

	return json.Marshal(event)
}

// checkEventContentHash checks if the unredacted content of the event matches the SHA-256 hash under the "hashes" key.
// Assumes that eventJSON has been canonicalised already.
func checkEventContentHash(eventJSON []byte) error {
	var err error

	result := gjson.GetBytes(eventJSON, "hashes.sha256")
	var hash Base64Bytes
	if err = hash.Decode(result.Str); err != nil {
		return err
	}

	hashableEventJSON := eventJSON

	for _, key := range []string{"signatures", "unsigned", "hashes"} {
		if hashableEventJSON, err = sjson.DeleteBytes(hashableEventJSON, key); err != nil {
			return err
		}
	}

	sha256Hash := sha256.Sum256(hashableEventJSON)

	if !bytes.Equal(sha256Hash[:], []byte(hash)) {
		return fmt.Errorf("Invalid Sha256 content hash: %v != %v", sha256Hash[:], []byte(hash))
	}

	return nil
}

// ReferenceSha256HashOfEvent returns the SHA-256 hash of the redacted event content.
// This is used when referring to this event from other events.
func referenceOfEvent(eventJSON []byte, roomVersion RoomVersion) (EventReference, error) {
	redactedJSON, err := RedactEventJSON(eventJSON, roomVersion)
	if err != nil {
		return EventReference{}, err
	}

	var event map[string]RawJSON
	if err = json.Unmarshal(redactedJSON, &event); err != nil {
		return EventReference{}, err
	}

	delete(event, "signatures")
	delete(event, "unsigned")

	hashableEventJSON, err := json.Marshal(event)
	if err != nil {
		return EventReference{}, err
	}

	hashableEventJSON, err = CanonicalJSON(hashableEventJSON)
	if err != nil {
		return EventReference{}, err
	}

	sha256Hash := sha256.Sum256(hashableEventJSON)
	var eventID string

	eventFormat, err := roomVersion.EventFormat()
	if err != nil {
		return EventReference{}, err
	}
	eventIDFormat, err := roomVersion.EventIDFormat()
	if err != nil {
		return EventReference{}, err
	}

	switch eventFormat {
	case EventFormatV1:
		if err = json.Unmarshal(event["event_id"], &eventID); err != nil {
			return EventReference{}, err
		}
	case EventFormatV2:
		var encoder *base64.Encoding
		switch eventIDFormat {
		case EventIDFormatV2:
			encoder = base64.RawStdEncoding.WithPadding(base64.NoPadding)
		case EventIDFormatV3:
			encoder = base64.RawURLEncoding.WithPadding(base64.NoPadding)
		default:
			return EventReference{}, UnsupportedRoomVersionError{Version: roomVersion}
		}
		if encoder != nil {
			eventID = fmt.Sprintf("$%s", encoder.EncodeToString(sha256Hash[:]))
		}
	default:
		return EventReference{}, UnsupportedRoomVersionError{Version: roomVersion}
	}

	return EventReference{eventID, sha256Hash[:]}, nil
}

// SignEvent adds a ED25519 signature to the event for the given key.
func signEvent(signingName string, keyID KeyID, privateKey ed25519.PrivateKey, eventJSON []byte, roomVersion RoomVersion) ([]byte, error) {
	// Redact the event before signing so signature that will remain valid even if the event is redacted.
	redactedJSON, err := RedactEventJSON(eventJSON, roomVersion)
	if err != nil {
		return nil, err
	}

	// Sign the JSON, this adds a "signatures" key to the redacted event.
	// TODO: Make an internal version of SignJSON that returns just the signatures so that we don't have to parse it out of the JSON.
	signedJSON, err := SignJSON(signingName, keyID, privateKey, redactedJSON)
	if err != nil {
		return nil, err
	}

	var signedEvent struct {
		Signatures RawJSON `json:"signatures"`
	}
	if err := json.Unmarshal(signedJSON, &signedEvent); err != nil {
		return nil, err
	}

	// Unmarshal the event JSON so that we can replace the signatures key.
	var event map[string]RawJSON
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}

	event["signatures"] = signedEvent.Signatures

	return json.Marshal(event)
}
