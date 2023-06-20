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

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

func VerifyAllEventSignatures(ctx context.Context, events []PDU, verifier JSONVerifier, userIDForSender spec.UserIDForSender) []error {
	errors := make([]error, 0, len(events))
	for _, e := range events {
		errors = append(errors, VerifyEventSignatures(ctx, e, verifier, userIDForSender))
	}
	return errors
}

func VerifyEventSignatures(ctx context.Context, e PDU, verifier JSONVerifier, userIDForSender spec.UserIDForSender) error {
	if userIDForSender == nil {
		panic("UserIDForSender func is nil")
	}

	needed := map[spec.ServerName]struct{}{}

	// The sender should have signed the event in all cases.
	validRoomID, err := spec.NewRoomID(e.RoomID())
	if err != nil {
		return err
	}
	sender, err := userIDForSender(*validRoomID, e.SenderID())
	if err != nil {
		return fmt.Errorf("invalid sender userID: %w", err)
	}
	serverName := sender.Domain()
	needed[serverName] = struct{}{}

	verImpl, err := GetRoomVersion(e.Version())
	if err != nil {
		return err
	}

	// In room versions 1 and 2, we should also check that the server
	// that created the event is included too. This is probably the
	// same as the sender.
	format := verImpl.EventIDFormat()
	if format == EventIDFormatV1 {
		_, serverName, err = SplitID('$', e.EventID())
		if err != nil {
			return fmt.Errorf("failed to split event ID: %w", err)
		}
		needed[serverName] = struct{}{}
	}

	// Special checks for membership events.
	if e.Type() == spec.MRoomMember {
		membership, err := e.Membership()
		if err != nil {
			return fmt.Errorf("failed to get membership of membership event: %w", err)
		}

		// Validate the MXIDMapping is signed correctly
		if verImpl.Version() == RoomVersionPseudoIDs && membership == spec.Join {
			err = validateMXIDMappingSignature(ctx, e, verifier, verImpl)
			if err != nil {
				return err
			}
		}

		// For invites, the invited server should have signed the event.
		if membership == spec.Invite {
			switch e.Version() {
			case RoomVersionPseudoIDs:
				// TODO: (pseudoIDs) revisit this logic for event signing
				needed[spec.ServerName(e.SenderID())] = struct{}{}
			default:
				_, serverName, err = SplitID('@', *e.StateKey())
				if err != nil {
					return fmt.Errorf("failed to split state key: %w", err)
				}
				needed[serverName] = struct{}{}
			}
		}

		// For restricted join rules, the authorising server should have signed.
		if membership == spec.Join {
			auth, err := verImpl.RestrictedJoinServername(e.Content())
			if err != nil {
				return err
			}
			if auth != "" {
				needed[auth] = struct{}{}
			}
		}

	}

	redactedJSON, err := verImpl.RedactEventJSON(e.JSON())
	if err != nil {
		return fmt.Errorf("failed to redact event: %w", err)
	}

	var toVerify []VerifyJSONRequest
	for serverName := range needed {
		v := VerifyJSONRequest{
			Message:              redactedJSON,
			AtTS:                 e.OriginServerTS(),
			ServerName:           serverName,
			ValidityCheckingFunc: verImpl.SignatureValidityCheck,
		}
		toVerify = append(toVerify, v)
	}

	if verImpl.Version() == RoomVersionPseudoIDs {
		// we already verified the mxid_mapping at this stage, so replace the KeyRing verifier
		// with the self verifier to validate pseudoID events
		verifier = JSONVerifierSelf{}
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

// validateMXIDMappingSignature validates that the MXIDMapping is correctly signed
func validateMXIDMappingSignature(ctx context.Context, e PDU, verifier JSONVerifier, verImpl IRoomVersion) error {
	var content MemberContent
	err := json.Unmarshal(e.Content(), &content)
	if err != nil {
		return err
	}

	// if there is no mapping, we can't check the signature
	if content.MXIDMapping == nil {
		return fmt.Errorf("missing mxid_mapping, unable to validate event")
	}

	var toVerify []VerifyJSONRequest

	mapping, err := json.Marshal(content.MXIDMapping)
	if err != nil {
		return err
	}
	for s := range content.MXIDMapping.Signatures {
		v := VerifyJSONRequest{
			Message:              mapping,
			AtTS:                 e.OriginServerTS(),
			ServerName:           s,
			ValidityCheckingFunc: verImpl.SignatureValidityCheck,
		}
		toVerify = append(toVerify, v)
	}

	// check that the mapping is correctly signed by the server
	results, err := verifier.VerifyJSONs(ctx, toVerify)
	if err != nil {
		return fmt.Errorf("failed to verify MXIDMapping: %w", err)
	}

	for _, result := range results {
		if result.Error != nil {
			return fmt.Errorf("failed to verify MXIDMapping: %w", result.Error)
		}
	}

	return err
}

func extractAuthorisedViaServerName(content []byte) (spec.ServerName, error) {
	if v := gjson.GetBytes(content, "join_authorised_via_users_server"); v.Exists() {
		_, serverName, err := SplitID('@', v.String())
		if err != nil {
			return "", fmt.Errorf("failed to split authorised server: %w", err)
		}
		return serverName, nil
	}
	return "", nil
}

func emptyAuthorisedViaServerName([]byte) (spec.ServerName, error) { return "", nil }

// addContentHashesToEvent sets the "hashes" key of the event with a SHA-256 hash of the unredacted event content.
// This hash is used to detect whether the unredacted content of the event is valid.
// Returns the event JSON with a "hashes" key added to it.
func addContentHashesToEvent(eventJSON []byte) ([]byte, error) {
	var event map[string]spec.RawJSON

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
		Sha256 spec.Base64Bytes `json:"sha256"`
	}{spec.Base64Bytes(sha256Hash[:])}
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
	event["hashes"] = spec.RawJSON(hashesJSON)

	return json.Marshal(event)
}

// checkEventContentHash checks if the unredacted content of the event matches the SHA-256 hash under the "hashes" key.
// Assumes that eventJSON has been canonicalised already.
func checkEventContentHash(eventJSON []byte) error {
	var err error

	result := gjson.GetBytes(eventJSON, "hashes.sha256")
	var hash spec.Base64Bytes
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
func referenceOfEvent(eventJSON []byte, roomVersion RoomVersion) (eventReference, error) {
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return eventReference{}, err
	}
	redactedJSON, err := verImpl.RedactEventJSON(eventJSON)
	if err != nil {
		return eventReference{}, err
	}

	var event map[string]spec.RawJSON
	if err = json.Unmarshal(redactedJSON, &event); err != nil {
		return eventReference{}, err
	}

	delete(event, "signatures")
	delete(event, "unsigned")

	hashableEventJSON, err := json.Marshal(event)
	if err != nil {
		return eventReference{}, err
	}

	hashableEventJSON, err = CanonicalJSON(hashableEventJSON)
	if err != nil {
		return eventReference{}, err
	}

	sha256Hash := sha256.Sum256(hashableEventJSON)
	var eventID string

	eventFormat := verImpl.EventFormat()
	eventIDFormat := verImpl.EventIDFormat()

	switch eventFormat {
	case EventFormatV1:
		if err = json.Unmarshal(event["event_id"], &eventID); err != nil {
			return eventReference{}, err
		}
	case EventFormatV2:
		var encoder *base64.Encoding
		switch eventIDFormat {
		case EventIDFormatV2:
			encoder = base64.RawStdEncoding.WithPadding(base64.NoPadding)
		case EventIDFormatV3:
			encoder = base64.RawURLEncoding.WithPadding(base64.NoPadding)
		default:
			return eventReference{}, UnsupportedRoomVersionError{Version: roomVersion}
		}
		eventID = fmt.Sprintf("$%s", encoder.EncodeToString(sha256Hash[:]))
	default:
		return eventReference{}, UnsupportedRoomVersionError{Version: roomVersion}
	}

	return eventReference{eventID, sha256Hash[:]}, nil
}

// SignEvent adds a ED25519 signature to the event for the given key.
func signEvent(signingName string, keyID KeyID, privateKey ed25519.PrivateKey, eventJSON []byte, roomVersion RoomVersion) ([]byte, error) {
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil, err
	}
	// Redact the event before signing so signature that will remain valid even if the event is redacted.
	redactedJSON, err := verImpl.RedactEventJSON(eventJSON)
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
		Signatures spec.RawJSON `json:"signatures"`
	}
	if err := json.Unmarshal(signedJSON, &signedEvent); err != nil {
		return nil, err
	}

	// Unmarshal the event JSON so that we can replace the signatures key.
	var event map[string]spec.RawJSON
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}

	event["signatures"] = signedEvent.Signatures

	return json.Marshal(event)
}
