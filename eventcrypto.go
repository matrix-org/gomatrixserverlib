package gomatrixserverlib

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

// AddContentHashesToEvent sets the "hashes" key of the event with a SHA-256 hash of the unredacted event content.
// This hash is used to detect whether the unredacted content of the event is valid.
func AddContentHashesToEvent(eventJSON []byte) ([]byte, error) {
	var event map[string]rawJSON

	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}

	unsignedJSON := event["unsigned"]

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
		Sha256 Base64String `json:"sha256"`
	}{Base64String(sha256Hash[:])}
	hashesJSON, err := json.Marshal(&hashes)
	if err != nil {
		return nil, err
	}

	if len(unsignedJSON) > 0 {
		event["unsigned"] = unsignedJSON
	}
	event["hashes"] = rawJSON(hashesJSON)

	return json.Marshal(event)
}

// CheckEventContentHash checks if the unredacted content of the event matches the SHA-256 hash under the "hashes" key.
func CheckEventContentHash(eventJSON []byte) error {
	var event map[string]rawJSON

	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return err
	}

	hashesJSON := event["hashes"]

	delete(event, "signatures")
	delete(event, "unsigned")
	delete(event, "hashes")

	var hashes struct {
		Sha256 Base64String `json:"sha256"`
	}
	if err := json.Unmarshal(hashesJSON, &hashes); err != nil {
		return err
	}

	hashableEventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	hashableEventJSON, err = CanonicalJSON(hashableEventJSON)
	if err != nil {
		return err
	}

	sha256Hash := sha256.Sum256(hashableEventJSON)

	if bytes.Compare(sha256Hash[:], []byte(hashes.Sha256)) != 0 {
		return fmt.Errorf("Invalid Sha256 content hash: %v != %v", sha256Hash[:], []byte(hashes.Sha256))
	}

	return nil
}

// ReferenceSha256HashOfEvent returns the SHA-256 hash of the redacted event content.
// This is used when referring to this event from other events.
func ReferenceSha256HashOfEvent(eventJSON []byte) ([]byte, error) {
	redactedJSON, err := RedactEvent(eventJSON)
	if err != nil {
		return nil, err
	}

	var event map[string]rawJSON
	if err = json.Unmarshal(redactedJSON, &event); err != nil {
		return nil, err
	}

	delete(event, "signatures")
	delete(event, "unsigned")

	hashableEventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	hashableEventJSON, err = CanonicalJSON(hashableEventJSON)
	if err != nil {
		return nil, err
	}

	sha256Hash := sha256.Sum256(hashableEventJSON)

	return sha256Hash[:], nil
}

// SignEvent adds a ED25519 signature to the event for the given key.
func SignEvent(signingName, keyID string, privateKey ed25519.PrivateKey, eventJSON []byte) ([]byte, error) {
	redactedJSON, err := RedactEvent(eventJSON)
	if err != nil {
		return nil, err
	}

	signedJSON, err := SignJSON(signingName, keyID, privateKey, redactedJSON)
	if err != nil {
		return nil, err
	}

	var signedEvent struct {
		Signatures rawJSON `json:"signatures"`
	}
	if err := json.Unmarshal(signedJSON, &signedEvent); err != nil {
		return nil, err
	}

	var event map[string]rawJSON
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}

	event["signatures"] = signedEvent.Signatures

	return json.Marshal(event)
}

// VerifyEventSignature checks if the event has been signed by the given ED25519 key.
func VerifyEventSignature(signingName, keyID string, publicKey ed25519.PublicKey, eventJSON []byte) error {
	redactedJSON, err := RedactEvent(eventJSON)
	if err != nil {
		return err
	}

	return VerifyJSON(signingName, keyID, publicKey, redactedJSON)
}
