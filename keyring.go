package gomatrixserverlib

import (
	"fmt"
	"golang.org/x/crypto/ed25519"
	"strings"
)

// A PublicKeyRequest is a request for a public key with a particular key ID.
type PublicKeyRequest struct {
	// The server to fetch a key for.
	ServerName string
	// The ID of the key to fetch.
	KeyID string
}

// A KeyFetcher is a way of fetching public keys in bulk.
type KeyFetcher interface {
	// Lookup a batch of public keys.
	FetchKeys(requests []PublicKeyRequest) (map[PublicKeyRequest]ServerKeys, error)
}

// A KeyDatabase is a store for caching public keys.
type KeyDatabase interface {
	KeyFetcher
	// Add a block public keys to the database.
	StoreKeys(map[PublicKeyRequest]ServerKeys) error
}

// A KeyRing stores keys for matrix servers and provides methods for verifying JSON messages.
type KeyRing struct {
	KeyFetchers []KeyFetcher
	KeyDatabase KeyDatabase
}

// A VerifyJSONRequest is a request to check for a signature on a JSON message.
// A JSON message is valid for a server if the message has at least one valid
// signature from that server.
type VerifyJSONRequest struct {
	// The name of the matrix server to check for a signature for.
	ServerName string
	// The millisecond posix timestamp the message needs to be valid at.
	AtTS uint64
	// The JSON bytes.
	Message []byte
}

// A VerifyJSONResult is the result of checking the signature of a JSON message.
type VerifyJSONResult struct {
	// Embedded copy of the request this result is for.
	VerifyJSONRequest
	// Whether the message passed the signature checks.
	// This will be nil if the message passed the checks.
	// This will have an error if the message did not pass the checks.
	Result error
}

// VerifyJSONs performs bulk JSON signature verification for a list of VerifyJSONRequests.
// Returns a list of VerifyJSONResults with the same length as the request list.
// The caller should check the Result field for each entry to see if it was valid.
// Returns an error if there was a problem talking to the database or one of the other methods
// of fetching the public keys.
func (k *KeyRing) VerifyJSONs(requests []VerifyJSONRequest) ([]VerifyJSONResult, error) {
	results := make([]VerifyJSONResult, len(requests))
	keyIDs := make([][]string, len(requests))

	for i := range requests {
		results[i].VerifyJSONRequest = requests[i]
		ids, err := ListKeyIDs(requests[i].ServerName, requests[i].Message)
		if err != nil {
			results[i].Result = fmt.Errorf("gomatrixserverlib: error extracting key IDs")
			continue
		}
		for _, keyID := range ids {
			if k.isAlgorithmSupported(keyID) {
				keyIDs[i] = append(keyIDs[i], keyID)
			}
		}
		if len(keyIDs[i]) == 0 {
			results[i].Result = fmt.Errorf("gomatrixserverlib: not signed by %q with a supported algorithm", results[i].ServerName)
			continue
		}
		// Set a place holder error in the result field.
		// This will be unset if one of the signature checks passes.
		// This will be overwritten if one of the signature checks fails.
		// Therefore this will only remain in place if the keys couldn't be downloaded.
		results[i].Result = fmt.Errorf("gomatrixserverlib: could not download key for %q", results[i].ServerName)
	}

	keyRequests := k.publicKeyRequests(results, keyIDs)
	if len(keyRequests) == 0 {
		// There aren't any keys to fetch so we can stop here.
		// This will happen if all the objects are missing supported signatures.
		return results, nil
	}
	keysFromDatabase, err := k.KeyDatabase.FetchKeys(keyRequests)
	if err != nil {
		return nil, err
	}
	k.checkUsingKeys(results, keyIDs, keysFromDatabase)

	for i := range k.KeyFetchers {
		keyRequests := k.publicKeyRequests(results, keyIDs)
		if len(keyRequests) == 0 {
			// There aren't any keys to fetch so we can stop here.
			// This means that we've checked every JSON object we can check.
			return results, nil
		}
		keysFetched, err := k.KeyFetchers[i].FetchKeys(keyRequests)
		if err != nil {
			return nil, err
		}
		k.checkUsingKeys(results, keyIDs, keysFetched)

		// Add the keys to the database so that we won't need to fetch them again.
		if err := k.KeyDatabase.StoreKeys(keysFetched); err != nil {
			return nil, err
		}
	}

	return results, nil
}

func (k *KeyRing) isAlgorithmSupported(keyID string) bool {
	return strings.HasPrefix(keyID, "ed25519:")
}

func (k *KeyRing) publicKeyRequests(results []VerifyJSONResult, keyIDs [][]string) []PublicKeyRequest {
	keyRequestSet := map[PublicKeyRequest]struct{}{}
	for i := range results {
		if results[i].Result == nil {
			continue
		}
		for _, keyID := range keyIDs[i] {
			keyRequestSet[PublicKeyRequest{results[i].ServerName, keyID}] = struct{}{}
		}
	}
	var keyRequests []PublicKeyRequest
	for keyRequest := range keyRequestSet {
		keyRequests = append(keyRequests, keyRequest)
	}
	return keyRequests
}

func (k *KeyRing) checkUsingKeys(results []VerifyJSONResult, keyIDs [][]string, keys map[PublicKeyRequest]ServerKeys) {
	for i := range results {
		if results[i].Result == nil {
			// We've already checked this message and it passed the signature checks.
			// So we can skip to the next message.
			continue
		}
		for _, keyID := range keyIDs[i] {
			serverKeys, ok := keys[PublicKeyRequest{results[i].ServerName, keyID}]
			if !ok {
				// No key for this key ID so we continue onto the next key ID.
				continue
			}
			publicKey := serverKeys.PublicKey(keyID, results[i].AtTS)
			if publicKey == nil {
				// The key wasn't valid at the timestamp we needed it to be valid at.
				// So skip onto the next key.
				results[i].Result = fmt.Errorf("gomatrixserverlib: key with ID %q for %q not valid at %d", keyID, results[i].ServerName, results[i].AtTS)
				continue
			}
			if err := VerifyJSON(results[i].ServerName, keyID, ed25519.PublicKey(publicKey), results[i].Message); err != nil {
				// The signature wasn't valid, record the error and try the next key ID.
				results[i].Result = err
				continue
			}
			// The signature is valid, set the result to nil.
			results[i].Result = nil
			break
		}
	}
}
