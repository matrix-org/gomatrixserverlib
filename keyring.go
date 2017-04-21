package gomatrixserverlib

import (
	"fmt"
	"golang.org/x/crypto/ed25519"
	"strings"
	"time"
)

// A Timestamp is a millisecond posix timestamp.
type Timestamp uint64

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
	FetchKeys(requests map[PublicKeyRequest]Timestamp) (map[PublicKeyRequest]ServerKeys, error)
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
	AtTS Timestamp
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

func (k *KeyRing) publicKeyRequests(results []VerifyJSONResult, keyIDs [][]string) map[PublicKeyRequest]Timestamp {
	keyRequests := map[PublicKeyRequest]Timestamp{}
	for i := range results {
		if results[i].Result == nil {
			continue
		}
		for _, keyID := range keyIDs[i] {
			k := PublicKeyRequest{results[i].ServerName, keyID}
			maxTS := keyRequests[k]
			if maxTS <= results[i].AtTS {
				keyRequests[k] = results[i].AtTS
			}
		}
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

// A PerspectiveKeyFetcher fetches server keys from a single perspective server.
type PerspectiveKeyFetcher struct {
	// The name of the perspective server to fetch keys from.
	ServerName string
	// The ed25519 public keys the perspective server must sign responses with.
	ServerKeys map[string]ed25519.PublicKey
	// The federation client to use to fetch keys with.
	Client Client
}

// FetchKeys implements KeyFetcher
func (p *PerspectiveKeyFetcher) FetchKeys(requests map[PublicKeyRequest]Timestamp) (map[PublicKeyRequest]ServerKeys, error) {
	results, err := p.Client.ServerKeys(p.ServerName, requests)
	if err != nil {
		return nil, err
	}

	for req, keys := range results {
		var valid bool
		keyIDs, err := ListKeyIDs(p.ServerName, keys.Raw)
		if err != nil {
			// The response from the perspective server was corrupted.
			return nil, err
		}
		for _, keyID := range keyIDs {
			perspectiveKey, ok := p.ServerKeys[keyID]
			if !ok {
				// We don't have a key for that keyID, skip to the next keyID.
				continue
			}
			if err := VerifyJSON(p.ServerName, keyID, perspectiveKey, keys.Raw); err != nil {
				// An invalid signature is very bad since it means we have a
				// problem talking to the perspective server.
				return nil, err
			}
			valid = true
			break
		}
		if !valid {
			// This means we don't have a known signature from the perspective server.
			return nil, fmt.Errorf("gomatrixserverlib: not signed with a known key for the perspective server")
		}

		// Check that the keys are valid for the server.
		checks, _, _ := CheckKeys(req.ServerName, time.Unix(0, 0), keys, nil)
		if !checks.AllChecksOK {
			// This is bad because it means that the perspective server was trying to feed us an invalid response.
			return nil, fmt.Errorf("gomatrixserverlib: key response from perspective server failed checks")
		}
	}

	return results, nil
}

// A DirectKeyFetcher fetches keys directly from a server.
// This may be suitable for local deployments that are firewalled from the public internet where DNS can be trusted.
type DirectKeyFetcher struct {
	// The federation client to use to fetch keys with.
	Client Client
}

// FetchKeys implements KeyFetcher
func (d *DirectKeyFetcher) FetchKeys(requests map[PublicKeyRequest]Timestamp) (map[PublicKeyRequest]ServerKeys, error) {
	byServer := map[string]map[PublicKeyRequest]Timestamp{}
	for req, ts := range requests {
		server := byServer[req.ServerName]
		if server == nil {
			server = map[PublicKeyRequest]Timestamp{}
			byServer[req.ServerName] = server
		}
		server[req] = ts
	}

	results := map[PublicKeyRequest]ServerKeys{}
	for server, reqs := range byServer {
		// TODO: make these requests in parallel
		serverResults, err := d.fetchKeysForServer(server, reqs)
		if err != nil {
			// TODO: Should we actually be erroring here? or should we just drop those keys from the result map?
			return nil, err
		}
		for req, keys := range serverResults {
			results[req] = keys
		}
	}
	return results, nil
}

func (d *DirectKeyFetcher) fetchKeysForServer(
	serverName string, requests map[PublicKeyRequest]Timestamp,
) (map[PublicKeyRequest]ServerKeys, error) {
	results, err := d.Client.ServerKeys(serverName, requests)
	if err != nil {
		return nil, err
	}

	for req, keys := range results {
		// Check that the keys are valid for the server.
		checks, _, _ := CheckKeys(req.ServerName, time.Unix(0, 0), keys, nil)
		if !checks.AllChecksOK {
			// This is bad because it means that the perspective server was trying to feed us an invalid response.
			return nil, fmt.Errorf("gomatrixserverlib: key response from perspective server failed checks")
		}
	}

	return results, nil
}
