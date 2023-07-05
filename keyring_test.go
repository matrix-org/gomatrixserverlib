package gomatrixserverlib

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
)

var privateKeySeed1 = `QJvXAPj0D9MUb1exkD8pIWmCvT1xajlsB8jRYz/G5HE`

// testKeys taken from a copy of synapse.
var testKeys = `{
	"old_verify_keys": {
		"ed25519:old": {
			"expired_ts": 929059200,
			"key": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
		}
	},
	"server_name": "localhost:8800",
	"signatures": {
		"localhost:8800": {
			"ed25519:a_Obwu": "xkr4Z49ODoQnRi//ePfXlt8Q68vzd+DkzBNCt60NcwnLjNREx0qVQrw1iTFSoxkgGtz30NDkmyffDrCrmX5KBw"
		}
	},
	"tls_fingerprints": [
		{
			"sha256": "I2ohBnqpb5m3HldWFwyA10WdjqDksukiKVUdZ690WzM"
		}
	],
	"valid_until_ts": 1493142432964,
	"verify_keys": {
		"ed25519:a_Obwu": {
			"key": "2UwTWD4+tgTgENV7znGGNqhAOGY+BW1mRAnC6W6FBQg"
		}
	}
}`

type testKeyDatabase struct{}

func (db testKeyDatabase) FetcherName() string {
	return "testKeyDatabase"
}

func (db *testKeyDatabase) FetchKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]spec.Timestamp,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}

	req1 := PublicKeyLookupRequest{"localhost:8800", "ed25519:old"}
	req2 := PublicKeyLookupRequest{"localhost:8800", "ed25519:a_Obwu"}
	req3 := PublicKeyLookupRequest{"localhost:8800", "ed25519:pastvalidity"}

	for req := range requests {
		if req == req1 {
			vk := VerifyKey{}
			err := vk.Key.Decode("O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik")
			if err != nil {
				return nil, err
			}
			results[req] = PublicKeyLookupResult{
				VerifyKey:    vk,
				ValidUntilTS: PublicKeyNotValid,
				ExpiredTS:    929059200,
			}
		}

		if req == req2 {
			vk := VerifyKey{}
			err := vk.Key.Decode("2UwTWD4+tgTgENV7znGGNqhAOGY+BW1mRAnC6W6FBQg")
			if err != nil {
				return nil, err
			}
			results[req] = PublicKeyLookupResult{
				VerifyKey:    vk,
				ValidUntilTS: 22493142432964,
				ExpiredTS:    PublicKeyNotExpired,
			}
		}

		if req == req3 {
			vk := VerifyKey{}
			err := vk.Key.Decode("2UwTWD4+tgTgENV7znGGNqhAOGY+BW1mRAnC6W6FBQg")
			if err != nil {
				return nil, err
			}
			results[req] = PublicKeyLookupResult{
				VerifyKey:    vk,
				ValidUntilTS: 1591068446195,
				ExpiredTS:    PublicKeyNotExpired,
			}
		}
	}
	return results, nil
}

func (db *testKeyDatabase) StoreKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]PublicKeyLookupResult,
) error {
	return nil
}

func TestVerifyJSONsSuccess(t *testing.T) {
	// Check that trying to verify the server key JSON works.
	k := KeyRing{nil, &testKeyDatabase{}}
	results, err := k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "localhost:8800",
		Message:              []byte(testKeys),
		AtTS:                 1493142432964,
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("VerifyJSON(): Wanted [{Error: nil}] got %#v", results)
	}
}

func TestVerifyJSONsFailureWithStrictChecking(t *testing.T) {
	// Check that trying to verify the server key JSON works.
	k := KeyRing{nil, &testKeyDatabase{}}
	results, err := k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "localhost:8800",
		Message:              []byte(testKeys),
		AtTS:                 22493142433964,
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 1 && results[0].Error == nil {
		t.Fatal("VerifyJSON() should have failed but didn't")
	}
}

func TestStrictCheckingKeyValidity(t *testing.T) {
	// Check that we limit key validity to being no more
	// than seven days in the future. Start by creating a
	// key timestamp which is 14 days in the future.
	// https://matrix.org/docs/spec/rooms/v5#signing-key-validity-period
	publicKeyLookup := PublicKeyLookupResult{
		ExpiredTS:    PublicKeyNotExpired,
		ValidUntilTS: spec.AsTimestamp(time.Now().Add(time.Hour * 24 * 14)),
	}
	shouldPass := spec.AsTimestamp(time.Now().Add(time.Hour * 24 * 5))
	shouldFail := spec.AsTimestamp(time.Now().Add(time.Hour * 24 * 9))

	// This test should pass because we are only looking
	// 5 days in the future, which is less than 7 days.
	if !publicKeyLookup.WasValidAt(shouldPass, StrictValiditySignatureCheck) {
		t.Fatalf("valid test should have passed")
	}

	// This test should fail because we are looking 9 days
	// in the future, which is more than 7 days.
	if publicKeyLookup.WasValidAt(shouldFail, StrictValiditySignatureCheck) {
		t.Fatalf("invalid test should have failed")
	}
}

func TestExpiredTS(t *testing.T) {
	// Check that we respect the ExpiredTS properly.
	publicKeyLookup := PublicKeyLookupResult{
		ExpiredTS: 1000,
	}
	shouldPass := spec.Timestamp(999)
	shouldFail := spec.Timestamp(1000)

	// This test should pass because it is less than ExpiredTS.
	if !publicKeyLookup.WasValidAt(shouldPass, StrictValiditySignatureCheck) {
		t.Fatalf("valid test should have passed")
	}

	// This test should fail because it is equal to or
	// greater than ExpiredTS.
	if publicKeyLookup.WasValidAt(shouldFail, StrictValiditySignatureCheck) {
		t.Fatalf("invalid test should have failed")
	}
}

func TestVerifyJSONsFailureWithoutStrictChecking(t *testing.T) {
	// Check that trying to verify the server key JSON works.
	k := KeyRing{nil, &testKeyDatabase{}}
	results, err := k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "localhost:8800",
		Message:              []byte(testKeys),
		AtTS:                 1493142433964,
		ValidityCheckingFunc: NoStrictValidityCheck,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("VerifyJSON(): Wanted [{Error: nil}] got %#v", results)
	}
}

func TestVerifyJSONsUnknownServerFails(t *testing.T) {
	// Check that trying to verify JSON for an unknown server fails.
	k := KeyRing{nil, &testKeyDatabase{}}
	results, err := k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "unknown:8800",
		Message:              []byte(testKeys),
		AtTS:                 1493142432964,
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Error == nil {
		t.Fatalf("VerifyJSON(): Wanted [{Error: <some error>}] got %#v", results)
	}
}

func TestVerifyJSONsDistantFutureFails(t *testing.T) {
	// Check that trying to verify JSON from the distant future fails.
	distantFuture := spec.Timestamp(2000000000000)
	k := KeyRing{nil, &testKeyDatabase{}}
	results, err := k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "unknown:8800",
		Message:              []byte(testKeys),
		AtTS:                 distantFuture,
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Error == nil {
		t.Fatalf("VerifyJSON(): Wanted [{Error: <some error>}] got %#v", results)
	}
}

func TestVerifyJSONsFetcherError(t *testing.T) {
	// Check that if the database errors then the attempt to verify JSON fails.
	k := KeyRing{nil, &erroringKeyDatabase{}}
	results, err := k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "localhost:8800",
		Message:              []byte(testKeys),
		AtTS:                 1493142432964,
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}})
	if err != error(&testErrorFetch) || results != nil {
		t.Fatalf("VerifyJSONs(): Wanted (nil, <some error>) got (%#v, %q)", results, err)
	}
}

// TestRequestKeyDummy is used as a dummy KeyFetcher to see if we
// tried to trigger a key fetch operation in a test. didRequest
// is false by default, but we'll set it to true in response to a
// FetchKeys request. See TestRequestKeyAfterValidity.
type TestRequestKeyDummy struct {
	KeyFetcher
	didRequest bool
}

func (d *TestRequestKeyDummy) FetchKeys(ctx context.Context, requests map[PublicKeyLookupRequest]spec.Timestamp) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	d.didRequest = true
	return map[PublicKeyLookupRequest]PublicKeyLookupResult{}, nil
}

func (d *TestRequestKeyDummy) FetcherName() string {
	return "TestRequestKeyDummy"
}

func TestRequestKeyAfterValidity(t *testing.T) {
	// The request dummy will allow us to capture whether the fetcher was
	// triggered - we'll use this to determine if we try to request a key
	// that the database returns that is past its validity.
	requestDummy := TestRequestKeyDummy{}
	k := KeyRing{
		[]KeyFetcher{&requestDummy},
		&testKeyDatabase{},
	}
	// Create a message that uses the ed25519:pastvalidity key. The
	// testKeyDatabase will return it but we're past the validity now.
	message := `{
		"signatures": {
			"localhost:8800": {
				"ed25519:pastvalidity": "signature_here"
			}
		}
	}`
	// Try verifying.
	_, _ = k.VerifyJSONs(context.Background(), []VerifyJSONRequest{{
		ServerName:           "localhost:8800",
		Message:              []byte(message),
		AtTS:                 1493142432964,
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}})
	// At this point, the TestRequestKeyDummy should have been triggered.
	// If not, then the test failed.
	if !requestDummy.didRequest {
		t.Fatalf("expected a key fetch request but got none")
	}
}

func TestPublicKeyRequestMarshalUnmarshalText(t *testing.T) {
	// The test must only separate based on the first forward slash.
	// The key ID therefore should remain intact even if it contains one.
	expects := `{"servername/keyid/1234":{}}`
	req := PublicKeyLookupRequest{
		ServerName: "servername",
		KeyID:      "keyid/1234",
	}
	// Start by creating a map with our struct key.
	one := map[PublicKeyLookupRequest]struct{}{}
	one[req] = struct{}{}
	// Marshal the JSON.
	j, err := json.Marshal(one)
	if err != nil {
		t.Fatal(err)
	}
	// The map key in the JSON should be marshalled.
	if string(j) != expects {
		t.Fatalf("expected %q, got %q", expects, string(j))
	}
	// Now let's unmarshal it into a new struct.
	two := map[PublicKeyLookupRequest]struct{}{}
	if err := json.Unmarshal(j, &two); err != nil {
		t.Fatal(err)
	}
	// We should now have a map key that looks like the original request.
	if _, ok := two[req]; !ok {
		t.Fatal("expected struct key to exist")
	}
}

type erroringKeyDatabase struct{}

type erroringKeyDatabaseError int

func (e *erroringKeyDatabaseError) Error() string { return "An error with the key database" }

var testErrorFetch = erroringKeyDatabaseError(1)
var testErrorStore = erroringKeyDatabaseError(2)

// FetcherName implements KeyFetcher
func (e erroringKeyDatabase) FetcherName() string {
	return "ErroringKeyDatabase"
}

func (e *erroringKeyDatabase) FetchKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]spec.Timestamp,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	return nil, &testErrorFetch
}

func (e *erroringKeyDatabase) StoreKeys(
	ctx context.Context, keys map[PublicKeyLookupRequest]PublicKeyLookupResult,
) error {
	return &testErrorStore
}

func TestJSONVerifierSelf_VerifyJSONs(t *testing.T) {
	tests := []struct {
		name     string
		requests []VerifyJSONRequest
		want     []VerifyJSONResult
	}{
		{
			name: "successfully verified",
			requests: []VerifyJSONRequest{
				{ServerName: "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", Message: []byte(`{"auth_events":["$JO2AluDC5p0BXHN_2fUPa2Bup4zO0os74kkw9B5Zg8Q","$tjiFWWvrQ7p9lePYf7NgsH4167NnDV77dbaK5pFAUPM","$uhHChO86B5V9JoStcemXOXzyJQ4vCvzxDdcuF2sswBw"],"content":{"avatar_url":"","displayname":"anon-20230619_110507-7","membership":"join","mxid_mapping":{"signatures":{"localhost:8802":{"ed25519:CrqzCX":"aodhnvDkPTkU69e/AbHhltztMoLpeGfIYMNe+hvQkG54KNyN8MHlL0u5qVkYqTYOcoXrJzZ4dYydmWOi5/TRCw"}},"user_id":"@anon-20230619_110507-7:localhost:8802","user_room_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk"}},"depth":8,"hashes":{"sha256":"sXx8rtwS0n405SuPHUSpICiCYHr+/CCw9jJ3nuwnVqs"},"origin":"self","origin_server_ts":1687172711324,"prev_events":["$8zL0XKqRUOWB9kVQyCjKY7ANLuDtCjLglWd6CWW6XrM"],"prev_state":[],"room_id":"!X0Rr8baajYOjRVQ3:localhost:8800","sender":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","signatures":{"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk":{"ed25519:1":"cmXVJmTqnxme1LYl5P5PP5EVtPLJxgGwXpXU2FOEw9FHtHz9WzrfRMRcrO45/55FrBl+g7kEMWEvr9hmOY/VBA"}},"state_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","type":"m.room.member","unsigned":{}}`)},
			},
			want: []VerifyJSONResult{{}},
		},
		{
			name: "tempered event", // auth events are removed
			requests: []VerifyJSONRequest{
				{ServerName: "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", Message: []byte(`{"auth_events":[],"content":{"avatar_url":"","displayname":"anon-20230619_110507-7","membership":"join","mxid_mapping":{"signatures":{"localhost:8802":{"ed25519:CrqzCX":"aodhnvDkPTkU69e/AbHhltztMoLpeGfIYMNe+hvQkG54KNyN8MHlL0u5qVkYqTYOcoXrJzZ4dYydmWOi5/TRCw"}},"user_id":"@anon-20230619_110507-7:localhost:8802","user_room_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk"}},"depth":8,"hashes":{"sha256":"sXx8rtwS0n405SuPHUSpICiCYHr+/CCw9jJ3nuwnVqs"},"origin":"self","origin_server_ts":1687172711324,"prev_events":["$8zL0XKqRUOWB9kVQyCjKY7ANLuDtCjLglWd6CWW6XrM"],"prev_state":[],"room_id":"!X0Rr8baajYOjRVQ3:localhost:8800","sender":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","signatures":{"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk":{"ed25519:1":"cmXVJmTqnxme1LYl5P5PP5EVtPLJxgGwXpXU2FOEw9FHtHz9WzrfRMRcrO45/55FrBl+g7kEMWEvr9hmOY/VBA"}},"state_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","type":"m.room.member","unsigned":{}}`)},
			},
			want: []VerifyJSONResult{{Error: fmt.Errorf("Bad signature from %q with ID %q", "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", "ed25519:1")}},
		},
		{
			name: "invalid signature", // changed one character for the signature
			requests: []VerifyJSONRequest{
				{ServerName: "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", Message: []byte(`{"auth_events":["$JO2AluDC5p0BXHN_2fUPa2Bup4zO0os74kkw9B5Zg8Q","$tjiFWWvrQ7p9lePYf7NgsH4167NnDV77dbaK5pFAUPM","$uhHChO86B5V9JoStcemXOXzyJQ4vCvzxDdcuF2sswBw"],"content":{"avatar_url":"","displayname":"anon-20230619_110507-7","membership":"join","mxid_mapping":{"signatures":{"localhost:8802":{"ed25519:CrqzCX":"aodhnvDkPTkU69e/AbHhltztMoLpeGfIYMNe+hvQkG54KNyN8MHlL0u5qVkYqTYOcoXrJzZ4dYydmWOi5/TRCw"}},"user_id":"@anon-20230619_110507-7:localhost:8802","user_room_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk"}},"depth":8,"hashes":{"sha256":"sXx8rtwS0n405SuPHUSpICiCYHr+/CCw9jJ3nuwnVqs"},"origin":"self","origin_server_ts":1687172711324,"prev_events":["$8zL0XKqRUOWB9kVQyCjKY7ANLuDtCjLglWd6CWW6XrM"],"prev_state":[],"room_id":"!X0Rr8baajYOjRVQ3:localhost:8800","sender":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","signatures":{"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk":{"ed25519:1":"caXVJmTqnxme1LYl5P5PP5EVtPLJxgGwXpXU2FOEw9FHtHz9WzrfRMRcrO45/55FrBl+g7kEMWEvr9hmOY/VBA"}},"state_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","type":"m.room.member","unsigned":{}}`)},
			},
			want: []VerifyJSONResult{{Error: fmt.Errorf("Bad signature from %q with ID %q", "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", "ed25519:1")}},
		},
		{
			name: "missing signature", // search ed25519:1, only ed25519:2 exists
			requests: []VerifyJSONRequest{
				{ServerName: "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", Message: []byte(`{"auth_events":["$JO2AluDC5p0BXHN_2fUPa2Bup4zO0os74kkw9B5Zg8Q","$tjiFWWvrQ7p9lePYf7NgsH4167NnDV77dbaK5pFAUPM","$uhHChO86B5V9JoStcemXOXzyJQ4vCvzxDdcuF2sswBw"],"content":{"avatar_url":"","displayname":"anon-20230619_110507-7","membership":"join","mxid_mapping":{"signatures":{"localhost:8802":{"ed25519:CrqzCX":"aodhnvDkPTkU69e/AbHhltztMoLpeGfIYMNe+hvQkG54KNyN8MHlL0u5qVkYqTYOcoXrJzZ4dYydmWOi5/TRCw"}},"user_id":"@anon-20230619_110507-7:localhost:8802","user_room_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk"}},"depth":8,"hashes":{"sha256":"sXx8rtwS0n405SuPHUSpICiCYHr+/CCw9jJ3nuwnVqs"},"origin":"self","origin_server_ts":1687172711324,"prev_events":["$8zL0XKqRUOWB9kVQyCjKY7ANLuDtCjLglWd6CWW6XrM"],"prev_state":[],"room_id":"!X0Rr8baajYOjRVQ3:localhost:8800","sender":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","signatures":{"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk":{"ed25519:2":"cmXVJmTqnxme1LYl5P5PP5EVtPLJxgGwXpXU2FOEw9FHtHz9WzrfRMRcrO45/55FrBl+g7kEMWEvr9hmOY/VBA"}},"state_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","type":"m.room.member","unsigned":{}}`)},
			},
			want: []VerifyJSONResult{{Error: fmt.Errorf("No signature from %q with ID %q", "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", "ed25519:1")}},
		},
		{
			name: "no signatures at all", // signatures field removed
			requests: []VerifyJSONRequest{
				{ServerName: "nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk", Message: []byte(`{"auth_events":["$JO2AluDC5p0BXHN_2fUPa2Bup4zO0os74kkw9B5Zg8Q","$tjiFWWvrQ7p9lePYf7NgsH4167NnDV77dbaK5pFAUPM","$uhHChO86B5V9JoStcemXOXzyJQ4vCvzxDdcuF2sswBw"],"content":{"avatar_url":"","displayname":"anon-20230619_110507-7","membership":"join","mxid_mapping":{"signatures":{"localhost:8802":{"ed25519:CrqzCX":"aodhnvDkPTkU69e/AbHhltztMoLpeGfIYMNe+hvQkG54KNyN8MHlL0u5qVkYqTYOcoXrJzZ4dYydmWOi5/TRCw"}},"user_id":"@anon-20230619_110507-7:localhost:8802","user_room_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk"}},"depth":8,"hashes":{"sha256":"sXx8rtwS0n405SuPHUSpICiCYHr+/CCw9jJ3nuwnVqs"},"origin":"self","origin_server_ts":1687172711324,"prev_events":["$8zL0XKqRUOWB9kVQyCjKY7ANLuDtCjLglWd6CWW6XrM"],"prev_state":[],"room_id":"!X0Rr8baajYOjRVQ3:localhost:8800","sender":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","state_key":"nlJIYQHzMN0qNbkrX57e5i0CuUl1CfAdlkw5h1s+TDk","type":"m.room.member","unsigned":{}}`)},
			},
			want: []VerifyJSONResult{{Error: fmt.Errorf("No signatures")}},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		var err error
		t.Run(tt.name, func(t *testing.T) {
			v := JSONVerifierSelf{}
			tt.requests[0].Message, err = MustGetRoomVersion(RoomVersionPseudoIDs).RedactEventJSON(tt.requests[0].Message)
			if err != nil {
				t.Fatal(err)
				return
			}

			got, _ := v.VerifyJSONs(ctx, tt.requests)
			for i := range tt.want {
				assert.Equalf(t, tt.want[i], got[i], "VerifyJSONs(%v, %v)", ctx, tt.requests)
			}
		})
	}
}
