package spec

import (
	"crypto/ed25519"
	"reflect"
	"testing"
)

func TestUserIDSenderIDs(t *testing.T) {
	tests := map[string]UserID{
		"basic":                    NewUserIDOrPanic("@localpart:domain", false),
		"extensive_local":          NewUserIDOrPanic("@abcdefghijklmnopqrstuvwxyz0123456789._=-/:domain", false),
		"extensive_local_historic": NewUserIDOrPanic("@!\"#$%&'()*+,-./0123456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~:domain", true),
		"domain_with_port":         NewUserIDOrPanic("@localpart:domain.org:80", false),
		"minimum_id":               NewUserIDOrPanic("@a:1", false),
	}

	for name, userID := range tests {
		t.Run(name, func(t *testing.T) {
			senderID := SenderIDFromUserID(userID)

			if string(senderID) != userID.String() {
				t.Fatalf("Created sender ID did not match user ID string: senderID %s for user ID %s", string(senderID), userID.String())
			}
			if !senderID.IsUserID() {
				t.Fatalf("IsUserID returned false for user ID: %s", userID.String())
			}
			if senderID.IsPseudoID() {
				t.Fatalf("IsPseudoID returned true for user ID: %s", userID.String())
			}
			returnedUserID := senderID.ToUserID()
			if returnedUserID == nil {
				t.Fatalf("ToUserID returned nil value")
			}
			if !reflect.DeepEqual(userID, *returnedUserID) {
				t.Fatalf("ToUserID returned different user ID than one used to created sender ID\ncreated with %s\nreturned %s", userID, *returnedUserID)
			}
			roomKey := senderID.ToPseudoID()
			if roomKey != nil {
				t.Fatalf("ToPseudoID returned non-nil value for user ID: %s, returned %s", userID.String(), roomKey)
			}
		})
	}
}

func TestPseudoIDSenderIDs(t *testing.T) {
	// Generate key from all zeroes seed
	testKeySeed := make([]byte, 32)
	testKey := ed25519.NewKeyFromSeed(testKeySeed)

	t.Run("test pseudo ID", func(t *testing.T) {
		senderID := SenderIDFromPseudoIDKey(testKey)
		testPubkey := testKey.Public()
		expectedSenderIDString := Base64Bytes(testPubkey.(ed25519.PublicKey)).Encode()

		if string(senderID) != expectedSenderIDString {
			t.Fatalf("Created sender ID did not match provided key: created sender ID %s, expected: %s", string(senderID), expectedSenderIDString)
		}
		if !senderID.IsPseudoID() {
			t.Fatalf("IsPseudoID returned false for pseudo ID sender ID")
		}
		if senderID.IsUserID() {
			t.Fatalf("IsUserID returned true for pseudo ID sender ID")
		}
		returnedKey := senderID.ToPseudoID()
		if returnedKey == nil {
			t.Fatal("ToPseudoID returned nil")
		}
		if !reflect.DeepEqual(testPubkey, *returnedKey) {
			t.Fatalf("ToPseudoID returned different key to the one used to create the sender ID:\ncreated with %v\nreturned %v", testPubkey, *returnedKey)
		}
		userID := senderID.ToUserID()
		if userID != nil {
			t.Fatalf("ToUserID returned non-nil value %v", userID.String())
		}
	})
}
