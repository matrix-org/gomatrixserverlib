package fclient

import (
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"testing"
)

func TestCrossSigningKeyEqual(t *testing.T) {
	tests := []struct {
		name   string
		s      *CrossSigningKey
		other  *CrossSigningKey
		expect bool
	}{
		{
			name:   "NilReceiver_ReturnsFalse",
			s:      nil,
			other:  &CrossSigningKey{},
			expect: false,
		},
		{
			name:   "NilOther_ReturnsFalse",
			s:      &CrossSigningKey{},
			other:  nil,
			expect: false,
		},
		{
			name:   "DifferentUserID_ReturnsFalse",
			s:      &CrossSigningKey{UserID: "user1"},
			other:  &CrossSigningKey{UserID: "user2"},
			expect: false,
		},
		{
			name:   "DifferentUsageLength_ReturnsFalse",
			s:      &CrossSigningKey{Usage: []CrossSigningKeyPurpose{CrossSigningKeyPurposeMaster}},
			other:  &CrossSigningKey{Usage: []CrossSigningKeyPurpose{CrossSigningKeyPurposeMaster, CrossSigningKeyPurposeSelfSigning}},
			expect: false,
		},
		{
			name:   "DifferentUsageValues_ReturnsFalse",
			s:      &CrossSigningKey{Usage: []CrossSigningKeyPurpose{CrossSigningKeyPurposeMaster}},
			other:  &CrossSigningKey{Usage: []CrossSigningKeyPurpose{CrossSigningKeyPurposeSelfSigning}},
			expect: false,
		},
		{
			name:   "DifferentKeysLength_ReturnsFalse",
			s:      &CrossSigningKey{Keys: map[gomatrixserverlib.KeyID]spec.Base64Bytes{"key1": {}}},
			other:  &CrossSigningKey{Keys: map[gomatrixserverlib.KeyID]spec.Base64Bytes{"key1": {}, "key2": {}}},
			expect: false,
		},
		{
			name:   "DifferentKeysValues_ReturnsFalse",
			s:      &CrossSigningKey{Keys: map[gomatrixserverlib.KeyID]spec.Base64Bytes{"key1": {}}},
			other:  &CrossSigningKey{Keys: map[gomatrixserverlib.KeyID]spec.Base64Bytes{"key1": {1}}},
			expect: false,
		},
		{
			name:   "DifferentSignaturesLength_ReturnsFalse",
			s:      &CrossSigningKey{Signatures: map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes{"sig1": {"key1": {}}}},
			other:  &CrossSigningKey{Signatures: map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes{"sig1": {"key1": {}}, "sig2": {"key2": {}}}},
			expect: false,
		},
		{
			name:   "DifferentSignaturesValues_ReturnsFalse",
			s:      &CrossSigningKey{Signatures: map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes{"sig1": {"key1": {}}}},
			other:  &CrossSigningKey{Signatures: map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes{"sig1": {"key1": {1}}}},
			expect: false,
		},
		{
			name: "IdenticalKeys_ReturnsTrue",
			s: &CrossSigningKey{
				UserID:     "user1",
				Usage:      []CrossSigningKeyPurpose{CrossSigningKeyPurposeMaster},
				Keys:       map[gomatrixserverlib.KeyID]spec.Base64Bytes{"key1": {}},
				Signatures: map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes{"sig1": {"key1": {}}},
			},
			other: &CrossSigningKey{
				UserID:     "user1",
				Usage:      []CrossSigningKeyPurpose{CrossSigningKeyPurposeMaster},
				Keys:       map[gomatrixserverlib.KeyID]spec.Base64Bytes{"key1": {}},
				Signatures: map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes{"sig1": {"key1": {}}},
			},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Equal(tt.other); got != tt.expect {
				t.Errorf("Equal() = %v, want %v", got, tt.expect)
			}
		})
	}
}
