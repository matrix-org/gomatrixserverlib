// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fclient

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
)

type CrossSigningKeyPurpose string

const (
	CrossSigningKeyPurposeMaster      CrossSigningKeyPurpose = "master"
	CrossSigningKeyPurposeSelfSigning CrossSigningKeyPurpose = "self_signing"
	CrossSigningKeyPurposeUserSigning CrossSigningKeyPurpose = "user_signing"
)

type CrossSigningKeys struct {
	MasterKey      CrossSigningKey `json:"master_key"`
	SelfSigningKey CrossSigningKey `json:"self_signing_key"`
	UserSigningKey CrossSigningKey `json:"user_signing_key"`
}

// https://spec.matrix.org/unstable/client-server-api/#post_matrixclientr0keysdevice_signingupload
type CrossSigningKey struct {
	Signatures map[string]map[gomatrixserverlib.KeyID]spec.Base64Bytes `json:"signatures,omitempty"`
	Keys       map[gomatrixserverlib.KeyID]spec.Base64Bytes            `json:"keys"`
	Usage      []CrossSigningKeyPurpose                                `json:"usage"`
	UserID     string                                                  `json:"user_id"`
}

func (s *CrossSigningKey) isCrossSigningBody() {} // implements CrossSigningBody

func (s *CrossSigningKey) Equal(other *CrossSigningKey) bool {
	if s == nil || other == nil {
		return false
	}
	if s.UserID != other.UserID {
		return false
	}
	if len(s.Usage) != len(other.Usage) {
		return false
	}

	// Make sure the slices are sorted before we compare them.
	if !slices.IsSorted(s.Usage) {
		slices.Sort(s.Usage)
	}
	if !slices.IsSorted(other.Usage) {
		slices.Sort(other.Usage)
	}
	for i := range s.Usage {
		if s.Usage[i] != other.Usage[i] {
			return false
		}
	}
	if len(s.Keys) != len(other.Keys) {
		return false
	}
	for k, v := range s.Keys {
		if !bytes.Equal(other.Keys[k], v) {
			return false
		}
	}
	if len(s.Signatures) != len(other.Signatures) {
		return false
	}
	for k, v := range s.Signatures {
		otherV, ok := other.Signatures[k]
		if !ok {
			return false
		}
		if len(v) != len(otherV) {
			return false
		}
		for k2, v2 := range v {
			if !bytes.Equal(otherV[k2], v2) {
				return false
			}
		}
	}
	return true
}

type CrossSigningBody interface {
	isCrossSigningBody()
}

type CrossSigningForKeyOrDevice struct {
	CrossSigningBody
}

// Implements json.Marshaler
func (c CrossSigningForKeyOrDevice) MarshalJSON() ([]byte, error) {
	// Marshal the contents at the top level, rather than having it embedded
	// in a "CrossSigningBody" JSON key.
	return json.Marshal(c.CrossSigningBody)
}

// Implements json.Unmarshaler
func (c *CrossSigningForKeyOrDevice) UnmarshalJSON(b []byte) error {
	if gjson.GetBytes(b, "device_id").Exists() {
		body := &DeviceKeys{}
		if err := json.Unmarshal(b, body); err != nil {
			return err
		}
		c.CrossSigningBody = body
		return nil
	}
	body := &CrossSigningKey{}
	if err := json.Unmarshal(b, body); err != nil {
		return err
	}
	c.CrossSigningBody = body
	return nil
}
