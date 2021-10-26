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

package gomatrixserverlib

import (
	"encoding/json"

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
	Signatures map[string]map[KeyID]Base64Bytes `json:"signatures,omitempty"`
	Keys       map[KeyID]Base64Bytes            `json:"keys"`
	Usage      []CrossSigningKeyPurpose         `json:"usage"`
	UserID     string                           `json:"user_id"`
}

func (s *CrossSigningKey) isCrossSigningBody() {} // implements CrossSigningBody

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
