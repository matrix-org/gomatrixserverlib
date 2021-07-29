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

type CrossSigningKeyPurpose string

const (
	CrossSigningKeyPurposeMaster      CrossSigningKeyPurpose = "master"
	CrossSigningKeyPurposeSelfSigning CrossSigningKeyPurpose = "self_signing"
	CrossSigningKeyPurposeUserSigning CrossSigningKeyPurpose = "user_signing"
)

type CrossSigningKeys struct {
	MasterKey      CrossSigningForKey `json:"master_key"`
	SelfSigningKey CrossSigningForKey `json:"self_signing_key"`
	UserSigningKey CrossSigningForKey `json:"user_signing_key"`
}

// https://spec.matrix.org/unstable/client-server-api/#post_matrixclientr0keysdevice_signingupload
type CrossSigningForKey struct {
	Signatures map[string]map[KeyID]Base64Bytes `json:"signatures,omitempty"`
	Keys       map[KeyID]Base64Bytes            `json:"keys"`
	Usage      []CrossSigningKeyPurpose         `json:"usage"`
	UserID     string                           `json:"user_id"`
}

// https://spec.matrix.org/unstable/client-server-api/#post_matrixclientr0keyssignaturesupload
type CrossSigningForDevice struct {
	Algorithms []string                         `json:"algorithms"`
	UserID     string                           `json:"user_id"`
	DeviceID   string                           `json:"device_id"`
	Keys       map[KeyID]Base64Bytes            `json:"keys"`
	Signatures map[string]map[KeyID]Base64Bytes `json:"signatures,omitempty"`
}
