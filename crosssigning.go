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

// CrossSigningBody represents either of the concrete types CrossSingingKeys or CrossSigningSignatures
type CrossSigningBody interface {
	isCrossSigningBody()
}

// https://spec.matrix.org/unstable/client-server-api/#post_matrixclientr0keysdevice_signingupload

type CrossSigningKeys struct {
	MasterKey      CrossSigningKey `json:"master_key"`
	SelfSigningKey CrossSigningKey `json:"self_signing_key"`
	UserSigningKey CrossSigningKey `json:"user_signing_key"`
}

type CrossSigningKey struct {
	Signatures map[string]map[KeyID]Base64Bytes `json:"signatures,omitempty"`
	Keys       map[KeyID]Base64Bytes            `json:"keys"`
	Usage      []CrossSigningKeyPurpose         `json:"usage"`
	UserID     string                           `json:"user_id"`
}

func (s *CrossSigningKey) isCrossSigningBody() {} // implements CrossSigningBody

// https://spec.matrix.org/unstable/client-server-api/#post_matrixclientr0keyssignaturesupload

type CrossSigningSignatures map[string]map[string]CrossSigningBody // user ID -> device ID -> key or signature

type CrossSigningSignature struct {
	Algorithms []string                         `json:"algorithms"`
	UserID     string                           `json:"user_id"`
	DeviceID   string                           `json:"device_id"`
	Keys       map[KeyID]Base64Bytes            `json:"keys"`
	Signatures map[string]map[KeyID]Base64Bytes `json:"signatures,omitempty"`
}

func (s *CrossSigningSignature) isCrossSigningBody() {} // implements CrossSigningBody
