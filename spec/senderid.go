// Copyright 2023 The Matrix.org Foundation C.I.C.
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

package spec

import (
	"context"

	"golang.org/x/crypto/ed25519"
)

type SenderID string

type UserIDForSender func(roomID RoomID, senderID SenderID) (*UserID, error)

// CreateSenderID is a function used to create the pseudoID private key.
type CreateSenderID func(ctx context.Context, userID UserID, roomID RoomID, roomVersion string) (SenderID, ed25519.PrivateKey, error)

// StoreSenderIDFromPublicID is a function to store the mxid_mapping after receiving a join event over federation.
type StoreSenderIDFromPublicID func(ctx context.Context, senderID SenderID, userID string, id RoomID) error

func SenderIDFromPseudoIDKey(key ed25519.PrivateKey) SenderID {
	return SenderID(Base64Bytes(key.Public().(ed25519.PublicKey)).Encode())
}

func (s SenderID) RawBytes() (res Base64Bytes, err error) {
	err = res.Decode(string(s))
	if err != nil {
		return nil, err
	}
	return res, nil
}
