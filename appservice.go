/* Copyright 2018 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

// ApplicationServiceTransaction is the transaction that is sent off to an
// application service.
// TODO: Update unstable prefix once MSC2409 completes FCP merge.
type ApplicationServiceTransaction struct {
	Events    []ClientEvent    `json:"events"`
	Ephemeral []EphemeralEvent `json:"de.sorunome.msc2409.ephemeral,omitempty"`
	ToDevice  []ToDeviceEvent  `json:"de.sorunome.msc2409.to_device,omitempty"`
}

// EphemeralEvent is an EDU fit for consumption in acordence with MSC2409
type EphemeralEvent struct {
	Type    string  `json:"edu_type"`
	RoomID  string  `json:"room_id"`
	Content RawJSON `json:"content,omitempty"`
}

// ToDeviceEvent is a special ephemeral event aimed at a particular user/device id combo in acordence with MSC2409
type ToDeviceEvent struct {
	Type       string  `json:"type"`
	Sender     string  `json:"sender"`
	ToUserID   string  `json:"to_user_id"`
	ToDeviceID string  `json:"to_device_id"`
	Content    RawJSON `json:"content,omitempty"`
}
