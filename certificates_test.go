/* Copyright 2017 Vector Creations Ltd
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

import (
	"testing"
)

// TODO: Change test for function to support IP Addresses
func TestCleanAndVerifyServerName(t *testing.T) { // nolint: gocyclo
	input := append(make([]string, 0, 6),
		"www.example.org:1234",
		"www.example.org",
		"1.1.1.1:1234",
		"1.1.1.1",
		"1fff:0:a88:85a3::ac1f",
		"[1fff:0:a88:85a3::ac1f]:1234",
		"2001:0db8:0000:0000:0000:ff00:0042:8329",
		"[2001:0db8:0000:0000:0000:ff00:0042]:8329",
	)
	output := append(make([]string, 0, 6),
		"www.example.org",
		"www.example.org",
		"",
		"",
		"",
		"",
		"",
		"",
	)

	for index, serverName := range input {
		cleanedServerName, _ := cleanAndVerifyServerName(ServerName(serverName))
		if output[index] != cleanedServerName {
			t.Errorf("Expected serverName '%s' to be cleaned and validated to '%s', got '%s'", serverName, output[index], cleanedServerName)
		}
	}
}
