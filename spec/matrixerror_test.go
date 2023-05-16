// Copyright 2017 Vector Creations Ltd
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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleMatrixErrors(t *testing.T) {
	tests := map[string]struct {
		errorString  string
		customErrMsg string
		errorFunc    func(string) MatrixError
	}{
		"m_unknown":                  {errorString: "M_UNKNOWN", errorFunc: Unknown},
		"m_unrecognized":             {errorString: "M_UNRECOGNIZED", errorFunc: Unrecognized},
		"m_forbidden":                {errorString: "M_FORBIDDEN", errorFunc: Forbidden},
		"m_bad_json":                 {errorString: "M_BAD_JSON", errorFunc: BadJSON},
		"m_bad_alias":                {errorString: "M_BAD_ALIAS", errorFunc: BadAlias},
		"m_not_json":                 {errorString: "M_NOT_JSON", errorFunc: NotJSON},
		"m_not_found":                {errorString: "M_NOT_FOUND", errorFunc: NotFound},
		"m_missing_token":            {errorString: "M_MISSING_TOKEN", errorFunc: MissingToken},
		"m_unknown_token":            {errorString: "M_UNKNOWN_TOKEN", errorFunc: UnknownToken},
		"m_weak_password":            {errorString: "M_WEAK_PASSWORD", errorFunc: WeakPassword},
		"m_invalid_username":         {errorString: "M_INVALID_USERNAME", errorFunc: InvalidUsername},
		"m_user_in_use":              {errorString: "M_USER_IN_USE", errorFunc: UserInUse},
		"m_room_in_use":              {errorString: "M_ROOM_IN_USE", errorFunc: RoomInUse},
		"m_exclusive":                {errorString: "M_EXCLUSIVE", errorFunc: ASExclusive},
		"m_guest_access_forbidden":   {errorString: "M_GUEST_ACCESS_FORBIDDEN", errorFunc: GuestAccessForbidden},
		"m_invalid_signature":        {errorString: "M_INVALID_SIGNATURE", errorFunc: InvalidSignature},
		"m_invalid_param":            {errorString: "M_INVALID_PARAM", errorFunc: InvalidParam},
		"m_missing_param":            {errorString: "M_MISSING_PARAM", errorFunc: MissingParam},
		"m_unable_to_authorise_join": {errorString: "M_UNABLE_TO_AUTHORISE_JOIN", errorFunc: UnableToAuthoriseJoin},
		"m_unsupported_room_version": {errorString: "M_UNSUPPORTED_ROOM_VERSION", errorFunc: UnsupportedRoomVersion},
		"m_server_not_trusted":       {errorString: "M_SERVER_NOT_TRUSTED", errorFunc: NotTrusted, customErrMsg: "Untrusted server 'error msg'"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			errorMsg := "error msg"
			e := tc.errorFunc(errorMsg)
			jsonBytes, err := json.Marshal(&e)
			if err != nil {
				t.Fatalf("Failed to marshal error. %s", err.Error())
			}
			if tc.customErrMsg != "" {
				errorMsg = tc.customErrMsg
			}
			want := `{"errcode":"` + tc.errorString + `","error":"` + errorMsg + `"}`
			if string(jsonBytes) != want {
				t.Errorf("want %s, got %s", want, string(jsonBytes))
			}
		})
	}
}

func TestInternalServerError(t *testing.T) {
	e := InternalServerError{}
	assert.NotPanics(t, func() { _ = e.Error() })
}

func TestLimitExceeded(t *testing.T) {
	e := LimitExceeded("error msg", 500)
	jsonBytes, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("Failed to marshal error. %s", err.Error())
	}
	want := `{"errcode":"M_LIMIT_EXCEEDED","error":"error msg","retry_after_ms":500}`
	if string(jsonBytes) != want {
		t.Errorf("want %s, got %s", want, string(jsonBytes))
	}
}

func TestLeaveServerNoticeError(t *testing.T) {
	e := LeaveServerNoticeError()
	jsonBytes, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("Failed to marshal error. %s", err.Error())
	}
	want := `{"errcode":"M_CANNOT_LEAVE_SERVER_NOTICE_ROOM","error":"You cannot reject this invite"}`
	if string(jsonBytes) != want {
		t.Errorf("want %s, got %s", want, string(jsonBytes))
	}
}

func TestWrongRoomKeysVersion(t *testing.T) {
	e := WrongBackupVersionError("error msg")
	jsonBytes, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("Failed to marshal error. %s", err.Error())
	}
	want := `{"errcode":"M_WRONG_ROOM_KEYS_VERSION","error":"Wrong backup version.","current_version":"error msg"}`
	if string(jsonBytes) != want {
		t.Errorf("want %s, got %s", want, string(jsonBytes))
	}
}

func TestIncompatibleRoomVersion(t *testing.T) {
	e := IncompatibleRoomVersion("error msg")
	jsonBytes, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("Failed to marshal error. %s", err.Error())
	}
	want := `{"errcode":"M_INCOMPATIBLE_ROOM_VERSION","error":"Your homeserver does not support the features required to join this room","room_version":"error msg"}`
	if string(jsonBytes) != want {
		t.Errorf("want %s, got %s", want, string(jsonBytes))
	}
}
