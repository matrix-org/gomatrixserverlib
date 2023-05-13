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
	"fmt"
)

type MatrixErrorCode int

const (
	ErrorUnknown MatrixErrorCode = iota
	ErrorForbidden
	ErrorBadJSON
	ErrorBadAlias
	ErrorNotJSON
	ErrorNotFound
	ErrorMissingToken
	ErrorUnknownToken
	ErrorWeakPassword
	ErrorInvalidUsername
	ErrorUserInUse
	ErrorRoomInUse
	ErrorExclusive
	ErrorGuestAccessForbidden
	ErrorInvalidSignature
	ErrorInvalidParam
	ErrorMissingParam
	ErrorUnableToAuthoriseJoin
	ErrorCannotLeaveServerNoticeRoom
	ErrorWrongRoomKeysVersion
	ErrorUnsupportedRoomVersion
	ErrorLimitExceeded
	ErrorServerNotTrusted
)

// MatrixError represents the "standard error response" in Matrix.
// http://matrix.org/docs/spec/client_server/r0.2.0.html#api-standards
type MatrixError struct {
	Code    MatrixErrorCode `json:"-"`
	ErrCode string          `json:"errcode"`
	Err     string          `json:"error"`
}

func (e MatrixError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e MatrixError) Unwrap() error {
	return fmt.Errorf(e.Err)
}

// InternalServerError
type InternalServerError struct {
	Err string
}

func (e InternalServerError) Error() string {
	return fmt.Sprintf("Internal server error: %s", e.Err)
}

// Unknown is an unexpected error
func Unknown(msg string) MatrixError {
	return MatrixError{ErrorUnknown, "M_UNKNOWN", msg}
}

// Forbidden is an error when the client tries to access a resource
// they are not allowed to access.
func Forbidden(msg string) MatrixError {
	return MatrixError{ErrorForbidden, "M_FORBIDDEN", msg}
}

// BadJSON is an error when the client supplies malformed JSON.
func BadJSON(msg string) MatrixError {
	return MatrixError{ErrorBadJSON, "M_BAD_JSON", msg}
}

// BadAlias is an error when the client supplies a bad alias.
func BadAlias(msg string) MatrixError {
	return MatrixError{ErrorBadAlias, "M_BAD_ALIAS", msg}
}

// NotJSON is an error when the client supplies something that is not JSON
// to a JSON endpoint.
func NotJSON(msg string) MatrixError {
	return MatrixError{ErrorNotJSON, "M_NOT_JSON", msg}
}

// NotFound is an error when the client tries to access an unknown resource.
func NotFound(msg string) MatrixError {
	return MatrixError{ErrorNotFound, "M_NOT_FOUND", msg}
}

// MissingToken is an error when the client tries to access a resource which
// requires authentication without supplying credentials.
func MissingToken(msg string) MatrixError {
	return MatrixError{ErrorMissingToken, "M_MISSING_TOKEN", msg}
}

// UnknownToken is an error when the client tries to access a resource which
// requires authentication and supplies an unrecognised token
func UnknownToken(msg string) MatrixError {
	return MatrixError{ErrorUnknownToken, "M_UNKNOWN_TOKEN", msg}
}

// WeakPassword is an error which is returned when the client tries to register
// using a weak password. http://matrix.org/docs/spec/client_server/r0.2.0.html#password-based
func WeakPassword(msg string) MatrixError {
	return MatrixError{ErrorWeakPassword, "M_WEAK_PASSWORD", msg}
}

// InvalidUsername is an error returned when the client tries to register an
// invalid username
func InvalidUsername(msg string) MatrixError {
	return MatrixError{ErrorInvalidUsername, "M_INVALID_USERNAME", msg}
}

// UserInUse is an error returned when the client tries to register an
// username that already exists
func UserInUse(msg string) MatrixError {
	return MatrixError{ErrorUserInUse, "M_USER_IN_USE", msg}
}

// RoomInUse is an error returned when the client tries to make a room
// that already exists
func RoomInUse(msg string) MatrixError {
	return MatrixError{ErrorRoomInUse, "M_ROOM_IN_USE", msg}
}

// ASExclusive is an error returned when an application service tries to
// register an username that is outside of its registered namespace, or if a
// user attempts to register a username or room alias within an exclusive
// namespace.
func ASExclusive(msg string) MatrixError {
	return MatrixError{ErrorExclusive, "M_EXCLUSIVE", msg}
}

// GuestAccessForbidden is an error which is returned when the client is
// forbidden from accessing a resource as a guest.
func GuestAccessForbidden(msg string) MatrixError {
	return MatrixError{ErrorGuestAccessForbidden, "M_GUEST_ACCESS_FORBIDDEN", msg}
}

// InvalidSignature is an error which is returned when the client tries
// to upload invalid signatures.
func InvalidSignature(msg string) MatrixError {
	return MatrixError{ErrorInvalidSignature, "M_INVALID_SIGNATURE", msg}
}

// InvalidParam is an error that is returned when a parameter has the wrong
// value or type.
func InvalidParam(msg string) MatrixError {
	return MatrixError{ErrorInvalidParam, "M_INVALID_PARAM", msg}
}

// MissingParam is an error that is returned when a parameter is missing from
// a request.
func MissingParam(msg string) MatrixError {
	return MatrixError{ErrorMissingParam, "M_MISSING_PARAM", msg}
}

// UnableToAuthoriseJoin is an error that is returned when a server can't
// determine whether to allow a restricted join or not.
func UnableToAuthoriseJoin(msg string) MatrixError {
	return MatrixError{ErrorUnableToAuthoriseJoin, "M_UNABLE_TO_AUTHORISE_JOIN", msg}
}

// LeaveServerNoticeError is an error returned when trying to reject an invite
// for a server notice room.
func LeaveServerNoticeError() MatrixError {
	return MatrixError{
		Code:    ErrorCannotLeaveServerNoticeRoom,
		ErrCode: "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM",
		Err:     "You cannot reject this invite",
	}
}

// ErrRoomKeysVersion is an error returned by `PUT /room_keys/keys`
type ErrRoomKeysVersion struct {
	MatrixError
	CurrentVersion string `json:"current_version"`
}

func (e ErrRoomKeysVersion) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e ErrRoomKeysVersion) Unwrap() error {
	return e.MatrixError
}

// WrongBackupVersionError is an error returned by `PUT /room_keys/keys`
func WrongBackupVersionError(currentVersion string) ErrRoomKeysVersion {
	return ErrRoomKeysVersion{
		MatrixError: MatrixError{
			Code:    ErrorWrongRoomKeysVersion,
			ErrCode: "M_WRONG_ROOM_KEYS_VERSION",
			Err:     "Wrong backup version.",
		},
		CurrentVersion: currentVersion,
	}
}

type IncompatibleRoomVersionError struct {
	RoomVersion string `json:"room_version"`
	ErrCode     string `json:"errcode"`
	Err         string `json:"error"`
}

func (e IncompatibleRoomVersionError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e IncompatibleRoomVersionError) Unwrap() error {
	return fmt.Errorf(e.Err)
}

// IncompatibleRoomVersion is an error which is returned when the client
// requests a room with a version that is unsupported.
func IncompatibleRoomVersion(roomVersion string) IncompatibleRoomVersionError {
	return IncompatibleRoomVersionError{
		RoomVersion: roomVersion,
		ErrCode:     "M_INCOMPATIBLE_ROOM_VERSION",
		Err:         "Your homeserver does not support the features required to join this room",
	}
}

// UnsupportedRoomVersion is an error which is returned when the client
// requests a room with a version that is unsupported.
func UnsupportedRoomVersion(msg string) MatrixError {
	return MatrixError{ErrorUnsupportedRoomVersion, "M_UNSUPPORTED_ROOM_VERSION", msg}
}

// LimitExceededError is a rate-limiting error.
type LimitExceededError struct {
	MatrixError
	RetryAfterMS int64 `json:"retry_after_ms,omitempty"`
}

func (e LimitExceededError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Err)
}

func (e LimitExceededError) Unwrap() error {
	return e.MatrixError
}

// LimitExceeded is an error when the client tries to send events too quickly.
func LimitExceeded(msg string, retryAfterMS int64) LimitExceededError {
	return LimitExceededError{
		MatrixError:  MatrixError{ErrorLimitExceeded, "M_LIMIT_EXCEEDED", msg},
		RetryAfterMS: retryAfterMS,
	}
}

// NotTrusted is an error which is returned when the client asks the server to
// proxy a request (e.g. 3PID association) to a server that isn't trusted
func NotTrusted(serverName string) MatrixError {
	return MatrixError{
		Code:    ErrorServerNotTrusted,
		ErrCode: "M_SERVER_NOT_TRUSTED",
		Err:     fmt.Sprintf("Untrusted server '%s'", serverName),
	}
}
