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

type MatrixErrorCode string

const (
	ErrorUnknown                     MatrixErrorCode = "M_UNKNOWN"
	ErrorUnrecognized                MatrixErrorCode = "M_UNRECOGNIZED"
	ErrorForbidden                   MatrixErrorCode = "M_FORBIDDEN"
	ErrorBadJSON                     MatrixErrorCode = "M_BAD_JSON"
	ErrorBadAlias                    MatrixErrorCode = "M_BAD_ALIAS"
	ErrorNotJSON                     MatrixErrorCode = "M_NOT_JSON"
	ErrorNotFound                    MatrixErrorCode = "M_NOT_FOUND"
	ErrorMissingToken                MatrixErrorCode = "M_MISSING_TOKEN"
	ErrorUnknownToken                MatrixErrorCode = "M_UNKNOWN_TOKEN"
	ErrorWeakPassword                MatrixErrorCode = "M_WEAK_PASSWORD"
	ErrorInvalidUsername             MatrixErrorCode = "M_INVALID_USERNAME"
	ErrorUserInUse                   MatrixErrorCode = "M_USER_IN_USE"
	ErrorRoomInUse                   MatrixErrorCode = "M_ROOM_IN_USE"
	ErrorExclusive                   MatrixErrorCode = "M_EXCLUSIVE"
	ErrorGuestAccessForbidden        MatrixErrorCode = "M_GUEST_ACCESS_FORBIDDEN"
	ErrorInvalidSignature            MatrixErrorCode = "M_INVALID_SIGNATURE"
	ErrorInvalidParam                MatrixErrorCode = "M_INVALID_PARAM"
	ErrorMissingParam                MatrixErrorCode = "M_MISSING_PARAM"
	ErrorUnableToAuthoriseJoin       MatrixErrorCode = "M_UNABLE_TO_AUTHORISE_JOIN"
	ErrorCannotLeaveServerNoticeRoom MatrixErrorCode = "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM"
	ErrorWrongRoomKeysVersion        MatrixErrorCode = "M_WRONG_ROOM_KEYS_VERSION"
	ErrorIncompatibleRoomVersion     MatrixErrorCode = "M_INCOMPATIBLE_ROOM_VERSION"
	ErrorUnsupportedRoomVersion      MatrixErrorCode = "M_UNSUPPORTED_ROOM_VERSION"
	ErrorLimitExceeded               MatrixErrorCode = "M_LIMIT_EXCEEDED"
	ErrorServerNotTrusted            MatrixErrorCode = "M_SERVER_NOT_TRUSTED"
	ErrorSessionNotValidated         MatrixErrorCode = "M_SESSION_NOT_VALIDATED"
	ErrorThreePIDInUse               MatrixErrorCode = "M_THREEPID_IN_USE"
	ErrorThreePIDAuthFailed          MatrixErrorCode = "M_THREEPID_AUTH_FAILED"
)

// MatrixError represents the "standard error response" in Matrix.
// http://matrix.org/docs/spec/client_server/r0.2.0.html#api-standards
type MatrixError struct {
	ErrCode MatrixErrorCode `json:"errcode"`
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
	return MatrixError{ErrorUnknown, msg}
}

// Unrecognized is an error when the server received a request at
// an unexpected endpoint.
func Unrecognized(msg string) MatrixError {
	return MatrixError{ErrorUnrecognized, msg}
}

// Forbidden is an error when the client tries to access a resource
// they are not allowed to access.
func Forbidden(msg string) MatrixError {
	return MatrixError{ErrorForbidden, msg}
}

// BadJSON is an error when the client supplies malformed JSON.
func BadJSON(msg string) MatrixError {
	return MatrixError{ErrorBadJSON, msg}
}

// BadAlias is an error when the client supplies a bad alias.
func BadAlias(msg string) MatrixError {
	return MatrixError{ErrorBadAlias, msg}
}

// NotJSON is an error when the client supplies something that is not JSON
// to a JSON endpoint.
func NotJSON(msg string) MatrixError {
	return MatrixError{ErrorNotJSON, msg}
}

// NotFound is an error when the client tries to access an unknown resource.
func NotFound(msg string) MatrixError {
	return MatrixError{ErrorNotFound, msg}
}

// MissingToken is an error when the client tries to access a resource which
// requires authentication without supplying credentials.
func MissingToken(msg string) MatrixError {
	return MatrixError{ErrorMissingToken, msg}
}

// UnknownToken is an error when the client tries to access a resource which
// requires authentication and supplies an unrecognised token
func UnknownToken(msg string) MatrixError {
	return MatrixError{ErrorUnknownToken, msg}
}

// WeakPassword is an error which is returned when the client tries to register
// using a weak password. http://matrix.org/docs/spec/client_server/r0.2.0.html#password-based
func WeakPassword(msg string) MatrixError {
	return MatrixError{ErrorWeakPassword, msg}
}

// InvalidUsername is an error returned when the client tries to register an
// invalid username
func InvalidUsername(msg string) MatrixError {
	return MatrixError{ErrorInvalidUsername, msg}
}

// UserInUse is an error returned when the client tries to register an
// username that already exists
func UserInUse(msg string) MatrixError {
	return MatrixError{ErrorUserInUse, msg}
}

// RoomInUse is an error returned when the client tries to make a room
// that already exists
func RoomInUse(msg string) MatrixError {
	return MatrixError{ErrorRoomInUse, msg}
}

// ASExclusive is an error returned when an application service tries to
// register an username that is outside of its registered namespace, or if a
// user attempts to register a username or room alias within an exclusive
// namespace.
func ASExclusive(msg string) MatrixError {
	return MatrixError{ErrorExclusive, msg}
}

// GuestAccessForbidden is an error which is returned when the client is
// forbidden from accessing a resource as a guest.
func GuestAccessForbidden(msg string) MatrixError {
	return MatrixError{ErrorGuestAccessForbidden, msg}
}

// InvalidSignature is an error which is returned when the client tries
// to upload invalid signatures.
func InvalidSignature(msg string) MatrixError {
	return MatrixError{ErrorInvalidSignature, msg}
}

// InvalidParam is an error that is returned when a parameter has the wrong
// value or type.
func InvalidParam(msg string) MatrixError {
	return MatrixError{ErrorInvalidParam, msg}
}

// MissingParam is an error that is returned when a parameter is missing from
// a request.
func MissingParam(msg string) MatrixError {
	return MatrixError{ErrorMissingParam, msg}
}

// UnableToAuthoriseJoin is an error that is returned when a server can't
// determine whether to allow a restricted join or not.
func UnableToAuthoriseJoin(msg string) MatrixError {
	return MatrixError{ErrorUnableToAuthoriseJoin, msg}
}

// LeaveServerNoticeError is an error returned when trying to reject an invite
// for a server notice room.
func LeaveServerNoticeError() MatrixError {
	return MatrixError{
		ErrCode: ErrorCannotLeaveServerNoticeRoom,
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
			ErrCode: ErrorWrongRoomKeysVersion,
			Err:     "Wrong backup version.",
		},
		CurrentVersion: currentVersion,
	}
}

type IncompatibleRoomVersionError struct {
	MatrixError
	RoomVersion string `json:"room_version"`
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
		MatrixError: MatrixError{
			ErrCode: ErrorIncompatibleRoomVersion,
			Err:     "Your homeserver does not support the features required to join this room",
		},
	}
}

// UnsupportedRoomVersion is an error which is returned when the client
// requests a room with a version that is unsupported.
func UnsupportedRoomVersion(msg string) MatrixError {
	return MatrixError{ErrorUnsupportedRoomVersion, msg}
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
		MatrixError:  MatrixError{ErrorLimitExceeded, msg},
		RetryAfterMS: retryAfterMS,
	}
}

// NotTrusted is an error which is returned when the client asks the server to
// proxy a request (e.g. 3PID association) to a server that isn't trusted
func NotTrusted(serverName string) MatrixError {
	return MatrixError{
		ErrCode: ErrorServerNotTrusted,
		Err:     fmt.Sprintf("Untrusted server '%s'", serverName),
	}
}
