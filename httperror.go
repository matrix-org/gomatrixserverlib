package gomatrixserverlib

import "fmt"

type HTTPError struct {
	WrappedError error
	Message      string
	Code         int
	Contents     []byte
}

func (e HTTPError) Error() string {
	var wrappedErrMsg string
	if e.WrappedError != nil {
		wrappedErrMsg = e.WrappedError.Error()
	}
	return fmt.Sprintf("msg=%s code=%d wrapped=%s", e.Message, e.Code, wrappedErrMsg)
}

func (e HTTPError) Unwrap() error {
	return e.WrappedError
}
