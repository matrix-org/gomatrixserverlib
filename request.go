package gomatrixserverlib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/matrix-org/util"
	"golang.org/x/crypto/ed25519"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// A MatrixRequest is a request to send to remote server or a request received
// from a remote server.
// Matrix requests are signed by building a JSON object and signing it
type MatrixRequest struct {
	fields struct {
		Content     rawJSON                      `json:"content,omitempty"`
		Destination string                       `json:"destination"`
		Method      string                       `json:"method"`
		Origin      string                       `json:"origin"`
		Signatures  map[string]map[string]string `json:"signatures,omitempty"`
		RequestURI  string                       `json:"uri"`
	}
}

// NewMatrixRequest creates a matrix request. Takes an HTTP method, a
// destination homeserver and a request path which can have a query string.
func NewMatrixRequest(method, destination, requestURL string) MatrixRequest {
	var r MatrixRequest
	r.fields.Destination = destination
	r.fields.Method = method
	r.fields.RequestURI = requestURL
	return r
}

// SetContent sets the JSON content for the request.
// Returns an error if there already is JSON content present on the request.
func (r *MatrixRequest) SetContent(content interface{}) error {
	if r.fields.Content != nil {
		return fmt.Errorf("gomatrixserverlib: content already set on the request")
	}
	if r.fields.Signatures != nil {
		return fmt.Errorf("gomatrixserverlib: the request is signed and cannot be modified")
	}
	data, err := json.Marshal(content)
	if err != nil {
		return err
	}
	r.fields.Content = rawJSON(data)
	return nil
}

// Method returns the JSON method for the request.
func (r *MatrixRequest) Method() string {
	return r.fields.Method
}

// Content returns the JSON content for the request.
func (r *MatrixRequest) Content() []byte {
	return []byte(r.fields.Content)
}

// Origin returns the server that the request originated on.
func (r *MatrixRequest) Origin() string {
	return r.fields.Origin
}

// RequestURI returns the path and query sections of the HTTP request URL.
func (r *MatrixRequest) RequestURI() string {
	return r.fields.RequestURI
}

// Sign the matrix request with an ed25519 key.
// Updates the request with the signature inplace.
// Returns an error if there was a problem signing the request.
func (r *MatrixRequest) Sign(serverName, keyID string, privateKey ed25519.PrivateKey) error {
	if r.fields.Origin != "" && r.fields.Origin != serverName {
		return fmt.Errorf("gomatrixserverlib: the request is already signed by a different server")
	}
	r.fields.Origin = serverName
	data, err := json.Marshal(r.fields)
	if err != nil {
		return err
	}
	signedData, err := SignJSON(serverName, keyID, privateKey, data)
	if err != nil {
		return err
	}
	return json.Unmarshal(signedData, &r.fields)
}

// HTTPRequest constructs an net/http.Request for this matrix request.
// The request can be passed to net/http.Client.Do().
func (r *MatrixRequest) HTTPRequest() (*http.Request, error) {
	urlStr := fmt.Sprintf("matrix://%s%s", r.fields.Destination, r.fields.RequestURI)

	var content io.Reader
	if r.fields.Content != nil {
		content = bytes.NewReader([]byte(r.fields.Content))
	}

	httpReq, err := http.NewRequest(r.fields.Method, urlStr, content)
	if err != nil {
		return nil, err
	}

	if r.fields.Content != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	for keyID, sig := range r.fields.Signatures[r.fields.Origin] {
		httpReq.Header.Add("Authorization", fmt.Sprintf(
			"X-Matrix origin=\"%s\",key=\"%s\",sig=\"%s\"", r.fields.Origin, keyID, sig,
		))
	}

	return httpReq, nil
}

// VerifyHTTPRequest extracts and verifies the contents of a net/http.Request.
// It consumes the body of the request.
// The JSON content can be accessed using MatrixRequest.Content()
// Returns an 400 error if there was a problem parsing the request.
// It authenticates the request using an ed25519 signature using the KeyRing.
// The origin server can be accesed using MatrixRequest.Origin()
// Returns a 401 error if there was a problem authenticating the request.
// HTTP handlers using this should be careful that they only use the parts of
// the request that have been authenticated: the method, the request path,
// the query parameters, and the JSON content.
func VerifyHTTPRequest(
	req *http.Request, now time.Time, destination string, keys KeyRing,
) (*MatrixRequest, util.JSONResponse) {
	request, err := readHTTPRequest(req)
	if err != nil {
		util.GetLogger(req.Context()).WithError(err).Print("Error parsing HTTP headers")
		return nil, util.MessageResponse(400, "Bad Request")
	}
	request.fields.Destination = destination

	toVerify, err := json.Marshal(request.fields)
	if err != nil {
		util.GetLogger(req.Context()).WithError(err).Print("Error parsing JSON")
		return nil, util.MessageResponse(400, "Invalid JSON")
	}

	if request.Origin() == "" {
		message := "Missing \"Authorization: X-Matrix ...\" HTTP header"
		util.GetLogger(req.Context()).WithError(err).Print(message)
		return nil, util.MessageResponse(401, message)
	}

	results, err := keys.VerifyJSONs([]VerifyJSONRequest{{
		ServerName: request.Origin(),
		AtTS:       Timestamp(now.UnixNano() / 1000000),
		Message:    toVerify,
	}})
	if err != nil {
		message := "Error authenticating request"
		util.GetLogger(req.Context()).WithError(err).Print(message)
		return nil, util.MessageResponse(500, message)
	}
	if results[0].Result != nil {
		message := "Invalid request signature"
		util.GetLogger(req.Context()).WithError(results[0].Result).Print(message)
		return nil, util.MessageResponse(401, message)
	}

	return request, util.JSONResponse{Code: 200, JSON: struct{}{}}
}

// Returns an error if there was a problem reading the content of the request
func readHTTPRequest(req *http.Request) (*MatrixRequest, error) {
	var result MatrixRequest

	result.fields.Method = req.Method
	result.fields.RequestURI = req.URL.RequestURI()

	content, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if len(content) != 0 {
		if req.Header.Get("Content-Type") != "application/json" {
			return nil, fmt.Errorf(
				"gomatrixserverlib: The request must be \"application/json\" not %q",
				req.Header.Get("Content-Type"),
			)
		}
		result.fields.Content = rawJSON(content)
	}

	for _, authorization := range req.Header["Authorization"] {
		parts := strings.SplitN(authorization, " ", 2)
		if parts[0] != "X-Matrix" {
			continue
		}
		origin, key, sig := parseAuthorizationXMatrix(parts)
		if origin == "" || key == "" || sig == "" {
			return nil, fmt.Errorf("gomatrixserverlib: invalid X-Matrix authorization header")
		}
		if result.fields.Origin != "" && result.fields.Origin != origin {
			return nil, fmt.Errorf("gomatrixserverlib: different origins in X-Matrix authorization headers")
		}
		result.fields.Origin = origin
		if result.fields.Signatures == nil {
			result.fields.Signatures = map[string]map[string]string{origin: map[string]string{key: sig}}
		} else {
			result.fields.Signatures[origin][key] = sig
		}
	}

	return &result, nil
}

func parseAuthorizationXMatrix(headerParts []string) (origin, key, sig string) {
	if len(headerParts) != 2 {
		return
	}
	for _, data := range strings.Split(headerParts[1], ",") {
		pair := strings.SplitN(data, "=", 2)
		if len(pair) != 2 {
			continue
		}
		name := pair[0]
		value := strings.Trim(pair[1], "\"")
		if name == "origin" {
			origin = value
		}
		if name == "key" {
			key = value
		}
		if name == "sig" {
			sig = value
		}
	}
	return
}
