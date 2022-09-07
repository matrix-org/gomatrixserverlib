/* Copyright 2016-2017 Vector Creations Ltd
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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matrix-org/gomatrix"
	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"
)

// Default HTTPS request timeout
const requestTimeout time.Duration = time.Duration(30) * time.Second

// A Client makes HTTP requests to remote servers. It is used to
// centralise a number of configurable options, such as DNS caching,
// timeouts etc.
type Client struct {
	client    http.Client
	userAgent string
}

// UserInfo represents information about a user.
type UserInfo struct {
	Sub string `json:"sub"`
}

type clientOptions struct {
	transport    http.RoundTripper
	dnsCache     *DNSCache
	timeout      time.Duration
	skipVerify   bool
	keepAlives   bool
	wellKnownSRV bool
}

// ClientOption are supplied to NewClient or NewFederationClient.
type ClientOption func(*clientOptions)

// NewClient makes a new Client. You can supply zero or more ClientOptions
// which control the transport, timeout, TLS validation etc - see
// WithTransport, WithTimeout, WithSkipVerify, WithDNSCache etc.
func NewClient(options ...ClientOption) *Client {
	clientOpts := &clientOptions{
		timeout: requestTimeout,
	}
	for _, option := range options {
		option(clientOpts)
	}
	if clientOpts.transport == nil {
		clientOpts.transport = newDestinationTripper(
			clientOpts.skipVerify,
			clientOpts.dnsCache,
			clientOpts.keepAlives,
			clientOpts.wellKnownSRV,
		)
	}
	client := &Client{
		client: http.Client{
			Transport: clientOpts.transport,
			Timeout:   clientOpts.timeout,
		},
	}
	return client
}

// WithTransport is an option that can be supplied to either NewClient or
// NewFederationClient. Supplying this option will render WithDNSCache and
// WithSkipVerify ineffective.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(options *clientOptions) {
		options.transport = transport
	}
}

// WithTimeout is an option that can be supplied to either NewClient or
// NewFederationClient.
func WithTimeout(duration time.Duration) ClientOption {
	return func(options *clientOptions) {
		options.timeout = duration
	}
}

// WithDNSCache is an option that can be supplied to either NewClient or
// NewFederationClient. This option will be ineffective if WithTransport
// has already been supplied.
func WithDNSCache(cache *DNSCache) ClientOption {
	return func(options *clientOptions) {
		options.dnsCache = cache
	}
}

// WithSkipVerify is an option that can be supplied to either NewClient or
// NewFederationClient. This option will be ineffective if WithTransport
// has already been supplied.
func WithSkipVerify(skipVerify bool) ClientOption {
	return func(options *clientOptions) {
		options.skipVerify = skipVerify
	}
}

// WithKeepAlives is an option that can be supplied to either NewClient or
// NewFederationClient. This option will be ineffective if WithTransport
// has already been supplied.
func WithKeepAlives(keepAlives bool) ClientOption {
	return func(options *clientOptions) {
		options.keepAlives = keepAlives
	}
}

// WithWellKnownSRVLookups enables federation lookups of well-known and SRV records.
func WithWellKnownSRVLookups(wellKnownSRV bool) ClientOption {
	return func(options *clientOptions) {
		options.wellKnownSRV = wellKnownSRV
	}
}

const destinationTripperLifetime = time.Minute * 5 // how long to keep an entry
const destinationTripperReapInterval = time.Minute // how often to check for dead entries

// nolint:maligned
type destinationTripper struct {
	// transports maps an TLS server name with an HTTP transport.
	transports      map[string]*destinationTripperTransport
	transportsMutex sync.Mutex
	skipVerify      bool
	resolutionCache sync.Map // serverName -> []ResolutionResult
	dnsCache        *DNSCache
	keepAlives      bool
	wellKnownSRV    bool
}

func newDestinationTripper(skipVerify bool, dnsCache *DNSCache, keepAlives, wellKnownSRV bool) *destinationTripper {
	tripper := &destinationTripper{
		transports:   make(map[string]*destinationTripperTransport),
		skipVerify:   skipVerify,
		dnsCache:     dnsCache,
		keepAlives:   keepAlives,
		wellKnownSRV: wellKnownSRV,
	}
	time.AfterFunc(destinationTripperReapInterval, tripper.reaper)
	return tripper
}

// reaper will remove round-trippers for remote servers that haven't been used
// in a while, otherwise we will just collect these in memory forever.
func (f *destinationTripper) reaper() {
	f.transportsMutex.Lock()
	defer f.transportsMutex.Unlock()

	for serverName, transport := range f.transports {
		since := transport.lastUsed.Load().(time.Time)
		if time.Since(since) > destinationTripperLifetime {
			delete(f.transports, serverName)
		}
	}

	time.AfterFunc(destinationTripperReapInterval, f.reaper)
}

// destinationTripperDialer enforces dial timeouts on the federation requests. If
// the TCP connection doesn't complete within 5 seconds, it's probably just not
// going to.
var destinationTripperDialer = &net.Dialer{
	Timeout: time.Second * 5,
}

type destinationTripperTransport struct {
	*http.Transport
	lastUsed atomic.Value // time.Time
}

// getTransport returns a http.Transport instance with a TLS configuration using
// the given server name for SNI. It also creates the instance if there isn't
// any for this server name.
// We need to use one transport per TLS server name (instead of giving our round
// tripper a single transport) because there is no way to specify the TLS
// ServerName on a per-connection basis.
func (f *destinationTripper) getTransport(tlsServerName string) http.RoundTripper {
	f.transportsMutex.Lock()
	defer f.transportsMutex.Unlock()

	// Create the transport if we don't have any for this TLS server name.
	transport, ok := f.transports[tlsServerName]
	if !ok {
		tr := &destinationTripperTransport{
			Transport: &http.Transport{
				DisableKeepAlives:   !f.keepAlives,
				MaxIdleConnsPerHost: 1,                          // only used if keepalives enabled
				IdleConnTimeout:     destinationTripperLifetime, // only used if keepalives enabled
				TLSClientConfig: &tls.Config{
					ServerName:         tlsServerName,
					InsecureSkipVerify: f.skipVerify,
					ClientSessionCache: tls.NewLRUClientSessionCache(0), // 0 = use default
				},
				Dial:              destinationTripperDialer.Dial, // nolint: staticcheck
				DialContext:       destinationTripperDialer.DialContext,
				Proxy:             http.ProxyFromEnvironment,
				ForceAttemptHTTP2: true, // if we can multiplex requests over HTTP/2, we should
			},
		}
		if f.dnsCache != nil {
			tr.DialContext = f.dnsCache.DialContext
		}
		transport, f.transports[tlsServerName] = tr, tr
	}

	transport.lastUsed.Store(time.Now())
	return transport
}

func makeHTTPSURL(u *url.URL, addr string) (httpsURL url.URL) {
	httpsURL = *u
	httpsURL.Scheme = "https"
	httpsURL.Host = addr
	return
}

func (f *destinationTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	var err error
	serverName := ServerName(r.URL.Host)
	resolutionRetried := false
	resolutionResults := []ResolutionResult{}

retryResolution:
	if f.wellKnownSRV {
		if cached, ok := f.resolutionCache.Load(serverName); ok {
			if results, ok := cached.([]ResolutionResult); ok {
				resolutionResults = results
			}
		}

		// If the cache returned nothing then we'll have no results here,
		// so go and hit the network.
		if len(resolutionResults) == 0 {
			resolutionResults, err = ResolveServer(r.Context(), serverName)
			if err != nil {
				return nil, err
			}
			f.resolutionCache.Store(serverName, resolutionResults)
		}
	} else {
		resolutionResults = append(resolutionResults, ResolutionResult{
			Destination:   r.URL.Host,
			Host:          ServerName(r.Host),
			TLSServerName: r.Host,
		})
	}

	// If we still have no results at this point, even after possibly
	// hitting the network, then give up.
	if len(resolutionResults) == 0 {
		return nil, fmt.Errorf("no address found for matrix host %v", serverName)
	}

	var resp *http.Response
	// TODO: respect the priority and weight fields from the SRV record
	for _, result := range resolutionResults {
		u := makeHTTPSURL(r.URL, result.Destination)
		r.URL = &u
		r.Host = string(result.Host)
		resp, err = f.getTransport(result.TLSServerName).RoundTrip(r)
		if err == nil {
			return resp, nil
		}
		util.GetLogger(r.Context()).Debugf("Error sending request to %s: %v",
			u.String(), err)
	}

	// We failed to reach any of the locations in the resolution results,
	// so clear the cache and mark that we're retrying, then give it a
	// try again.
	f.resolutionCache.Delete(serverName)
	if !resolutionRetried {
		resolutionRetried = true
		goto retryResolution
	}

	// just return the most recent error
	return nil, err
}

// SetUserAgent sets the user agent string that is sent in the headers of
// outbound HTTP requests.
func (fc *Client) SetUserAgent(ua string) {
	fc.userAgent = ua
}

// LookupUserInfo gets information about a user from a given matrix homeserver
// using a bearer access token.
func (fc *Client) LookupUserInfo(
	ctx context.Context, matrixServer ServerName, token string,
) (u UserInfo, err error) {
	url := url.URL{
		Scheme:   "matrix",
		Host:     string(matrixServer),
		Path:     "/_matrix/federation/v1/openid/userinfo",
		RawQuery: url.Values{"access_token": []string{token}}.Encode(),
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return
	}

	var response *http.Response
	response, err = fc.DoHTTPRequest(ctx, req)
	if response != nil {
		defer response.Body.Close() // nolint: errcheck
	}
	if err != nil {
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var errorOutput []byte
		errorOutput, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return
		}
		err = fmt.Errorf("HTTP %d : %s", response.StatusCode, errorOutput)
		return
	}

	err = json.NewDecoder(response.Body).Decode(&u)
	if err != nil {
		return
	}

	userParts := strings.SplitN(u.Sub, ":", 2)
	if len(userParts) != 2 || userParts[1] != string(matrixServer) {
		err = fmt.Errorf("userID doesn't match server name '%v' != '%v'", u.Sub, matrixServer)
		return
	}

	return
}

// GetServerKeys asks a matrix server for its signing keys and TLS cert
func (fc *Client) GetServerKeys(
	ctx context.Context, matrixServer ServerName,
) (ServerKeys, error) {
	url := url.URL{
		Scheme: "matrix",
		Host:   string(matrixServer),
		Path:   "/_matrix/key/v2/server",
	}

	var body ServerKeys
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return body, err
	}

	err = fc.DoRequestAndParseResponse(
		ctx, req, &body,
	)
	return body, err
}

// GetVersion gets the version information of a homeserver.
// See https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-version
func (fc *Client) GetVersion(
	ctx context.Context, s ServerName,
) (res Version, err error) {
	// Construct a request for version information
	url := url.URL{
		Scheme: "matrix",
		Host:   string(s),
		Path:   "/_matrix/federation/v1/version",
	}
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return
	}

	// Make the request and parse the response
	err = fc.DoRequestAndParseResponse(ctx, req, &res)
	return
}

// LookupServerKeys looks up the keys for a matrix server from a matrix server.
// The first argument is the name of the matrix server to download the keys from.
// The second argument is a map from (server name, key ID) pairs to timestamps.
// The (server name, key ID) pair identifies the key to download.
// The timestamps tell the server when the keys need to be valid until.
// Perspective servers can use that timestamp to determine whether they can
// return a cached copy of the keys or whether they will need to retrieve a fresh
// copy of the keys.
// Returns the keys returned by the server, or an error if there was a problem talking to the server.
func (fc *Client) LookupServerKeys(
	ctx context.Context, matrixServer ServerName, keyRequests map[PublicKeyLookupRequest]Timestamp,
) ([]ServerKeys, error) {
	url := url.URL{
		Scheme: "matrix",
		Host:   string(matrixServer),
		Path:   "/_matrix/key/v2/query",
	}

	// The request format is:
	// { "server_keys": { "<server_name>": { "<key_id>": { "minimum_valid_until_ts": <ts> }}}
	type keyreq struct {
		MinimumValidUntilTS Timestamp `json:"minimum_valid_until_ts"`
	}
	request := struct {
		ServerKeyMap map[ServerName]map[KeyID]keyreq `json:"server_keys"`
	}{map[ServerName]map[KeyID]keyreq{}}
	for k, ts := range keyRequests {
		server := request.ServerKeyMap[k.ServerName]
		if server == nil {
			server = map[KeyID]keyreq{}
			request.ServerKeyMap[k.ServerName] = server
		}
		if k.KeyID != "" {
			server[k.KeyID] = keyreq{ts}
		}
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var body struct {
		ServerKeyList []json.RawMessage `json:"server_keys"`
	}

	var res struct {
		ServerKeyList []ServerKeys
	}

	req, err := http.NewRequest("POST", url.String(), bytes.NewBuffer(requestBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	err = fc.DoRequestAndParseResponse(
		ctx, req, &body,
	)
	if err != nil {
		return nil, err
	}

	for _, field := range body.ServerKeyList {
		var keys ServerKeys
		if err := json.Unmarshal(field, &keys); err == nil {
			res.ServerKeyList = append(res.ServerKeyList, keys)
		}
	}

	return res.ServerKeyList, nil
}

// CreateMediaDownloadRequest creates a request for media on a homeserver and returns the http.Response or an error
func (fc *Client) CreateMediaDownloadRequest(
	ctx context.Context, matrixServer ServerName, mediaID string,
) (*http.Response, error) {
	// Set allow_remote=false here so that we avoid loops:
	// https://github.com/matrix-org/synapse/pull/1992
	requestURL := "matrix://" + string(matrixServer) + "/_matrix/media/v3/download/" + string(matrixServer) + "/" + mediaID + "?allow_remote=false"
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	return fc.DoHTTPRequest(ctx, req)
}

// DoRequestAndParseResponse calls DoHTTPRequest and then decodes the response.
//
// If the HTTP response is not a 200, an attempt is made to parse the response
// body into a gomatrix.RespError. In any case, a non-200 response will result
// in a gomatrix.HTTPError.
func (fc *Client) DoRequestAndParseResponse(
	ctx context.Context,
	req *http.Request,
	result interface{},
) error {
	response, err := fc.DoHTTPRequest(ctx, req)
	if response != nil {
		defer response.Body.Close() // nolint: errcheck
	}
	if err != nil {
		return err
	}

	if response.StatusCode/100 != 2 { // not 2xx
		// Adapted from https://github.com/matrix-org/gomatrix/blob/master/client.go
		var contents []byte
		contents, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}

		var wrap error
		var respErr gomatrix.RespError
		if _ = json.Unmarshal(contents, &respErr); respErr.ErrCode != "" {
			wrap = respErr
		}

		// If we failed to decode as RespError, don't just drop the HTTP body, include it in the
		// HTTP error instead (e.g proxy errors which return HTML).
		msg := fmt.Sprintf("Failed to %s JSON (hostname %q path %q)", req.Method, req.Host, req.URL.Path)
		if wrap == nil {
			msg += ": " + string(contents)
		}

		return gomatrix.HTTPError{
			Code:         response.StatusCode,
			Message:      msg,
			WrappedError: wrap,
			Contents:     contents,
		}
	}

	if err = json.NewDecoder(response.Body).Decode(result); err != nil {
		return err
	}

	return nil
}

// DoHTTPRequest creates an outgoing request ID and adds it to the context
// before sending off the request and awaiting a response.
//
// If the returned error is nil, the Response will contain a non-nil
// Body which the caller is expected to close.
func (fc *Client) DoHTTPRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	reqID := util.RandomString(12)
	logger := util.GetLogger(ctx).WithFields(logrus.Fields{
		"out.req.ID":     reqID,
		"out.req.method": req.Method,
		"out.req.uri":    req.URL,
	})
	logger.Trace("Outgoing request")
	newCtx := util.ContextWithLogger(ctx, logger)
	if fc.userAgent != "" {
		req.Header.Set("User-Agent", fc.userAgent)
	}

	start := time.Now()
	resp, err := fc.client.Do(req.WithContext(newCtx))
	if err != nil {
		logger.WithContext(ctx).WithField("error", err).Debug("Outgoing request failed")
		return nil, err
	}

	// we haven't yet read the body, so this is slightly premature, but it's the easiest place.
	logger.WithFields(logrus.Fields{
		"out.req.code":        resp.StatusCode,
		"out.req.duration_ms": int(time.Since(start) / time.Millisecond),
	}).Trace("Outgoing request returned")

	return resp, nil
}
