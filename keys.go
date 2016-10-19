package matrixfederation

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// ServerKeys are the ed25519 signing keys published by a matrix server.
// Contains SHA256 fingerprints of the TLS X509 certificates used by the server.
type ServerKeys struct {
	Raw             []byte     `json:"-"`           // Copy of the raw JSON for signature checking.
	ServerName      string     `json:"server_name"` // The name of the server.
	TLSFingerprints []struct { // List of SHA256 fingerprints of X509 certificates.
		SHA256 Base64String `json:"sha256"`
	} `json:"tls_fingerprints"`
	VerifyKeys map[string]struct { // The current signing keys in use on this server.
		Key Base64String `json:"key"` // The public key.
	} `json:"verify_keys"`
	ValidUntilTS  uint64              `json:"valid_until_ts"` // When this result is valid until in milliseconds.
	OldVerifyKeys map[string]struct { // Old keys that are now only valid for checking historic events.
		Key       Base64String `json:"key"`        // The public key.
		ExpiredTS uint64       `json:"expired_ts"` // When this key stopped being valid for event signing.
	} `json:"old_verify_keys"`
}

// FetchKeysDirect fetches the matrix keys directly from the given address.
// Optionally sets a SNI header if ``sni`` is not empty.
// Returns the server keys and the state of the TLS connection used to retrieve them.
func FetchKeysDirect(serverName, addr, sni string) (*ServerKeys, *tls.ConnectionState, error) {
	// Create a TLS connection.
	tcpconn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	defer tcpconn.Close()
	tlsconn := tls.Client(tcpconn, &tls.Config{ServerName: sni})
	if err = tlsconn.Handshake(); err != nil {
		return nil, nil, err
	}
	connectionState := tlsconn.ConnectionState()

	// Write a GET /_matrix/key/v2/server down the connection.
	requestURL := "matrix://" + serverName + "/_matrix/key/v2/server"
	request, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Connection", "close")
	if err = request.Write(tlsconn); err != nil {
		return nil, nil, err
	}

	// Read the 200 OK from the server.
	response, err := http.ReadResponse(bufio.NewReader(tlsconn), request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	var keys ServerKeys
	if keys.Raw, err = ioutil.ReadAll(response.Body); err != nil {
		return nil, nil, err
	}
	if err = json.Unmarshal(keys.Raw, &keys); err != nil {
		return nil, nil, err
	}
	return &keys, &connectionState, nil
}

// KeyChecks are the checks that should be applied to ServerKey responses.
type KeyChecks struct {
	AllChecksOK               bool  // Did all the checks pass?
	MatchingServerName        bool  // Does the server name match what was requested.
	FutureValidUntilTS        bool  // The valid until TS is in the future.
	HasEd25519VerifyKey       bool  // The key response has a E25519 key for the server.
	ValidEd25519VerifyKey     bool  // The verify keys are value.
	MatchingEd25519Signature  bool  // Every verify key claimed has a valid signature.
	HasTLSFingerprint         bool  // The response includes a TLS fingerprint.
	ValidSHA256TLSFingerprint bool  // Every TLS fingerprint includes a SHA-256 hash.
	MatchingTLSFingerprint    *bool // The TLS fingerprint for the connection matches one of the listed fingerprints.
}

// CheckKeys checks the keys returned from a server to make sure they are valid.
// If the checks pass then also return a map of key_id to Ed25519 public key and a list of SHA256 TLS fingerprints.
func CheckKeys(serverName string, timeNowMs uint64, keys ServerKeys, connState *tls.ConnectionState) (
	checks KeyChecks, ed25519Keys map[string]Base64String, sha256Fingerprints []Base64String,
) {
	checks.MatchingServerName = serverName == keys.ServerName

	ed25519Keys = checkVerifyKeys(keys, &checks)
	sha256Fingerprints = checkTLSFingerprints(keys, &checks)

	checks.FutureValidUntilTS = timeNowMs < keys.ValidUntilTS

	checks.AllChecksOK = (checks.MatchingServerName &&
		checks.FutureValidUntilTS &&
		checks.HasEd25519VerifyKey &&
		checks.ValidEd25519VerifyKey &&
		checks.MatchingEd25519Signature &&
		checks.HasTLSFingerprint &&
		checks.ValidSHA256TLSFingerprint)

	// Only check the fingerprint if we have the TLS connection state.
	if connState != nil {
		// Check the peer certificates.
		matches := checkFingerprint(connState, sha256Fingerprints)
		checks.MatchingTLSFingerprint = &matches
		checks.AllChecksOK = checks.AllChecksOK && matches
	}

	if !checks.AllChecksOK {
		sha256Fingerprints = nil
		ed25519Keys = nil
	}
	return
}

func checkFingerprint(connState *tls.ConnectionState, sha256Fingerprints []Base64String) bool {
	if len(connState.PeerCertificates) == 0 {
		return false
	}
	cert := connState.PeerCertificates[0]
	digest := sha256.Sum256(cert.Raw)
	for _, fingerprint := range sha256Fingerprints {
		if bytes.Compare(digest[:], fingerprint) == 0 {
			return true
		}
	}
	return false
}

func checkVerifyKeys(keys ServerKeys, checks *KeyChecks) map[string]Base64String {
	checks.ValidEd25519VerifyKey = true
	checks.MatchingEd25519Signature = true
	verifyKeys := map[string]Base64String{}
	for keyID, keyData := range keys.VerifyKeys {
		algorithm := strings.SplitN(keyID, ":", 2)[0]
		publicKey := keyData.Key
		if algorithm == "ed25519" {
			if len(publicKey) != 32 {
				checks.ValidEd25519VerifyKey = false
				continue
			}
			if err := VerifyJSON(keys.ServerName, keyID, []byte(publicKey), keys.Raw); err != nil {
				checks.MatchingEd25519Signature = false
				continue
			}
			checks.HasEd25519VerifyKey = true
			verifyKeys[keyID] = publicKey
		}
	}
	return verifyKeys
}

func checkTLSFingerprints(keys ServerKeys, checks *KeyChecks) []Base64String {
	var fingerprints []Base64String
	checks.ValidSHA256TLSFingerprint = true
	for _, fingerprint := range keys.TLSFingerprints {
		if len(fingerprint.SHA256) != sha256.Size {
			checks.ValidSHA256TLSFingerprint = false
			continue
		}
		checks.HasTLSFingerprint = true
		fingerprints = append(fingerprints, fingerprint.SHA256)
	}
	return fingerprints
}
