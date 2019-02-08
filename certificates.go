package gomatrixserverlib

import (
	"crypto/x509"
	"errors"
	"net"
	"strings"
)

// IsValidCertificate checks if the given x509 certificate can be verified using
// system root CAs and an optional pool of intermediate CAs.
func IsValidCertificate(serverName ServerName, c *x509.Certificate, intermediates *x509.CertPool) (valid bool, err error) {
	// Clean and verify serverName
	serverNameCleaned, err := cleanAndVerifyServerName(serverName)
	if err != nil {
		return false, err
	}

	// Check certificate chain validity
	verificationOpts := x509.VerifyOptions{
		DNSName:       serverNameCleaned,
		Intermediates: intermediates,
	}
	roots, err := c.Verify(verificationOpts)

	return len(roots) > 0, err
}

// cleanServerName is a function that takes in a ServerName, verifies it, and
// removes the port if necessary
// TODO: Support IP Addresses (and update test)
func cleanAndVerifyServerName(serverName ServerName) (serverNameCleaned string, err error) {
	serverNameCleaned = string(serverName)

	// Remove port from serverName if it exists
	serverNameCleanedNoPort := strings.Split(string(serverName), ":")[0]

	// Fail if serverName is an ipv4/6
	if strings.Contains(serverNameCleaned, "[") || net.ParseIP(serverNameCleaned) != nil ||
		net.ParseIP(serverNameCleanedNoPort) != nil {
		// This is an IP Address, fail
		return "", errors.New("serverName is an IP literal. This is not currently supported for certificate validation checking.")
	}
	 

	return serverNameCleanedNoPort, nil
}