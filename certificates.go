package gomatrixserverlib

import (
	"crypto/x509"
	"errors"
)

// IsValidCertificate checks if the given x509 certificate can be verified using
// system root CAs and an optional pool of intermediate CAs.
func IsValidCertificate(serverName ServerName, c *x509.Certificate, intermediates *x509.CertPool) (valid bool, err error) {
	host, _, isValid := ParseAndValidateServerName(serverName)
	if !isValid {
		return false, errors.New("Not a valid serverName")
	}

	// Check certificate chain validity
	verificationOpts := x509.VerifyOptions{
		// Certificate.Verify appears to handle IP addresses optionally surrounded by square brackets.
		DNSName:       host,
		Intermediates: intermediates,
	}
	roots, err := c.Verify(verificationOpts)

	return len(roots) > 0, err
}
