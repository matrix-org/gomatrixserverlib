package gomatrixserverlib

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"gopkg.in/h2non/gock.v1"
)

const (
	ipLiteral                   = "42.42.42.42"
	ipLiteralDefaultPort        = "42.42.42.42:8448"
	ipLiteralAndPort            = "42.42.42.42:443"
	hostname                    = "example.com"
	hostnameDefaultPort         = "example.com:8448"
	hostnameAndPort             = "example.com:4242"
	delegatedAddress            = "matrix.example.com"
	delegatedAddressDefaultPort = "matrix.example.com:8448"
	delegatedAddressWithPort    = "matrix.example.com:4242"
	srvHostname                 = "matrix.otherexample.com"
	srvHostnameDefaultPort      = "matrix.otherexample.com:8448"
	srvHostnameWithPort         = "matrix.otherexample.com:4242"
	srvPort                     = 4242

	dnsPort = 5555
)

// assertCritical checks whether the second parameter it gets has the same type
// and value as the third one, and aborts the current test if that's not the
// case.
func assertCritical(t *testing.T, val, expected interface{}) {
	if !reflect.DeepEqual(val, expected) {
		fmt.Printf("expected %v to equal %v\n", val, expected)
		t.FailNow()
	}
}

// testResolve performs a server name resolution for a given server name and
// checks if the result matches with the given destination, Host header value
// and expected certificate name.
// If one of them doesn't match, or the resolution function returned with an
// error, it aborts the current test.
func testResolve(t *testing.T, serverName ServerName, destination, host, certName string) {
	res, err := ResolveServer(serverName)
	assertCritical(t, err, nil)
	assertCritical(t, len(res), 1)
	assertCritical(t, res[0].Destination, destination)
	assertCritical(t, res[0].Host, ServerName(host))
	assertCritical(t, res[0].Name, certName)
}

func TestIPLiteral(t *testing.T) {
	testResolve(
		t,
		ServerName(ipLiteral), // The server name is an IP literal without a port
		ipLiteralDefaultPort,  // Destination must be the IP address + 8448
		ipLiteral,             // Host must be the IP address
		ipLiteral,             // Certificate (Name) must be for the IP address
	)
}

func TestIPLiteralWithPort(t *testing.T) {
	testResolve(
		t,
		ServerName(ipLiteralAndPort), // The server name is an IP literal with a port
		ipLiteralAndPort,             // Destination must be the IP address + port
		ipLiteralAndPort,             // Host must be the IP address + port
		ipLiteral,                    // Certificate (Name) must be for the IP address
	)
}

func TestHostnameAndPort(t *testing.T) {
	testResolve(
		t,
		ServerName(hostnameAndPort), // The server name is not an IP literal and includes an explicit port
		hostnameAndPort,             // Destination must be the hostname + port
		hostnameAndPort,             // Host must be the hostname + port
		hostname,                    // Certificate (Name) must be for the hostname
	)
}

func TestHostnameWellKnownWithIPLiteral(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(200).
		JSON(WellKnownResult{NewAddress: ipLiteral})

	testResolve(
		t,
		ServerName(hostname), // The server name is a domain hosting a .well-known file which specifies an IP literal without a port
		ipLiteralDefaultPort, // Destination must be the IP literal + 8448
		ipLiteral,            // Host must be the IP literal
		ipLiteral,            // Certificate (Name) must be for the IP literal
	)
}

func TestHostnameWellKnownWithIPLiteralAndPort(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(200).
		JSON(WellKnownResult{NewAddress: ipLiteralAndPort})

	testResolve(
		t,
		ServerName(hostname), // The server name is a domain hosting a .well-known file which specifies an IP literal with a port
		ipLiteralAndPort,     // Destination must be the IP literal + port
		ipLiteralAndPort,     // Host must be the IP literal + port
		ipLiteral,            // Certificate (Name) must be for the IP literal
	)
}

func TestHostnameWellKnownWithHostnameAndPort(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(200).
		JSON(WellKnownResult{NewAddress: delegatedAddressWithPort})

	testResolve(
		t,
		ServerName(hostname),     // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal and has a port
		delegatedAddressWithPort, // Destination must be the hostname + port
		delegatedAddressWithPort, // Host must be the hostname + port
		delegatedAddress,         // Certificate (Name) must be for the hostname
	)
}

func TestHostnameWellKnownWithHostnameSRVNoPort(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(200).
		JSON(WellKnownResult{NewAddress: delegatedAddress})

	defer clearFakeDNS(setupFakeDNS(0, true))

	testResolve(
		t,
		ServerName(hostname),   // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal, has no port and for which a SRV record with port 0 exists
		srvHostnameDefaultPort, // Destination must be the hostname from the SRV record + 8448
		delegatedAddress,       // Host must be the delegated hostname
		delegatedAddress,       // Certificate (Name) must be for the delegated hostname
	)
}

func TestHostnameWellKnownWithHostnameSRVWithPort(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(200).
		JSON(WellKnownResult{NewAddress: delegatedAddress})

	defer clearFakeDNS(setupFakeDNS(srvPort, true))

	testResolve(
		t,
		ServerName(hostname), // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal, has no port and for which a SRV record with a non-0 exists
		srvHostnameWithPort,  // Destination must be the hostname + port from the SRV record
		delegatedAddress,     // Host must be the delegated hostname
		delegatedAddress,     // Certificate (Name) must be for the delegated hostname
	)
}

func TestHostnameWellKnownWithHostnameNoSRV(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(200).
		JSON(WellKnownResult{NewAddress: delegatedAddress})

	defer clearFakeDNS(setupFakeDNS(0, false))

	testResolve(
		t,
		ServerName(hostname),        // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal, has no port and for which no SRV record exists
		delegatedAddressDefaultPort, // Destination must be the hostname + port from the SRV record
		delegatedAddress,            // Host must be the delegated hostname
		delegatedAddress,            // Certificate (Name) must be for the delegated hostname
	)
}

func TestHostnameWithSRVNoPort(t *testing.T) {
	defer clearFakeDNS(setupFakeDNS(0, true))

	testResolve(
		t,
		ServerName(hostname),   // The server name is a domain for which a SRV record exists with port 0
		srvHostnameDefaultPort, // Destination must be the hostname + 8448
		hostname,               // Host must be the server name
		hostname,               // Certificate (Name) must be for the server name
	)
}

func TestHostnameWithSRVWithPort(t *testing.T) {
	defer clearFakeDNS(setupFakeDNS(srvPort, true))

	testResolve(
		t,
		ServerName(hostname), // The server name is a domain for which a SRV record exists with a non-0 port
		srvHostnameWithPort,  // Destination must be the hostname + port
		hostname,             // Host must be the server name
		hostname,             // Certificate (Name) must be for the server name
	)
}

func TestHostnameWithNoWellKnownNorSRV(t *testing.T) {
	defer gock.Off()

	gock.New("https://" + hostname).
		Get("/.well-known/matrix/server").
		Reply(404)

	defer clearFakeDNS(setupFakeDNS(0, false))

	testResolve(
		t,
		ServerName(hostname), // The server name is a domain for no .well-known file nor SRV record exist
		hostnameDefaultPort,  // Destination must be the hostname + 8448
		hostname,             // Host must be the server name
		hostname,             // Certificate (Name) must be for the server name
	)
}

// setupFakeDNS starts a DNS server that mocks answers from a live DNS server
// for Matrix SRV lookups, and re-assigns the default DNS resolver so it only
// uses the local server. This is done to limit network calls over network we
// don't control in order to make tests more reliable and time-proof.
// It expects to be provided with a port to return in answers, and a boolean
// which, if set to false, will cause the server to respond to any query with no
// answer.
// Returns with the server so it can be shutdown later, and the default resolver
// as it was at the beginning so it can be reset.
func setupFakeDNS(delegatedPort int, answerSRV bool) (*dns.Server, *net.Resolver) {
	defaultResolver := net.DefaultResolver

	// Start a DNS server with our custom handler.
	srv := &dns.Server{Addr: fmt.Sprintf("127.0.0.1:%d", dnsPort), Net: "udp"}
	srv.Handler = &dnsHandler{delegatedPort: uint16(delegatedPort), answerSRV: answerSRV}
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	// Redefine the default resolver so it uses our local server.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Redirect every DNS query to our local server.
			return net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
		},
	}

	return srv, defaultResolver
}

// clearFakeDNS shutdowns the DNS server, and reset the default resolver with
// the value it had before being tempered with.
func clearFakeDNS(srv *dns.Server, resolver *net.Resolver) {
	srv.Shutdown()
	net.DefaultResolver = resolver
}

// dnsHandler is the handler used to answer DNS queries.
type dnsHandler struct {
	delegatedPort uint16
	answerSRV     bool
}

// ServeDNS answers DNS queries.
func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeSRV:
		if h.answerSRV {
			msg.Authoritative = true
			domain := msg.Question[0].Name
			msg.Answer = append(msg.Answer, &dns.SRV{
				Hdr:      dns.RR_Header{Name: domain, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Priority: 10,
				Weight:   0,
				Port:     h.delegatedPort,
				Target:   srvHostname + ".", // Domain name needs to be fully qualified.
			})
		}
	}

	err := w.WriteMsg(&msg)
	if err != nil {
		panic(err)
	}
}
