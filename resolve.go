package matrixfederation

import (
	"net"
	"strconv"
	"strings"
)

// A HostResult is the result of looking up the IP addresses for a host.
type HostResult struct {
	CName string    // The canonical name for the host.
	Addrs []string  // The IP addresses for the host.
	Error *DNSError // If there was an error getting the IP addresses.
}

// A DNSResult is the result of looking up a matrix server in DNS.
type DNSResult struct {
	SRVCName   string                // The canonical name for the SRV record in DNS
	SRVRecords []*net.SRV            // List of SRV record for the matrix server.
	SRVError   *DNSError             // If there was an error getting the SRV records.
	Hosts      map[string]HostResult // The results of looking up the SRV record targets.
	Addrs      []string              // List of "<ip>:<port>" strings that the server is listening on.
}

// A DNSError describes an error that occured when trying to lookup a matrix server in DNS.
type DNSError struct {
	Error     string // The string decription of the error.
	Temporary bool   // Whether the error is temporary.
	Timeout   bool   // Whether the error was a timeout.
}

func dnsError(err error) (result *DNSError) {
	if err == nil {
		return
	}
	result = &DNSError{}
	result.Error = err.Error()
	if neterr, ok := err.(net.Error); ok {
		result.Temporary = neterr.Temporary()
		result.Timeout = neterr.Timeout()
	}
	return
}

// LookupServer looks up a matrix server in DNS.
func LookupServer(serverName string) (result DNSResult, err error) {
	hosts := map[string][]net.SRV{}
	result.Hosts = map[string]HostResult{}

	if strings.Index(serverName, ":") == -1 {
		result.SRVCName, result.SRVRecords, err = net.LookupSRV("matrix", "tcp", serverName)
		result.SRVError = dnsError(err)

		if err != nil {
			if dnserr, ok := err.(*net.DNSError); ok {
				if dnserr.Timeout() {
					return
				}
				hosts[serverName] = []net.SRV{net.SRV{
					Target: serverName,
					Port:   8448,
				}}
			}
		} else {
			for _, record := range result.SRVRecords {
				hosts[record.Target] = append(hosts[record.Target], *record)
			}
		}
	} else {
		var host, portStr string
		host, portStr, err = net.SplitHostPort(serverName)
		if err != nil {
			return
		}
		var port uint64
		port, err = strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return
		}
		hosts[host] = []net.SRV{net.SRV{
			Target: host,
			Port:   uint16(port),
		}}
	}
	for host, records := range hosts {
		cname, err := net.LookupCNAME(host)
		if err != nil {
			result.Hosts[host] = HostResult{
				Error: dnsError(err),
			}
			continue
		}
		addrs, err := net.LookupHost(cname)
		result.Hosts[host] = HostResult{
			CName: cname,
			Addrs: addrs,
			Error: dnsError(err),
		}
		for _, record := range records {
			for _, addr := range addrs {
				ipPort := net.JoinHostPort(addr, strconv.Itoa(int(record.Port)))
				result.Addrs = append(result.Addrs, ipPort)
			}
		}
	}

	return
}
