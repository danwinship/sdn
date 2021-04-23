package common

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFixupNameservers(t *testing.T) {
	type fixupTest struct {
		testCase    string
		nameservers []string
		defaultPort string
		ipFamilies  IPSupport
		output      []string
	}

	tests := []fixupTest{
		{
			testCase:    "Single-stack IPv4, mixed resolvers",
			nameservers: []string{"1.2.3.4", "5.6.7.8:5353", "fd00::1234", "[fd00::5678]:5353"},
			defaultPort: "53",
			ipFamilies:  IPv4Support,
			output:      []string{"1.2.3.4:53", "5.6.7.8:5353"},
		},
		{
			testCase:    "Single-stack IPv6, mixed resolvers",
			nameservers: []string{"1.2.3.4", "5.6.7.8:5353", "fd00::1234", "[fd00::5678]:5353"},
			defaultPort: "53",
			ipFamilies:  IPv6Support,
			output:      []string{"[fd00::1234]:53", "[fd00::5678]:5353"},
		},
		{
			testCase:    "Single-stack IPv6, IPv4-only resolvers",
			nameservers: []string{"1.2.3.4", "5.6.7.8:5353"},
			defaultPort: "53",
			ipFamilies:  IPv6Support,
			output:      []string{"1.2.3.4:53", "5.6.7.8:5353"},
		},
		{
			testCase:    "Dual stack, mixed resolvers",
			nameservers: []string{"1.2.3.4", "5.6.7.8:5353", "fd00::1234", "[fd00::5678]:5353"},
			defaultPort: "53",
			ipFamilies:  DualStackSupport,
			output:      []string{"1.2.3.4:53", "5.6.7.8:5353", "[fd00::1234]:53", "[fd00::5678]:5353"},
		},
	}

	for _, test := range tests {
		output := fixupNameservers(test.nameservers, test.defaultPort, test.ipFamilies)
		if !reflect.DeepEqual(output, test.output) {
			t.Fatalf("Bad results for %q: expected %v, got %v", test.testCase, test.output, output)
		}
	}
}

func TestAddDNS(t *testing.T) {
	s, addr, err := runLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	configFileName, err := createResolveConfFile(addr)
	if err != nil {
		t.Fatalf("unable to create test resolver: %v", err)
	}
	defer os.Remove(configFileName)

	type dnsTest struct {
		testCase          string
		domainName        string
		dnsResolverOutput string
		ips               []net.IP
		ttl               time.Duration
		expectFailure     bool
	}

	ip := net.ParseIP("10.11.12.13")
	tests := []dnsTest{
		{
			testCase:          "Test valid domain name with resolver returning only A record",
			domainName:        "example.com",
			dnsResolverOutput: "example.com. 600 IN A 10.11.12.13",
			ips:               []net.IP{ip},
			ttl:               600 * time.Second,
			expectFailure:     false,
		},
		{
			testCase:          "Test valid domain name with resolver returning both CNAME and A records",
			domainName:        "example.com",
			dnsResolverOutput: "example.com. 200 IN CNAME foo.example.com.\nfoo.example.com. 600 IN A 10.11.12.13",
			ips:               []net.IP{ip},
			ttl:               200 * time.Second,
			expectFailure:     false,
		},
		{
			testCase:          "Test valid domain name with no response",
			domainName:        "example.com",
			dnsResolverOutput: "",
			expectFailure:     true,
		},
		{
			testCase:          "Test invalid domain name",
			domainName:        "sads@#$.com",
			dnsResolverOutput: "",
			expectFailure:     true,
		},
		{
			testCase:          "Test min TTL",
			domainName:        "example.com",
			dnsResolverOutput: "example.com. 0 IN A 10.11.12.13",
			ips:               []net.IP{ip},
			ttl:               30 * time.Second,
			expectFailure:     false,
		},
	}

	for _, test := range tests {
		serverFn := dummyServer(test.dnsResolverOutput)
		dns.HandleFunc(test.domainName, serverFn)
		defer dns.HandleRemove(test.domainName)

		n, err := NewDNS(configFileName, IPv4Support)
		if err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}
		// Override timeout so the "no response" test doesn't take too long
		n.timeout = 100 * time.Millisecond

		err = n.Add(test.domainName)
		if test.expectFailure && err == nil {
			t.Fatalf("Test case: %s failed, expected failure but got success", test.testCase)
		} else if !test.expectFailure && err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}

		if test.expectFailure {
			if _, ok := n.dnsMap[test.domainName]; ok {
				t.Fatalf("Test case: %s failed, unexpected domain %q found in dns map", test.testCase, test.domainName)
			}
		} else {
			d, ok := n.dnsMap[test.domainName]
			if !ok {
				t.Fatalf("Test case: %s failed, domain %q not found in dns map", test.testCase, test.domainName)
			}
			if !ipsEqual(d.ips, test.ips) {
				t.Fatalf("Test case: %s failed, expected IPs: %v, got: %v for the domain %q", test.testCase, test.ips, d.ips, test.domainName)
			}
			normalizedTTL := normalizeTTL(test.ttl)
			if d.ttl != normalizedTTL {
				t.Fatalf("Test case: %s failed, expected TTL: %s, got: %s for the domain %q", test.testCase, normalizedTTL, d.ttl, test.domainName)
			}
			if d.nextQueryTime.IsZero() {
				t.Fatalf("Test case: %s failed, nextQueryTime for the domain %q is not set", test.testCase, test.domainName)
			}
		}
	}
}

func TestAddDNSIPv6(t *testing.T) {
	s, addr, err := runLocalUDPServer("[::]:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	configFileName, err := createResolveConfFile(addr)
	if err != nil {
		t.Fatalf("unable to create test resolver: %v", err)
	}
	defer os.Remove(configFileName)

	type dnsTest struct {
		testCase          string
		domainName        string
		dnsResolverOutput string
		ips               []net.IP
		ttl               time.Duration
		expectFailure     bool
	}

	ip := net.ParseIP("2600:5200::7800:1")
	tests := []dnsTest{
		{
			testCase:          "Test valid domain name with resolver returning only AAAA record",
			domainName:        "example.com",
			dnsResolverOutput: "example.com. 600 IN AAAA 2600:5200::7800:1",
			ips:               []net.IP{ip},
			ttl:               600 * time.Second,
			expectFailure:     false,
		},
		{
			testCase:          "Test valid domain name with resolver returning both CNAME and AAAA records",
			domainName:        "example.com",
			dnsResolverOutput: "example.com. 200 IN CNAME foo.example.com.\nfoo.example.com. 600 IN AAAA 2600:5200::7800:1",
			ips:               []net.IP{ip},
			ttl:               200 * time.Second,
			expectFailure:     false,
		},
		{
			testCase:          "Test valid domain name with resolver returning only A record",
			domainName:        "example.com",
			dnsResolverOutput: "example.com. 600 IN A 10.11.12.13",
			expectFailure:     true,
		},
	}

	for _, test := range tests {
		serverFn := dummyServer(test.dnsResolverOutput)
		dns.HandleFunc(test.domainName, serverFn)
		defer dns.HandleRemove(test.domainName)

		n, err := NewDNS(configFileName, IPv6Support)
		if err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}
		// Override timeout so the "no response" test doesn't take too long
		n.timeout = 100 * time.Millisecond

		err = n.Add(test.domainName)
		if test.expectFailure && err == nil {
			t.Fatalf("Test case: %s failed, expected failure but got success", test.testCase)
		} else if !test.expectFailure && err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}

		if test.expectFailure {
			if _, ok := n.dnsMap[test.domainName]; ok {
				t.Fatalf("Test case: %s failed, unexpected domain %q found in dns map", test.testCase, test.domainName)
			}
		} else {
			d, ok := n.dnsMap[test.domainName]
			if !ok {
				t.Fatalf("Test case: %s failed, domain %q not found in dns map", test.testCase, test.domainName)
			}
			if !ipsEqual(d.ips, test.ips) {
				t.Fatalf("Test case: %s failed, expected IPs: %v, got: %v for the domain %q", test.testCase, test.ips, d.ips, test.domainName)
			}
			normalizedTTL := normalizeTTL(test.ttl)
			if d.ttl != normalizedTTL {
				t.Fatalf("Test case: %s failed, expected TTL: %s, got: %s for the domain %q", test.testCase, normalizedTTL, d.ttl, test.domainName)
			}
			if d.nextQueryTime.IsZero() {
				t.Fatalf("Test case: %s failed, nextQueryTime for the domain %q is not set", test.testCase, test.domainName)
			}
		}
	}
}

func TestAddDNSDualStack(t *testing.T) {
	s, addr, err := runLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	configFileName, err := createResolveConfFile(addr)
	if err != nil {
		t.Fatalf("unable to create test resolver: %v", err)
	}
	defer os.Remove(configFileName)

	type dnsTest struct {
		testCase      string
		domainName    string
		dnsV4Output   string
		dnsV6Output   string
		ips           []net.IP
		ttl           time.Duration
		expectFailure bool
	}

	ip4 := net.ParseIP("10.11.12.13")
	ip6 := net.ParseIP("2600:5200::7800:1")

	// Returning an SOA to mean "no answer" is what real DNS servers to (and makes the test
	// complete immediately rather than needing to time out).
	tests := []dnsTest{
		{
			testCase:      "Test valid domain name with resolver returning only A record",
			domainName:    "example.com",
			dnsV4Output:   "example.com. 600 IN A 10.11.12.13",
			dnsV6Output:   "example.com. 3600 IN SOA ns.example.com. root.example.com. 12345 600 600 600 600",
			ips:           []net.IP{ip4},
			ttl:           600 * time.Second,
			expectFailure: false,
		},
		{
			testCase:      "Test valid domain name with resolver returning only AAAA record",
			domainName:    "example.com",
			dnsV4Output:   "example.com. 3600 IN SOA ns.example.com. root.example.com. 12345 600 600 600 600",
			dnsV6Output:   "example.com. 600 IN AAAA 2600:5200::7800:1",
			ips:           []net.IP{ip6},
			ttl:           600 * time.Second,
			expectFailure: false,
		},
		{
			testCase:      "Test valid domain name with resolver returning both A and AAAA records",
			domainName:    "example.com",
			dnsV4Output:   "example.com. 200 IN A 10.11.12.13",
			dnsV6Output:   "example.com. 600 IN AAAA 2600:5200::7800:1",
			ips:           []net.IP{ip4, ip6},
			ttl:           200 * time.Second,
			expectFailure: false,
		},
		{
			testCase:      "Test valid domain name with resolver returning both A and AAAA records, AAA has lower TTL",
			domainName:    "example.com",
			dnsV4Output:   "example.com. 600 IN A 10.11.12.13",
			dnsV6Output:   "example.com. 200 IN AAAA 2600:5200::7800:1",
			ips:           []net.IP{ip4, ip6},
			ttl:           200 * time.Second,
			expectFailure: false,
		},
		{
			testCase:      "Test valid domain name with resolver returning A record and failing on AAAA request",
			domainName:    "example.com",
			dnsV4Output:   "example.com. 200 IN A 10.11.12.13",
			dnsV6Output:   "",
			ips:           []net.IP{ip4},
			ttl:           200 * time.Second,
			expectFailure: false,
		},
		{
			testCase:      "Test no match",
			domainName:    "example.com",
			dnsV4Output:   "example.com. 3600 IN SOA ns.example.com. root.example.com. 12345 600 600 600 600",
			dnsV6Output:   "example.com. 3600 IN SOA ns.example.com. root.example.com. 12345 600 600 600 600",
			expectFailure: true,
		},
	}

	for _, test := range tests {
		serverFn := dummyDualStackServer(test.dnsV4Output, test.dnsV6Output)
		dns.HandleFunc(test.domainName, serverFn)
		defer dns.HandleRemove(test.domainName)

		n, err := NewDNS(configFileName, DualStackSupport)
		if err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}
		// Override timeout so the "no response" test doesn't take too long
		n.timeout = 100 * time.Millisecond

		err = n.Add(test.domainName)
		if test.expectFailure && err == nil {
			t.Fatalf("Test case: %s failed, expected failure but got success", test.testCase)
		} else if !test.expectFailure && err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}

		if test.expectFailure {
			if _, ok := n.dnsMap[test.domainName]; ok {
				t.Fatalf("Test case: %s failed, unexpected domain %q found in dns map", test.testCase, test.domainName)
			}
		} else {
			d, ok := n.dnsMap[test.domainName]
			if !ok {
				t.Fatalf("Test case: %s failed, domain %q not found in dns map", test.testCase, test.domainName)
			}
			if !ipsEqual(d.ips, test.ips) {
				t.Fatalf("Test case: %s failed, expected IPs: %v, got: %v for the domain %q", test.testCase, test.ips, d.ips, test.domainName)
			}
			normalizedTTL := normalizeTTL(test.ttl)
			if d.ttl != normalizedTTL {
				t.Fatalf("Test case: %s failed, expected TTL: %s, got: %s for the domain %q", test.testCase, normalizedTTL, d.ttl, test.domainName)
			}
			if d.nextQueryTime.IsZero() {
				t.Fatalf("Test case: %s failed, nextQueryTime for the domain %q is not set", test.testCase, test.domainName)
			}
		}
	}
}

func TestUpdateDNS(t *testing.T) {
	s, addr, err := runLocalUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	configFileName, err := createResolveConfFile(addr)
	if err != nil {
		t.Fatalf("unable to create test resolver: %v", err)
	}
	defer os.Remove(configFileName)

	type dnsTest struct {
		testCase   string
		domainName string

		addResolverOutput string
		addIPs            []net.IP
		addTTL            time.Duration

		updateResolverOutput string
		updateIPs            []net.IP
		updateTTL            time.Duration

		expectFailure bool
	}

	addIP := net.ParseIP("10.11.12.13")
	updateIP := net.ParseIP("10.11.12.14")
	tests := []dnsTest{
		{
			testCase:             "Test dns update of valid domain",
			domainName:           "example.com",
			addResolverOutput:    "example.com. 600 IN A 10.11.12.13",
			addIPs:               []net.IP{addIP},
			addTTL:               600 * time.Second,
			updateResolverOutput: "example.com. 500 IN A 10.11.12.14",
			updateIPs:            []net.IP{updateIP},
			updateTTL:            500 * time.Second,
			expectFailure:        false,
		},
		{
			testCase:             "Test dns update of invalid domain",
			domainName:           "sads@#$.com",
			addResolverOutput:    "",
			updateResolverOutput: "",
			expectFailure:        true,
		},
		{
			testCase:             "Test dns update min TTL",
			domainName:           "example.com",
			addResolverOutput:    "example.com. 5 IN A 10.11.12.13",
			addIPs:               []net.IP{addIP},
			addTTL:               5 * time.Second,
			updateResolverOutput: "example.com. 0 IN A 10.11.12.14",
			updateIPs:            []net.IP{updateIP},
			updateTTL:            30 * time.Second,
			expectFailure:        false,
		},
	}

	for _, test := range tests {
		serverFn := dummyServer(test.addResolverOutput)
		dns.HandleFunc(test.domainName, serverFn)
		defer dns.HandleRemove(test.domainName)

		n, err := NewDNS(configFileName, IPv4Support)
		if err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}

		n.Add(test.domainName)

		orig := n.Get(test.domainName)

		dns.HandleRemove(test.domainName)
		serverFn = dummyServer(test.updateResolverOutput)
		dns.HandleFunc(test.domainName, serverFn)
		defer dns.HandleRemove(test.domainName)

		_, err = n.Update(test.domainName)
		if test.expectFailure && err == nil {
			t.Fatalf("Test case: %s failed, expected failure but got success", test.testCase)
		} else if !test.expectFailure && err != nil {
			t.Fatalf("Test case: %s failed, err: %v", test.testCase, err)
		}

		updated := n.Get(test.domainName)
		sz := n.Size()

		if !test.expectFailure && sz != 1 {
			t.Fatalf("Test case: %s failed, expected dns map size: 1, got %d", test.testCase, sz)
		}
		if test.expectFailure && sz != 0 {
			t.Fatalf("Test case: %s failed, expected dns map size: 0, got %d", test.testCase, sz)
		}

		if !test.expectFailure {
			if !ipsEqual(orig.ips, test.addIPs) {
				t.Fatalf("Test case: %s failed, expected ips after add op: %v, got: %v", test.testCase, test.addIPs, orig.ips)
			}
			normalizedTTL := normalizeTTL(test.addTTL)
			if orig.ttl != normalizedTTL {
				t.Fatalf("Test case: %s failed, expected ttl after add op: %s, got: %s", test.testCase, normalizedTTL, orig.ttl)
			}
			if orig.nextQueryTime.IsZero() {
				t.Fatalf("Test case: %s failed, expected nextQueryTime to be set after add op", test.testCase)
			}

			if !ipsEqual(updated.ips, test.updateIPs) {
				t.Fatalf("Test case: %s failed, expected ips after update op: %v, got: %v", test.testCase, test.updateIPs, updated.ips)
			}
			normalizedTTL = normalizeTTL(test.updateTTL)
			if updated.ttl != normalizedTTL {
				t.Fatalf("Test case: %s failed, expected ttl after add op: %s, got: %s", test.testCase, normalizedTTL, orig.ttl)
			}
			if updated.nextQueryTime.IsZero() {
				t.Fatalf("Test case: %s failed, expected nextQueryTime to be set after update op", test.testCase)
			}

			if orig.nextQueryTime == updated.nextQueryTime {
				t.Fatalf("Test case: %s failed, expected nextQueryTime to change, original nextQueryTime: %v, updated nextQueryTime: %v", test.testCase, orig.nextQueryTime, updated.nextQueryTime)
			}
		}
	}
}
func TestNormalizeTTL(t *testing.T) {
	// The tests map stores the argument as the key and the expected output
	// as the value
	tests := make(map[int]int)
	tests[2] = 2
	tests[27] = 27
	tests[29] = 29
	tests[30] = 30
	tests[31] = 30
	tests[1799] = 30
	tests[1800] = 1800
	tests[1801] = 1800
	tests[3600] = 1800
	for k, v := range tests {
		originalTTL := time.Duration(k) * time.Second
		expectedTTL := time.Duration(v) * time.Second
		normalizedTTL := normalizeTTL(originalTTL)
		if normalizedTTL != expectedTTL {
			t.Fatalf("Test case: For TTL %s expected %s, got: %s", originalTTL, expectedTTL, normalizedTTL)
		}
	}

}

func dummyServer(output string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		answers := strings.Split(output, "\n")
		m.Answer = make([]dns.RR, len(answers))
		for i, ans := range answers {
			mx, _ := dns.NewRR(ans)
			m.Answer[i] = mx
		}
		w.WriteMsg(m)
	}
}

func dummyDualStackServer(v4output, v6output string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		var output string
		if req.Question[0].Qtype == dns.TypeA {
			output = v4output
		} else if req.Question[0].Qtype == dns.TypeAAAA {
			output = v6output
		}
		answers := strings.Split(output, "\n")
		m.Answer = make([]dns.RR, len(answers))
		for i, ans := range answers {
			mx, _ := dns.NewRR(ans)
			m.Answer[i] = mx
		}
		w.WriteMsg(m)
	}
}

func runLocalUDPServer(addr string) (*dns.Server, string, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, "", err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from.
	fin := make(chan error, 1)

	go func() {
		fin <- server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), nil
}

func createResolveConfFile(addr string) (string, error) {
	configFile, err := ioutil.TempFile("/tmp/", "resolv")
	if err != nil {
		return "", fmt.Errorf("cannot create DNS resolver config file: %v", err)
	}

	data := fmt.Sprintf(`
nameserver %s
#nameserver 192.168.10.11

options rotate timeout:1 attempts:1`, addr)

	if _, err := configFile.WriteString(data); err != nil {
		return "", fmt.Errorf("unable to write data to resolver config file: %v", err)
	}

	return configFile.Name(), nil
}
