package ovs

import (
	"regexp"
	"strings"
)

var ipv6Match1 = regexp.MustCompile(`(nw|tun)_(src|dst)=[[:xdigit:]]*:[[:xdigit:]]*:`)
var ipv6Match2 = regexp.MustCompile(`:[[:xdigit:]]*:[[:xdigit:]]*->tun_dst`)
var ipv4Match1 = regexp.MustCompile(`(nw|tun)_(src|dst)=[[:digit:]]*\.[[:digit:]]*\.`)
var ipv4Match2 = regexp.MustCompile(`\.[[:digit:]]*\.[[:digit:]]*->tun_dst`)

func fixIPFlow(flow string, ipv4Supported, ipv6Supported bool) []string {
	explicitIPv4 := ipv4Match1.MatchString(flow) || ipv4Match2.MatchString(flow) || strings.Contains(flow, ", arp,")
	explicitIPv6 := ipv6Match1.MatchString(flow) || ipv6Match2.MatchString(flow)

	if (explicitIPv4 && !ipv4Supported) || (explicitIPv6 && !ipv6Supported) {
		// ignore
		return nil
	}

	if !ipv6Supported || explicitIPv4 {
		// Input flow is already IPv4, so return it unchanged
		return []string{flow}
	}

	var flow4 string
	if ipv4Supported {
		flow4 = flow
	}
	flow6 := flow

	if explicitIPv6 {
		// IPv6-only input flow
		flow4 = ""

		// Rewrite the field names from IPv4 to IPv6
		flow6 = strings.ReplaceAll(flow6, "nw_src=", "ipv6_src=")
		flow6 = strings.ReplaceAll(flow6, "nw_dst=", "ipv6_dst=")
		flow6 = strings.ReplaceAll(flow6, "tun_src=", "tun_ipv6_src=")
		flow6 = strings.ReplaceAll(flow6, "->tun_dst", "->tun_ipv6_dst")
	}
	flow6 = strings.ReplaceAll(flow6, ", ip,", ", ipv6,")
	flow6 = strings.ReplaceAll(flow6, ", udp,", ", udp6,")
	flow6 = strings.ReplaceAll(flow6, ", tcp,", ", tcp6,")
	flow6 = strings.ReplaceAll(flow6, ", sctp,", ", sctp6,")

	if flow4 != "" && flow6 != "" && flow4 != flow6 {
		return []string{flow4, flow6}
	} else if flow6 != "" {
		return []string{flow6}
	} else {
		return []string{flow4}
	}
}
