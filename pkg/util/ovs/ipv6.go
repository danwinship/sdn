package ovs

import (
	"regexp"
	"strings"
)

var fixupTunSrc = regexp.MustCompile(`tun_src=([[:xdigit:]]*:[[:xdigit:]:]*)`)
var fixupTunDst = regexp.MustCompile(`([[:xdigit:]]*:[[:xdigit:]:]*)->tun_dst`)

var ipv4Addresses = regexp.MustCompile(`nw_(src|dst)=([[:digit:]]*\.[[:digit:]]*\.)`)
var ipv6Addresses = regexp.MustCompile(`nw_(src|dst)=([[:xdigit:]]*:[[:xdigit:]:]*)`)
var ipv6Src = regexp.MustCompile(`nw_src=([[:xdigit:]]*:[[:xdigit:]:]*)`)
var ipv6Dst = regexp.MustCompile(`nw_dst=([[:xdigit:]]*:[[:xdigit:]:]*)`)
var arpSHA = regexp.MustCompile(`arp_sha=([[:xdigit:]]*:[[:xdigit:]:]*/[[:xdigit:]]*:[[:xdigit:]:]*)`)

var ipmatch = regexp.MustCompile(`, *ip,`)
var protomatch = regexp.MustCompile(`, *(tcp|udp|sctp),`)

func fixIPFlow(flow string, supportIPv4, supportIPv6 bool) []string {
	// First fix up tun_src/tun_dst, which are independent of anything else in the flow
	flow = fixupTunSrc.ReplaceAllString(flow, `tun_ipv6_src=$1`)
	flow = fixupTunDst.ReplaceAllString(flow, `$1->tun_ipv6_dst`)

	// There are four cases:
	//
	//   1. The flow is independent of IP, so we can return a single copy regardless
	//      of what families we support.
	//      eg, "in_port=1, actions=output:2"
	//
	//   2. The flow involves IP but does not refer to any specific addresses, so we
	//      need to return (a) an IPv4 version if we support IPv4, or (b) a translated
	//      IPv6 version if we support IPv6, or (c) both if we support both.
	//      eg, "ip, actions=goto_table:20"
	//      (aka "ipv6, actions=goto_table:20")
	//
	//   3. The flow includes IPv4 addresses, so we need to (a) return it unchanged if
	//      we support IPv4, or (b) return nil if we don't.
	//      eg, "ip, nw_src=10.128.0.0/14, actions=goto_table:10"
	//
	//   4. The flow includes IPv6 addresses, so we need to (a) return a translated
	//      IPv6 copy of it if we support IPv6, or (b) return nil if we don't.
	//      eg, "ip, nw_src=fd01::/48, actions=goto_table:10"
	//      (aka "ipv6, ipv6_src=fd01::/48, actions=goto_table:10")

	hasIPv4Addrs := ipv4Addresses.MatchString(flow)
	hasIPv6Addrs := ipv6Addresses.MatchString(flow)

	if hasIPv4Addrs {
		if supportIPv4 {
			// Case 3a
			return []string{flow}
		} else {
			// Case 3b
			return nil
		}
	}

	if !supportIPv6 {
		if hasIPv6Addrs {
			// Case 4b
			return nil
		} else {
			// Shortcut to Case 1 or 2a; we could go through translation, but
			// we'd end up with the same result anyway.
			return []string{flow}
		}
	}

	if strings.Contains(flow, "arp,") {
		// ARP-related flow

		// The IPv4 ARP flows are symmetric (a single rule correctly handles both
		// requests and responses) but the corresponding IPv6 Neighbor Discovery
		// flows aren't. So each "arp" flow becomes a pair of "icmp6" flows
		//
		// IPv6 Neighbor Solicitations (icmpv6_type=135) can be sent to either a
		// "solicited-node multicast address" (if the sender has no idea about the
		// IP/eth mapping), or to the actual expected destination IP (if the
		// sender is just verifying that the other endpoint is still there).
		// Either way, the Target Address will indicate the destination IP, so we
		// use that instead of ipv6_dst.
		//
		// Neighbor Advertisements (icmpv6_type=136) are the opposite; the
		// destination will be unicast, but the source may be multicast, so we
		// need to check nd_target rather than ipv6_src.

		v6NSFlow := flow
		v6NDFlow := flow

		v6NSFlow = strings.ReplaceAll(v6NSFlow, "arp,", "icmp6, icmpv6_type=135,")
		v6NSFlow = ipv6Src.ReplaceAllString(v6NSFlow, `ipv6_src=$1`)
		v6NSFlow = ipv6Dst.ReplaceAllString(v6NSFlow, `nd_target=$1`)
		v6NSFlow = arpSHA.ReplaceAllString(v6NSFlow, `eth_src=$1, nd_sll=$1`)

		v6NDFlow = strings.ReplaceAll(v6NDFlow, "arp,", "icmp6, icmpv6_type=136,")
		v6NDFlow = ipv6Src.ReplaceAllString(v6NDFlow, `nd_target=$1`)
		v6NDFlow = ipv6Dst.ReplaceAllString(v6NDFlow, `ipv6_dst=$1`)
		v6NDFlow = arpSHA.ReplaceAllString(v6NDFlow, `eth_src=$1, nd_tll=$1`)

		// The fact that this is ARP means it's not Case 1 ("independent of IP"),
		// and we already dealt with Cases 2a, 3, and 4b above.
		if !hasIPv6Addrs {
			if !supportIPv4 {
				// Case 2b
				return []string{v6NSFlow, v6NDFlow}
			} else {
				// Case 2c
				return []string{flow, v6NSFlow, v6NDFlow}
			}
		} else {
			// Case 4a
			return []string{v6NSFlow, v6NDFlow}
		}
	} else {
		// IP-based flow

		v6Flow := ipv6Addresses.ReplaceAllString(flow, `ipv6_$1=$2`)
		v6Flow = ipmatch.ReplaceAllString(v6Flow, `, ipv6,`)
		v6Flow = protomatch.ReplaceAllString(v6Flow, `, ${1}6,`)

		// We already dealt with Cases 2a, 3, and 4b above.

		if v6Flow == flow {
			// Case 1
			return []string{flow}
		} else if hasIPv6Addrs {
			// Case 4a
			return []string{v6Flow}
		} else if !supportIPv4 {
			// Case 2b
			return []string{v6Flow}
		} else {
			// Case 2c
			return []string{flow, v6Flow}
		}
	}
}
