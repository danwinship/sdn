package ranges

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

func mustParseCIDR(cidrString string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(cidrString)
	if err != nil {
		panic(err.Error())
	}
	return cidr
}

func Test_rangeForCIDR(t *testing.T) {
	var cidr *net.IPNet
	var r intRange
	var expectStart, expectEnd uint64

	cidr = mustParseCIDR("10.0.0.0/8")
	r = rangeForCIDR(cidr)
	expectStart = 10 * 256 * 256 * 256
	expectEnd = 11*256*256*256 - 1
	if r.start.low != expectStart {
		t.Fatalf("bad start %d != %d", r.start.low, expectStart)
	}
	if r.end.low != expectEnd {
		t.Fatalf("bad end %d != %d", r.end.low, expectEnd)
	}

	cidr = mustParseCIDR("192.168.0.0/24")
	r = rangeForCIDR(cidr)
	expectStart = 192*256*256*256 + 168*256*256
	expectEnd = 192*256*256*256 + 168*256*256 + 255
	if r.start.low != expectStart {
		t.Fatalf("bad start %d != %d", r.start.low, expectStart)
	}
	if r.end.low != expectEnd {
		t.Fatalf("bad end %d != %d", r.end.low, expectEnd)
	}
}

func parseRange(start, end string) intRange {
	r := intRange{
		start: newFixedIntFromIP(net.ParseIP(start)),
		end:   newFixedIntFromIP(net.ParseIP(end)),
	}
	return r
}

func Test_rangesForIPBlock(t *testing.T) {
	for i, tc := range []struct {
		ipBlock networkingv1.IPBlock
		result  []intRange
	}{
		{
			ipBlock: networkingv1.IPBlock{
				CIDR:   "10.0.0.0/8",
				Except: []string{"10.0.1.0/24"},
			},
			result: []intRange{
				parseRange("10.0.0.0", "10.0.0.255"),
				parseRange("10.0.2.0", "10.255.255.255"),
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.0.0/16",
				Except: []string{
					"192.168.2.0/24",
					"192.168.3.6/32",
				},
			},
			result: []intRange{
				parseRange("192.168.0.0", "192.168.1.255"),
				parseRange("192.168.3.0", "192.168.3.5"),
				parseRange("192.168.3.7", "192.168.255.255"),
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.1.0/24",
				Except: []string{
					"192.168.1.0/32",
					"192.168.1.9/32",
					"192.168.1.255/32",
				},
			},
			result: []intRange{
				parseRange("192.168.1.1", "192.168.1.8"),
				parseRange("192.168.1.10", "192.168.1.254"),
			},
		},
		{
			// Make sure we're doing the math right in both 64-bit blocks
			ipBlock: networkingv1.IPBlock{
				CIDR: "fd01::/48",
				Except: []string{
					"fd01:0000:0000:1234::/64",
					"fd01:0000:0000:5600::/56",
					"fd01::7800/120",
				},
			},
			result: []intRange{
				parseRange("fd01::", "fd01::77ff"),
				parseRange("fd01::7900", "fd01:0000:0000:1233:ffff:ffff:ffff:ffff"),
				parseRange("fd01:0000:0000:1235::", "fd01:0000:0000:55ff:ffff:ffff:ffff:ffff"),
				parseRange("fd01:0000:0000:5700::", "fd01:0000:0000:ffff:ffff:ffff:ffff:ffff"),
			},
		},
	} {
		ranges := rangesForIPBlock(&tc.ipBlock)

		if !reflect.DeepEqual(tc.result, ranges) {
			t.Fatalf("bad result for %d\nexpected %v\ngot      %v", i, tc.result, ranges)
		}
	}
}

func TestIPBlockToCIDRs(t *testing.T) {
	for i, tc := range []struct {
		ipBlock networkingv1.IPBlock
		result  []string
	}{
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "10.0.0.0/8",
				Except: []string{
					"10.0.1.0/24",
				},
			},
			result: []string{
				"10.0.0.0/24",   // 10.0.0.0 - 10.0.0.255
				"10.0.2.0/23",   // 10.0.2.0 - 10.0.3.255
				"10.0.4.0/22",   // 10.0.4.0 - 10.0.7.255
				"10.0.8.0/21",   // 10.0.8.0 - 10.0.15.255
				"10.0.16.0/20",  // 10.0.16.0 - 10.0.31.255
				"10.0.32.0/19",  // 10.0.32.0 - 10.0.63.255
				"10.0.64.0/18",  // 10.0.64.0 - 10.0.127.255
				"10.0.128.0/17", // 10.0.128.0 - 10.0.255.255
				"10.1.0.0/16",   // 10.1.0.0 - 10.1.255.255
				"10.2.0.0/15",   // 10.2.0.0 - 10.3.255.255
				"10.4.0.0/14",   // 10.4.0.0 - 10.7.255.255
				"10.8.0.0/13",   // 10.8.0.0 - 10.15.255.255
				"10.16.0.0/12",  // 10.16.0.0 - 10.31.255.255
				"10.32.0.0/11",  // 10.32.0.0 - 10.63.255.255
				"10.64.0.0/10",  // 10.64.0.0 - 10.127.255.255
				"10.128.0.0/9",  // 10.128.0.0 - 10.255.255.255
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.0.0/16",
				Except: []string{
					"192.168.2.0/24",
					"192.168.3.6/32",
				},
			},
			result: []string{
				"192.168.0.0/23",   // 192.168.0.0 - 192.168.1.255
				"192.168.3.0/30",   // 192.168.3.0 - 192.168.3.3
				"192.168.3.4/31",   // 192.168.3.4 - 192.168.3.5
				"192.168.3.7/32",   // 192.168.3.7 - 192.168.3.7
				"192.168.3.8/29",   // 192.168.3.8 - 192.168.3.15
				"192.168.3.16/28",  // 192.168.3.16 - 192.168.3.31
				"192.168.3.32/27",  // 192.168.3.32 - 192.168.3.63
				"192.168.3.64/26",  // 192.168.3.64 - 192.168.3.127
				"192.168.3.128/25", // 192.168.3.128 - 192.168.3.255
				"192.168.4.0/22",   // 192.168.4.0 - 192.168.7.255
				"192.168.8.0/21",   // 192.168.8.0 - 192.168.15.255
				"192.168.16.0/20",  // 192.168.16.0 - 192.168.31.255
				"192.168.32.0/19",  // 192.168.32.0 - 192.168.63.255
				"192.168.64.0/18",  // 192.168.64.0 - 192.168.127.255
				"192.168.128.0/17", // 192.168.128.0 - 192.168.255.255
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "192.168.1.0/24",
				Except: []string{
					"192.168.1.0/32",
					"192.168.1.9/32",
					"192.168.1.255/32",
				},
			},
			result: []string{
				"192.168.1.1/32",   // 192.168.1.1 - 192.168.1.1
				"192.168.1.2/31",   // 192.168.1.2 - 192.168.1.3
				"192.168.1.4/30",   // 192.168.1.4 - 192.168.1.7
				"192.168.1.8/32",   // 192.168.1.8 - 192.168.1.8
				"192.168.1.10/31",  // 192.168.1.10 - 192.168.1.11
				"192.168.1.12/30",  // 192.168.1.12 - 192.168.1.15
				"192.168.1.16/28",  // 192.168.1.16 - 192.168.1.31
				"192.168.1.32/27",  // 192.168.1.32 - 192.168.1.63
				"192.168.1.64/26",  // 192.168.1.64 - 192.168.1.127
				"192.168.1.128/26", // 192.168.1.128 - 192.168.1.191
				"192.168.1.192/27", // 192.168.1.192 - 192.168.1.223
				"192.168.1.224/28", // 192.168.1.224 - 192.168.1.239
				"192.168.1.240/29", // 192.168.1.240 - 192.168.1.247
				"192.168.1.248/30", // 192.168.1.248 - 192.168.1.251
				"192.168.1.252/31", // 192.168.1.252 - 192.168.1.253
				"192.168.1.254/32", // 192.168.1.254 - 192.168.1.254
			},
		},
		{
			ipBlock: networkingv1.IPBlock{
				CIDR: "fd01::/48",
				Except: []string{
					"fd01:0:0:1234::/64",
				},
			},
			result: []string{
				"fd01::/52",          // fd01::          - fd01::0fff:ffff:ffff:ffff:ffff
				"fd01:0:0:1000::/55", // fd01:0:0:1000:: - fd01::11ff:ffff:ffff:ffff:ffff
				"fd01:0:0:1200::/59", // fd01:0:0:1200:: - fd01::121f:ffff:ffff:ffff:ffff
				"fd01:0:0:1220::/60", // fd01:0:0:1220:: - fd01::122f:ffff:ffff:ffff:ffff
				"fd01:0:0:1230::/62", // fd01:0:0:1230:: - fd01::1233:ffff:ffff:ffff:ffff
				"fd01:0:0:1235::/64", // fd01:0:0:1235:: - fd01::1235:ffff:ffff:ffff:ffff
				"fd01:0:0:1236::/63", // fd01:0:0:1236:: - fd01::1237:ffff:ffff:ffff:ffff
				"fd01:0:0:1238::/61", // fd01:0:0:1238:: - fd01::123f:ffff:ffff:ffff:ffff
				"fd01:0:0:1240::/58", // fd01:0:0:1240:: - fd01::127f:ffff:ffff:ffff:ffff
				"fd01:0:0:1280::/57", // fd01:0:0:1280:: - fd01::12ff:ffff:ffff:ffff:ffff
				"fd01:0:0:1300::/56", // fd01:0:0:1300:: - fd01::13ff:ffff:ffff:ffff:ffff
				"fd01:0:0:1400::/54", // fd01:0:0:1400:: - fd01::17ff:ffff:ffff:ffff:ffff
				"fd01:0:0:1800::/53", // fd01:0:0:1800:: - fd01::1fff:ffff:ffff:ffff:ffff
				"fd01:0:0:2000::/51", // fd01:0:0:2000:: - fd01::3fff:ffff:ffff:ffff:ffff
				"fd01:0:0:4000::/50", // fd01:0:0:4000:: - fd01::7fff:ffff:ffff:ffff:ffff
				"fd01:0:0:8000::/49", // fd01:0:0:8000:: - fd01::ffff:ffff:ffff:ffff:ffff
			},
		},
	} {
		cidrs := IPBlockToCIDRs(&tc.ipBlock)

		if !reflect.DeepEqual(tc.result, cidrs) {
			fmt.Printf("\t\t\tresult: []string{\n")
			for _, cidr := range cidrs {
				r := rangeForCIDR(mustParseCIDR(cidr))
				fmt.Printf("\t\t\t\t\"%s\", // %s - %s\n",
					cidr,
					net.IP(r.start.toBytes()),
					net.IP(r.end.toBytes()),
				)
			}
			fmt.Printf("\t\t\t}\n")
			t.Fatalf("bad result for %d", i)
		}
	}
}

func TestPortRangeToPortMasks(t *testing.T) {
	for i, tc := range []struct {
		start  uint16
		end    uint16
		result []string
	}{
		{
			start: 0,
			end:   0,
			result: []string{
				"0x0000/0xffff",
			},
		},
		{
			start: 0,
			end:   65535,
			result: []string{
				"0x0000/0x0000",
			},
		},
		{
			start: 0,
			end:   1023,
			result: []string{
				"0x0000/0xfc00",
			},
		},
		{
			start: 1024,
			end:   65535,
			result: []string{
				"0x0400/0xfc00",
				"0x0800/0xf800",
				"0x1000/0xf000",
				"0x2000/0xe000",
				"0x4000/0xc000",
				"0x8000/0x8000",
			},
		},
		{
			start: 6000,
			end:   6100,
			result: []string{
				"0x1770/0xfff0",
				"0x1780/0xffc0",
				"0x17c0/0xfff0",
				"0x17d0/0xfffc",
				"0x17d4/0xffff",
			},
		},
	} {
		masks := PortRangeToPortMasks(int(tc.start), int(tc.end))
		if !reflect.DeepEqual(masks, tc.result) {
			fmt.Printf("\t\t\tresult: []string{\n")
			for _, mask := range masks {
				fmt.Printf("\t\t\t\t%q,\n", mask)
			}
			fmt.Printf("\t\t\t},\n")
			t.Fatalf("bad result for %d\nexpected %v\ngot      %v", i, tc.result, masks)
		}
	}
}
