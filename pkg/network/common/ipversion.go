package common

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/openshift/library-go/pkg/network/networkutils"
)

// IPVersion represents an IP version. The typedef exists primarily to avoid mixing them
// up with other ints (especially socket address family values), but as a bonus, they
// stringify to "IPv%d", so you can print them using "%s" in error messages.
type IPVersion int

const (
	IPv4 IPVersion = 4
	IPv6 IPVersion = 6
)

func (version IPVersion) String() string {
	return fmt.Sprintf("IPv%d", int(version))
}

// AddressFamily returns the address family (syscall.AF_INET or syscall.AF_INET6)
// corresponding to an IP version. Note that these values are also equal to
// netlink.FAMILY_V4 and netlink.FAMILY_V6.
func (version IPVersion) AddressFamily() int {
	if version == IPv6 {
		return syscall.AF_INET6
	} else {
		return syscall.AF_INET
	}
}

// ParseIP parses ipString and returns a net.IP and the IP version, or an error
func ParseIP(ipString string) (net.IP, IPVersion, error) {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP address")
	}
	return ip, GetIPVersion(ip), nil
}

// ParseIPv parses ipString, which must be of the indicated IP version
func ParseIPv(ipString string, version IPVersion) (net.IP, error) {
	ip, parsedVersion, err := ParseIP(ipString)
	if err != nil {
		return nil, err
	}
	if parsedVersion != version {
		return nil, fmt.Errorf("expected IP address %q to be %s", ipString, version)
	}
	return ip, nil
}

// ParseCIDR parses cidrString and returns a *net.IPNet and the IP version, or an error
func ParseCIDR(cidrString string) (*net.IPNet, IPVersion, error) {
	cidr, err := networkutils.ParseCIDRMask(cidrString)
	if err != nil {
		return nil, 0, err
	}
	return cidr, GetIPVersion(cidr.IP), nil
}

// ParseCIDRv parses cidrString, which must be of the indicated IP version
func ParseCIDRv(cidrString string, version IPVersion) (*net.IPNet, error) {
	cidr, parsedVersion, err := ParseCIDR(cidrString)
	if err != nil {
		return nil, err
	}
	if parsedVersion != version {
		return nil, fmt.Errorf("expected CIDR %q to be %s", cidrString, version)
	}
	return cidr, nil
}

// GetIPVersion returns the IPVersion of a net.IP
func GetIPVersion(ip net.IP) IPVersion {
	if ip.To4() != nil {
		return IPv4
	} else {
		return IPv6
	}
}

// ParseIPVersion returns the IPVersion of an IP/CIDR string (or 0 on error)
func ParseIPVersion(ipOrCIDR string) IPVersion {
	var version IPVersion
	if strings.Contains(ipOrCIDR, "/") {
		_, version, _ = ParseCIDR(ipOrCIDR)
	} else {
		_, version, _ = ParseIP(ipOrCIDR)
	}
	return version
}

