package common

import (
	"fmt"
	"net"

	"github.com/openshift/library-go/pkg/network/networkutils"
)

func validateCIDRv4(cidr string) (*net.IPNet, error) {
	ipnet, err := networkutils.ParseCIDRMask(cidr)
	if err != nil {
		return nil, err
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("must be an IPv4 network")
	}
	return ipnet, nil
}

func validateIPv4(ip string) (net.IP, error) {
	bytes := net.ParseIP(ip)
	if bytes == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	if bytes.To4() == nil {
		return nil, fmt.Errorf("must be an IPv4 address")
	}
	return bytes, nil
}
