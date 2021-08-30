package common

import (
	"fmt"
	"net"

	kerrors "k8s.io/apimachinery/pkg/util/errors"

	osdnv1 "github.com/openshift/api/network/v1"
)

func HostSubnetToString(subnet *osdnv1.HostSubnet) string {
	return fmt.Sprintf("%s (host: %q, ip: %q, subnet: %q)", subnet.Name, subnet.Host, subnet.HostIP, subnet.Subnet)
}

func ClusterNetworkToString(n *osdnv1.ClusterNetwork) string {
	return fmt.Sprintf("%s (network: %q, hostSubnetBits: %d, serviceNetwork: %q, pluginName: %q)", n.Name, n.Network, n.HostSubnetLength, n.ServiceNetwork, n.PluginName)
}

// Generate the default gateway IP Address for a subnet
// IPV6FIXME: IPv4-specific
func GenerateDefaultGateway(sna *net.IPNet) net.IP {
	ip := sna.IP.To4()
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]|0x1)
}

// Return Host IP Networks
// Ignores provided interfaces and filters loopback and non IPv4 addrs.
// IPV6FIXME: IPv4-specific
func GetHostIPNetworks(skipInterfaces []string) ([]*net.IPNet, []net.IP, error) {
	hostInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	skipInterfaceMap := make(map[string]bool)
	for _, ifaceName := range skipInterfaces {
		skipInterfaceMap[ifaceName] = true
	}

	errList := []error{}
	var hostIPNets []*net.IPNet
	var hostIPs []net.IP
	for _, iface := range hostInterfaces {
		if skipInterfaceMap[iface.Name] {
			continue
		}

		ifAddrs, err := iface.Addrs()
		if err != nil {
			errList = append(errList, err)
			continue
		}
		for _, addr := range ifAddrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				errList = append(errList, err)
				continue
			}

			// Skip loopback and non IPv4 addrs
			if !ip.IsLoopback() && ip.To4() != nil {
				hostIPNets = append(hostIPNets, ipNet)
				hostIPs = append(hostIPs, ip)
			}
		}
	}
	return hostIPNets, hostIPs, kerrors.NewAggregate(errList)
}

func HSEgressIPsToStrings(ips []osdnv1.HostSubnetEgressIP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, string(ip))
	}
	return out
}

func StringsToHSEgressIPs(ips []string) []osdnv1.HostSubnetEgressIP {
	out := make([]osdnv1.HostSubnetEgressIP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, osdnv1.HostSubnetEgressIP(ip))
	}
	return out
}
