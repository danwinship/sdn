package common

import (
	"crypto/sha256"
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
func GenerateDefaultGateway(sna *net.IPNet) net.IP {
	ip := append([]byte{}, sna.IP...)
	ip[len(ip)-1] |= 0x1
	return ip
}

// Return Host IP Networks
// Ignores provided interfaces and filters loopback addrs.
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

			if ip.IsLoopback() {
				continue
			}

			hostIPNets = append(hostIPNets, ipNet)
			hostIPs = append(hostIPs, ip)
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

// IPAddrToHWAddr takes the four octets of IPv4 address (aa.bb.cc.dd, for example) and
// uses them in creating a MAC address (0A:58:AA:BB:CC:DD). For IPv6, create a hash from
// the IPv6 string and use that for MAC Address.
func IPAddrToHWAddr(ip net.IP) net.HardwareAddr {
	// Ensure that for IPv4, we are always working with the IP in 4-byte form.
	ip4 := ip.To4()
	if ip4 != nil {
		// safe to use private MAC prefix: 0A:58
		return net.HardwareAddr{0x0A, 0x58, ip4[0], ip4[1], ip4[2], ip4[3]}
	}

	hash := sha256.Sum256(ip)
	return net.HardwareAddr{0x0A, 0x58, hash[0], hash[1], hash[2], hash[3]}
}
