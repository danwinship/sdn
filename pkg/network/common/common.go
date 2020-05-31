package common

import (
	"context"
	"fmt"
	"net"

	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilnet "k8s.io/utils/net"

	"github.com/openshift/library-go/pkg/network/networkutils"
	networkv1 "github.com/openshift/api/network/v1"
	networkclient "github.com/openshift/client-go/network/clientset/versioned"
)

func HostSubnetToString(subnet *networkv1.HostSubnet) string {
	return fmt.Sprintf("%s (host: %q, ip: %q, subnet: %q)", subnet.Name, subnet.Host, subnet.HostIP, subnet.Subnet)
}

// IPSupport is used to track whether IPv4, IPv6, or both is supported. It maps from
// the result of utilnet.IsIPv6() to whether it's supported...
type IPSupport map[bool]bool

// These are mostly for tests
var IPv4Support = IPSupport{false: true, true: false}
var IPv6Support = IPSupport{false: false, true: true}
var DualStackSupport = IPSupport{false: true, true: true}

// AllowsIPv4 is true if ipv allows IPv4
func (ipv IPSupport) AllowsIPv4() bool {
	return ipv[false]
}

// AllowsIPv6 is true if ipv allows IPv6
func (ipv IPSupport) AllowsIPv6() bool {
	return ipv[true]
}

// ParseIP parses ipString, which must be of an appropriate IP family for ipv
func (ipv IPSupport) ParseIP(ipString string) (net.IP, error) {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", ipString)
	}
	if !ipv[utilnet.IsIPv6(ip)] {
		return nil, fmt.Errorf("invalid IP family for address %q", ipString)
	}
	return ip, nil
}

// ParseCIDR parses cidrString, which must be of an appropriate IP family for ipv
func (ipv IPSupport) ParseCIDR(cidrString string) (*net.IPNet, error) {
	cidr, err := networkutils.ParseCIDRMask(cidrString)
	if err != nil {
		return nil, err
	}
	if !ipv[utilnet.IsIPv6CIDR(cidr)] {
		return nil, fmt.Errorf("invalid IP family for subnet %q", cidrString)
	}
	return cidr, nil
}

type ParsedClusterNetwork struct {
	IPFamilies      IPSupport
	ClusterNetworks []ParsedClusterNetworkEntry
	ServiceNetwork  *net.IPNet
	VXLANPort       uint32
	MTU             uint32
}

type ParsedClusterNetworkEntry struct {
	ClusterCIDR      *net.IPNet
	HostSubnetLength uint32
}

func ParseClusterNetwork(cn *networkv1.ClusterNetwork) (*ParsedClusterNetwork, error) {
	pcn := &ParsedClusterNetwork{
		ClusterNetworks: make([]ParsedClusterNetworkEntry, 0, len(cn.ClusterNetworks)),
		IPFamilies:      make(IPSupport),
	}

	for _, entry := range cn.ClusterNetworks {
		cidr, err := networkutils.ParseCIDRMask(entry.CIDR)
		if err != nil {
			return nil, fmt.Errorf("bad cluster CIDR value %q: %v", entry.CIDR, err)
		}

		maskLen, addrLen := cidr.Mask.Size()
		if entry.HostSubnetLength > uint32(addrLen-maskLen) {
			return nil, fmt.Errorf("hostSubnetLength %d is too large for CIDR %q",
				entry.HostSubnetLength, entry.CIDR)
		} else if entry.HostSubnetLength < 2 {
			return nil, fmt.Errorf("hostSubnetLength %d must be at least 2",
				entry.HostSubnetLength)
		}

		if _, _, overlap := pcn.Overlaps(cidr); overlap != nil {
			return nil, fmt.Errorf("cluster CIDR %q overlaps another CIDR %q", entry.CIDR, overlap.String())
		}

		pcn.ClusterNetworks = append(pcn.ClusterNetworks, ParsedClusterNetworkEntry{ClusterCIDR: cidr, HostSubnetLength: entry.HostSubnetLength})
		pcn.IPFamilies[utilnet.IsIPv6CIDR(cidr)] = true
	}

	serviceNetwork, err := pcn.IPFamilies.ParseCIDR(cn.ServiceNetwork)
	if err != nil {
		return nil, fmt.Errorf("bad service CIDR value %q: %v", cn.ServiceNetwork, err)
	}
	if _, _, overlap := pcn.Overlaps(serviceNetwork); overlap != nil {
		return nil, fmt.Errorf("service CIDR %q overlaps with cluster CIDR %q", cn.ServiceNetwork, overlap.String())
	}
	pcn.ServiceNetwork = serviceNetwork

	if cn.VXLANPort != nil {
		pcn.VXLANPort = *cn.VXLANPort
	} else {
		pcn.VXLANPort = 4789
	}

	if cn.MTU != nil {
		pcn.MTU = *cn.MTU
	} else if pcn.IPFamilies.AllowsIPv6() {
		pcn.MTU = 1430
	} else {
		pcn.MTU = 1450
	}

	return pcn, nil
}

// Contains determines whether pcn contains ip
func (pcn *ParsedClusterNetwork) Contains(ip net.IP) (inPodNetwork, isServiceNetwork bool, subnet *net.IPNet) {
	for _, cn := range pcn.ClusterNetworks {
		if cn.ClusterCIDR.Contains(ip) {
			return true, false, cn.ClusterCIDR
		}
	}
	if pcn.ServiceNetwork != nil {
		if pcn.ServiceNetwork.Contains(ip) {
			return false, true, pcn.ServiceNetwork
		}
	}
	return false, false, nil
}

// Overlaps determines whether pcn overlaps cidr
func (pcn *ParsedClusterNetwork) Overlaps(cidr *net.IPNet) (inPodNetwork, isServiceNetwork bool, subnet *net.IPNet) {
	for _, cn := range pcn.ClusterNetworks {
		if cn.ClusterCIDR.Contains(cidr.IP) || cidr.Contains(cn.ClusterCIDR.IP) {
			return true, false, cn.ClusterCIDR
		}
	}
	if pcn.ServiceNetwork != nil {
		if pcn.ServiceNetwork.Contains(cidr.IP) || cidr.Contains(pcn.ServiceNetwork.IP) {
			return false, true, pcn.ServiceNetwork
		}
	}
	return false, false, nil
}

func (pcn *ParsedClusterNetwork) ValidateNodeIP(nodeIP string) error {
	if nodeIP == "" || nodeIP == "127.0.0.1" || nodeIP == "::1" {
		return fmt.Errorf("invalid node IP %q", nodeIP)
	}

	// Make sure nodeIP is valid, and acceptable for the cluster's IP families
	ipaddr, err := pcn.IPFamilies.ParseIP(nodeIP)
	if err != nil {
		return fmt.Errorf("failed to parse node IP: %v", err)
	}

	// Ensure each node's NodeIP is not contained by the cluster network,
	// which could cause a routing loop. (rhbz#1295486)
	if _, _, conflictingCIDR := pcn.Contains(ipaddr); conflictingCIDR != nil {
		return fmt.Errorf("node IP %s conflicts with cluster network %s", nodeIP, conflictingCIDR.String())
	}

	return nil
}

func (pcn *ParsedClusterNetwork) CheckHostNetworks(hostIPNets []*net.IPNet) error {
	errList := []error{}
	for _, ipNet := range hostIPNets {
		if _, _, overlap := pcn.Overlaps(ipNet); overlap != nil {
			errList = append(errList, fmt.Errorf("cluster network %q conflicts with host network %q", overlap.String(), ipNet.String()))
		}
	}
	return kerrors.NewAggregate(errList)
}

func (pcn *ParsedClusterNetwork) CheckClusterObjects(subnets []networkv1.HostSubnet, pods []kapi.Pod, services []kapi.Service) error {
	var errList []error

	for _, subnet := range subnets {
		subnetIP, err := pcn.IPFamilies.ParseCIDR(subnet.Subnet)
		if err != nil {
			errList = append(errList, fmt.Errorf("HostSubnet %q has bad subnet %q: %v", subnet.Name, subnet.Subnet, err))
		} else if inPodNetwork, _, _ := pcn.Contains(subnetIP.IP); !inPodNetwork {
			errList = append(errList, fmt.Errorf("HostSubnet %q has subnet %q that is not in any cluster network CIDR", subnet.Name, subnet.Subnet))
		}
		if len(errList) >= 10 {
			break
		}
	}
	for _, pod := range pods {
		if pod.Spec.HostNetwork || pod.Status.PodIP == "" {
			continue
		}
		podIP, err := pcn.IPFamilies.ParseIP(pod.Status.PodIP)
		if err != nil {
			errList = append(errList, fmt.Errorf("pod '%s/%s' has bad IP %q: %v", pod.Namespace, pod.Name, pod.Status.PodIP, err))
		} else if inPodNetwork, _, _ := pcn.Contains(podIP); !inPodNetwork {
			errList = append(errList, fmt.Errorf("existing pod '%s/%s' with IP %s is not part of cluster network", pod.Namespace, pod.Name, pod.Status.PodIP))
		}
		if len(errList) >= 10 {
			break
		}
	}
	for _, svc := range services {
		svcIP := net.ParseIP(svc.Spec.ClusterIP)
		if svcIP == nil {
			continue
		}
		if _, inServiceNetwork, _ := pcn.Contains(svcIP); !inServiceNetwork {
			errList = append(errList, fmt.Errorf("existing service '%s/%s' with IP %s is not part of service network", svc.Namespace, svc.Name, svc.Spec.ClusterIP))
		}
		if len(errList) >= 10 {
			break
		}
	}

	if len(errList) >= 10 {
		errList = append(errList, fmt.Errorf("too many errors... truncating"))
	}
	return kerrors.NewAggregate(errList)
}

type ParsedHostSubnet struct {
	HostIP net.IP
	Subnet *net.IPNet

	EgressIPs   []net.IP
	EgressCIDRs []*net.IPNet
}

func (pcn *ParsedClusterNetwork) ParseHostSubnet(hs *networkv1.HostSubnet, parseEgressIPs bool) (*ParsedHostSubnet, error) {
	phs := &ParsedHostSubnet{}
	var err error

	phs.HostIP, err = pcn.IPFamilies.ParseIP(hs.HostIP)
	if err != nil {
		return nil, fmt.Errorf("bad HostIP value %q: %v", hs.HostIP, err)
	}

	if hs.Subnet == "" {
		// check if annotation exists, then let the Subnet field be empty
		if _, ok := hs.Annotations[networkv1.AssignHostSubnetAnnotation]; !ok {
			return nil, fmt.Errorf("missing Subnet value")
		}
	} else {
		phs.Subnet, err = pcn.IPFamilies.ParseCIDR(hs.Subnet)
		if err != nil {
			return nil, fmt.Errorf("bad Subnet value %q: %v", hs.Subnet, err)
		}
	}

	if parseEgressIPs {
		if hs.EgressIPs != nil {
			phs.EgressIPs = make([]net.IP, len(hs.EgressIPs))
			for i, egressIP := range hs.EgressIPs {
				phs.EgressIPs[i], err = pcn.IPFamilies.ParseIP(string(egressIP))
				if err != nil {
					return nil, fmt.Errorf("bad EgressIPs value %q: %v", egressIP, err)
				}
			}
		}

		if hs.EgressCIDRs != nil {
			phs.EgressCIDRs = make([]*net.IPNet, len(hs.EgressCIDRs))
			for i, egressCIDR := range hs.EgressCIDRs {
				phs.EgressCIDRs[i], err = pcn.IPFamilies.ParseCIDR(string(egressCIDR))
				if err != nil {
					return nil, fmt.Errorf("bad EgressCIDRs value %q: %v", egressCIDR, err)
				}
			}
		}
	}

	return phs, nil
}

type ParsedNetNamespace struct {
	NetName string
	NetID   uint32

	EgressIPs []net.IP
}

func (pcn *ParsedClusterNetwork) ParseNetNamespace(netns *networkv1.NetNamespace) (*ParsedNetNamespace, error) {
	pnetns := &ParsedNetNamespace{
		NetName: netns.NetName,
		NetID:   netns.NetID,
	}

	if netns.EgressIPs != nil {
		var err error
		pnetns.EgressIPs = make([]net.IP, len(netns.EgressIPs))
		for i, egressIP := range netns.EgressIPs {
			pnetns.EgressIPs[i], err = pcn.IPFamilies.ParseIP(string(egressIP))
			if err != nil {
				return nil, fmt.Errorf("bad EgressIPs value %q: %v", egressIP, err)
			}
		}
	}

	return pnetns, nil
}

func GetParsedClusterNetwork(networkClient networkclient.Interface) (*ParsedClusterNetwork, error) {
	cn, err := networkClient.NetworkV1().ClusterNetworks().Get(context.TODO(), networkv1.ClusterNetworkDefault, v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return ParseClusterNetwork(cn)
}

// Generate the default gateway IP Address for a subnet
func GenerateDefaultGateway(sna *net.IPNet) net.IP {
	baseIP := append([]byte{}, sna.IP...)
	baseIP[len(baseIP)-1] |= 0x1
	return baseIP
}

// GetHostIPNetworks returns host IP networks, ignoring skipInterfaces and loopback
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

func HSEgressIPsToStrings(ips []networkv1.HostSubnetEgressIP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, string(ip))
	}
	return out
}

func StringsToHSEgressIPs(ips []string) []networkv1.HostSubnetEgressIP {
	out := make([]networkv1.HostSubnetEgressIP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, networkv1.HostSubnetEgressIP(ip))
	}
	return out
}
