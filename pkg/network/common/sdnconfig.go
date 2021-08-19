package common

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilnet "k8s.io/utils/net"

	osdnv1 "github.com/openshift/api/network/v1"
	operv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
)

// SDNConfig holds the openshift-sdn configuration
type SDNConfig struct {
	PluginName      string
	ClusterNetworks []ClusterNetworkEntry
	ServiceNetworks []*net.IPNet

	ClusterNetworkCIDRStrings []string
	ServiceNetworkCIDRStrings []string

	HasIPv4         bool
	HasIPv6         bool
	PrimaryIPFamily corev1.IPFamily

	VXLANPort int
	MTU       int
}

type ClusterNetworkEntry struct {
	CIDR             *net.IPNet
	HostSubnetLength int
}

func GetSDNConfig(clients *SDNClients) (*SDNConfig, error) {
	cfg, err := clients.OperClient.OperatorV1().Networks().Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return ParseSDNConfig(cfg)
}

var pluginNameMap = map[operv1.SDNMode]string {
	operv1.SDNModeSubnet:        networkutils.SingleTenantPluginName,
	operv1.SDNModeMultitenant:   networkutils.MultiTenantPluginName,
	operv1.SDNModeNetworkPolicy: networkutils.NetworkPolicyPluginName,
}

func ParseSDNConfig(cfg *operv1.Network) (*SDNConfig, error) {
	if cfg.Spec.DefaultNetwork.Type != operv1.NetworkTypeOpenShiftSDN {
		return nil, fmt.Errorf("not an OpenShift SDN configuration (Type: %s)", cfg.Spec.DefaultNetwork.Type)
	}

	osdnConfig := cfg.Spec.DefaultNetwork.OpenShiftSDNConfig
	if osdnConfig == nil {
		osdnConfig = &operv1.OpenShiftSDNConfig{
			Mode: operv1.SDNModeNetworkPolicy,
		}
	}

	sdnConfig := &SDNConfig{
		PluginName:                pluginNameMap[osdnConfig.Mode],
		ClusterNetworks:           make([]ClusterNetworkEntry, 0, len(cfg.Spec.ClusterNetwork)),
		ClusterNetworkCIDRStrings: make([]string, 0, len(cfg.Spec.ClusterNetwork)),
	}

	for i, entry := range cfg.Spec.ClusterNetwork {
		cidr, err := networkutils.ParseCIDRMask(entry.CIDR)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ClusterNetwork CIDR %s: %v", entry.CIDR, err)
		}

		_, len := cidr.Mask.Size()
		sdnConfig.ClusterNetworks = append(sdnConfig.ClusterNetworks,
			ClusterNetworkEntry{
				CIDR:             cidr,
				HostSubnetLength: len - int(entry.HostPrefix),
			},
		)
		sdnConfig.ClusterNetworkCIDRStrings = append(sdnConfig.ClusterNetworkCIDRStrings, entry.CIDR)

		if utilnet.IsIPv6CIDR(cidr) {
			sdnConfig.HasIPv6 = true
			if i == 0 {
				sdnConfig.PrimaryIPFamily = corev1.IPv6Protocol
			}
		} else {
			sdnConfig.HasIPv4 = true
			if i == 0 {
				sdnConfig.PrimaryIPFamily = corev1.IPv4Protocol
			}
		}
	}

	for i, entry := range cfg.Spec.ServiceNetwork {
		cidr, err := sdnConfig.ParseCIDR(entry, i == 0)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ServiceNetwork CIDR %s: %v", entry, err)
		}

		sdnConfig.ServiceNetworks = append(sdnConfig.ServiceNetworks, cidr)
		sdnConfig.ServiceNetworkCIDRStrings = append(sdnConfig.ServiceNetworkCIDRStrings, entry)
	}

	if osdnConfig.VXLANPort != nil {
		sdnConfig.VXLANPort = int(*osdnConfig.VXLANPort)
	} else {
		sdnConfig.VXLANPort = 4789
	}

	if osdnConfig.MTU != nil {
		sdnConfig.MTU = int(*osdnConfig.MTU)
	} else {
		sdnConfig.MTU = 1500 - sdnConfig.VXLANOverhead()
	}

	return sdnConfig, nil
}

// ParseIP parses ipString, which must be of an appropriate IP family for the sdnConfig
func (sdnConfig *SDNConfig) ParseIP(ipString string, mustBePrimary bool) (net.IP, error) {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", ipString)
	}
	isIPv6 := utilnet.IsIPv6(ip)
	if (isIPv6 && !sdnConfig.HasIPv6) || (!isIPv6 && !sdnConfig.HasIPv4) {
		return nil, fmt.Errorf("address %q is wrong family for this cluster", ipString)
	}
	if mustBePrimary && (isIPv6 != (sdnConfig.PrimaryIPFamily == corev1.IPv6Protocol)) {
		return nil, fmt.Errorf("address %q is wrong family for cluster with primary family %q", ipString, sdnConfig.PrimaryIPFamily)
	}

	return ip, nil
}

// ParseCIDR parses cidrString, which must be of an appropriate IP family for sdnConfig.
func (sdnConfig *SDNConfig) ParseCIDR(cidrString string, mustBePrimary bool) (*net.IPNet, error) {
	cidr, err := networkutils.ParseCIDRMask(cidrString)
	if err != nil {
		return nil, err
	}
	isIPv6 := utilnet.IsIPv6CIDR(cidr)
	if (isIPv6 && !sdnConfig.HasIPv6) || (!isIPv6 && !sdnConfig.HasIPv4) {
		return nil, fmt.Errorf("network %q is wrong family for this cluster", cidrString)
	}
	if mustBePrimary && (isIPv6 != (sdnConfig.PrimaryIPFamily == corev1.IPv6Protocol)) {
		return nil, fmt.Errorf("network %q is wrong family for cluster with primary family %q", cidrString, sdnConfig.PrimaryIPFamily)
	}

	return cidr, nil
}

// PodNetworkContains determines whether sdnConfig's pod network contains ip
func (sdnConfig *SDNConfig) PodNetworkContains(ip net.IP) bool {
	for _, cn := range sdnConfig.ClusterNetworks {
		if cn.CIDR.Contains(ip) {
			return true
		}
	}
	return false
}

// ServiceNetworkContains determines whether sdnConfig's service network contains ip
func (sdnConfig *SDNConfig) ServiceNetworkContains(ip net.IP) bool {
	for _, sn := range sdnConfig.ServiceNetworks {
		if sn.Contains(ip) {
			return true
		}
	}
	return false
}

func (sdnConfig *SDNConfig) ValidateNodeIP(nodeIP string) error {
	if nodeIP == "" || nodeIP == "127.0.0.1" || nodeIP == "::1" {
		return fmt.Errorf("invalid node IP %q", nodeIP)
	}

	// Make sure nodeIP is valid, and acceptable for the cluster's IP families
	ipaddr, err := sdnConfig.ParseIP(nodeIP, true)
	if err != nil {
		return fmt.Errorf("failed to parse node IP: %v", err)
	}

	// Ensure each node's NodeIP is not contained by the cluster network,
	// which could cause a routing loop. (rhbz#1295486)
	for _, cn := range sdnConfig.ClusterNetworks {
		if cn.CIDR.Contains(ipaddr) {
			return fmt.Errorf("node IP %s conflicts with cluster network %s", nodeIP, cn.CIDR.String())
		}
	}
	for _, sn := range sdnConfig.ServiceNetworks {
		if sn.Contains(ipaddr) {
			return fmt.Errorf("node IP %s conflicts with service network %s", nodeIP, sn.String())
		}
	}

	return nil
}

func (sdnConfig *SDNConfig) CheckHostNetworks(hostIPNets []*net.IPNet) error {
	errList := []error{}
	for _, ipNet := range hostIPNets {
		for _, clusterNetwork := range sdnConfig.ClusterNetworks {
			if cidrsOverlap(ipNet, clusterNetwork.CIDR) {
				errList = append(errList, fmt.Errorf("cluster IP: %s conflicts with host network: %s", clusterNetwork.CIDR.IP.String(), ipNet.String()))
			}
		}
		for _, serviceNetwork := range sdnConfig.ServiceNetworks {
			if cidrsOverlap(ipNet, serviceNetwork) {
				errList = append(errList, fmt.Errorf("service IP: %s conflicts with host network: %s", serviceNetwork.String(), ipNet.String()))
			}
		}
	}
	return kerrors.NewAggregate(errList)
}

func (sdnConfig *SDNConfig) CheckClusterObjects(subnets []osdnv1.HostSubnet, pods []corev1.Pod, services []corev1.Service) error {
	var errList []error

	for _, subnet := range subnets {
		subnetIP, err := sdnConfig.ParseCIDR(subnet.Subnet, false)
		if err != nil {
			errList = append(errList, fmt.Errorf("HostSubnet %q has bad subnet %q: %v", subnet.Name, subnet.Subnet, err))
		} else if !sdnConfig.PodNetworkContains(subnetIP.IP) {
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
		podIP, err := sdnConfig.ParseIP(pod.Status.PodIP, false)
		if err != nil {
			errList = append(errList, fmt.Errorf("pod '%s/%s' has bad IP %q: %v", pod.Namespace, pod.Name, pod.Status.PodIP, err))
		} else if !sdnConfig.PodNetworkContains(podIP) {
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
		if !sdnConfig.ServiceNetworkContains(svcIP) {
			errList = append(errList, fmt.Errorf("existing service %s:%s with IP %s is not part of service network", svc.Namespace, svc.Name, svc.Spec.ClusterIP))
			if len(errList) >= 10 {
				break
			}
		}
	}

	if len(errList) >= 10 {
		errList = append(errList, fmt.Errorf("too many errors... truncating"))
	}
	return kerrors.NewAggregate(errList)
}

// VXLANOverhead returns the number of bytes of overhead needed for VXLAN tunneling in a
// cluster with this configuration.
func (sdnConfig *SDNConfig) VXLANOverhead() int {
	if sdnConfig.PrimaryIPFamily == corev1.IPv6Protocol {
		return 70
	} else {
		return 50
	}
}

// osdnv1.HostSubnet is forced to be IPv4-only by its CRD. So for dual-stack, we
// use annotations to store the IPv6 HostIP and Subnet. For single-stack IPv6, we
// likewise use the annotations, and leave "0.0.0.0" and "0.0.0.0/0" for the IPv4
// HostIP/Subnet.
//
// IPV6FIXME: We should drop HostSubnet in favor of using annotations on Node
// like ovn-kubernetes does.

const (
	HostSubnetIPv6HostIPAnnotation = "hostsubnet.network.openshift.io/ipv6-hostip"
	HostSubnetIPv6SubnetAnnotation = "hostsubnet.network.openshift.io/ipv6-subnet"
)

type ParsedHostSubnet struct {
	Host    string
	HostIPs []net.IP
	Subnets []*net.IPNet
}

// ParseHostSubnet validates and parses hs, ensuring that it is compatible with the
// sdnConfig's IP families.
func (sdnConfig *SDNConfig) ParseHostSubnet(hs *osdnv1.HostSubnet) (*ParsedHostSubnet, error) {
	phs := &ParsedHostSubnet{
		Host: hs.Host,
	}

	var err error
	var v4ip, v6ip net.IP
	var v4subnet, v6subnet *net.IPNet

	if hs.HostIP == "0.0.0.0" {
		if sdnConfig.HasIPv4 {
			return nil, fmt.Errorf("subnet has no IPv4 HostIP value")
		}
	} else {
		v4ip, err = sdnConfig.ParseIP(hs.HostIP, false)
		if err != nil {
			return nil, fmt.Errorf("bad HostIP value %q: %v", hs.HostIP, err)
		}
	}

	if annotation, exists := hs.Annotations[HostSubnetIPv6HostIPAnnotation]; exists {
		v6ip, err = sdnConfig.ParseIP(annotation, false)
		if err != nil {
			return nil, fmt.Errorf("bad IPv6 HostIP value %q: %v", annotation, err)
		}
	} else if sdnConfig.HasIPv6 {
		return nil, fmt.Errorf("subnet has no IPv6 HostIP value")
	}

	if sdnConfig.PrimaryIPFamily == corev1.IPv4Protocol {
		phs.HostIPs = append(phs.HostIPs, v4ip)
		if v6ip != nil {
			phs.HostIPs = append(phs.HostIPs, v6ip)
		}
	} else {
		phs.HostIPs = append(phs.HostIPs, v6ip)
		if v4ip != nil {
			phs.HostIPs = append(phs.HostIPs, v4ip)
		}
	}

	if hs.Subnet == "" {
		// check if annotation exists, then let the Subnet field be empty
		if _, ok := hs.Annotations[osdnv1.AssignHostSubnetAnnotation]; !ok {
			return nil, fmt.Errorf("missing Subnet value")
		}
		return phs, nil
	}

	if hs.Subnet == "0.0.0.0/0" {
		if sdnConfig.HasIPv4 {
			return nil, fmt.Errorf("subnet has no IPv4 Subnet value")
		}
	} else {
		v4subnet, err = sdnConfig.ParseCIDR(hs.Subnet, false)
		if err != nil {
			return nil, fmt.Errorf("bad Subnet value %q: %v", hs.Subnet, err)
		}
	}

	if annotation, exists := hs.Annotations[HostSubnetIPv6SubnetAnnotation]; exists {
		v6subnet, err = sdnConfig.ParseCIDR(annotation, false)
		if err != nil {
			return nil, fmt.Errorf("bad IPv6 Subnet value %q: %v", annotation, err)
		}
	} else if sdnConfig.HasIPv6 {
		return nil, fmt.Errorf("subnet has no IPv6 Subnet value")
	}

	if sdnConfig.PrimaryIPFamily == corev1.IPv4Protocol {
		phs.Subnets = append(phs.Subnets, v4subnet)
		if v6subnet != nil {
			phs.Subnets = append(phs.Subnets, v6subnet)
		}
	} else {
		phs.Subnets = append(phs.Subnets, v6subnet)
		if v4subnet != nil {
			phs.Subnets = append(phs.Subnets, v4subnet)
		}
	}

	return phs, nil
}

// UnparseHostSubnet copies the data from a ParsedHostSubnet back into an
// osdnv1.HostSubnet so it can be updated. Assumes that phs is valid for sdnConfig.
func (sdnConfig *SDNConfig) UnparseHostSubnet(phs *ParsedHostSubnet, hs *osdnv1.HostSubnet) {
	if hs.Annotations == nil {
		hs.Annotations = map[string]string{}
	} else {
		delete(hs.Annotations, HostSubnetIPv6HostIPAnnotation)
		delete(hs.Annotations, HostSubnetIPv6SubnetAnnotation)
	}

	for _, ip := range phs.HostIPs {
		if utilnet.IsIPv4(ip) {
			hs.HostIP = ip.String()
		} else {
			hs.Annotations[HostSubnetIPv6HostIPAnnotation] = ip.String()
		}
	}
	for _, subnet := range phs.Subnets {
		if utilnet.IsIPv4CIDR(subnet) {
			hs.Subnet = subnet.String()
		} else {
			hs.Annotations[HostSubnetIPv6SubnetAnnotation] = subnet.String()
		}
	}

	if !sdnConfig.HasIPv4 {
		hs.HostIP = "0.0.0.0"
		hs.Subnet = "0.0.0.0/0"
	}
}

// NewTestSDNConfig creates a new basic SDNConfig for unit tests. By default it returns an
// IPv4-only config, but you can pass one or two corev1.IPFamily values to override that.
func NewTestSDNConfig(families ...corev1.IPFamily) *SDNConfig {
	cfg := &operv1.Network{
		Spec: operv1.NetworkSpec{
			DefaultNetwork: operv1.DefaultNetworkDefinition{
				Type: operv1.NetworkTypeOpenShiftSDN,
				OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
					Mode: operv1.SDNModeNetworkPolicy,
				},
			},
			ClusterNetwork: []operv1.ClusterNetworkEntry{},
			ServiceNetwork: []string{},
		},
	}

	if families == nil {
		families = []corev1.IPFamily{corev1.IPv4Protocol}
	}
	for _, family := range families {
		switch family {
		case corev1.IPv4Protocol:
			cfg.Spec.ClusterNetwork = append(cfg.Spec.ClusterNetwork,
				operv1.ClusterNetworkEntry{
					CIDR:       "10.128.0.0/14",
					HostPrefix: 23,
				},
			)
			cfg.Spec.ServiceNetwork = append(cfg.Spec.ServiceNetwork,
				"172.30.0.0/16",
			)
		case corev1.IPv6Protocol:
			cfg.Spec.ClusterNetwork = append(cfg.Spec.ClusterNetwork,
				operv1.ClusterNetworkEntry{
					CIDR:       "fd01::/48",
					HostPrefix: 64,
				},
			)
			cfg.Spec.ServiceNetwork = append(cfg.Spec.ServiceNetwork,
				"fd02::/112",
			)
		}
	}

	sdnConfig, err := ParseSDNConfig(cfg)
	if err != nil {
		panic(fmt.Sprintf("unexpected error parsing network info: %v", err))
	}
	return sdnConfig
}
