package common

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"

	osdnv1 "github.com/openshift/api/network/v1"
	operv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
)

// IPV6FIXME: dual-stack support

// SDNConfig holds the openshift-sdn configuration
type SDNConfig struct {
	PluginName      string
	ClusterNetworks []ClusterNetworkEntry
	ServiceNetwork  *net.IPNet

	ClusterNetworkCIDRStrings []string
	ServiceNetworkCIDRString  string

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

	for _, entry := range cfg.Spec.ClusterNetwork {
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
	}

	// IPV6FIXME: dual-stack ServiceNetworks
	var err error
	sdnConfig.ServiceNetwork, err = networkutils.ParseCIDRMask(cfg.Spec.ServiceNetwork[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ServiceNetwork CIDR %s: %v", cfg.Spec.ServiceNetwork[0], err)
	}
	sdnConfig.ServiceNetworkCIDRString = cfg.Spec.ServiceNetwork[0]

	if osdnConfig.VXLANPort != nil {
		sdnConfig.VXLANPort = int(*osdnConfig.VXLANPort)
	} else {
		sdnConfig.VXLANPort = 4789
	}

	if osdnConfig.MTU != nil {
		sdnConfig.MTU = int(*osdnConfig.MTU)
	} else {
		// IPV6FIXME: ipv4-specific default
		sdnConfig.MTU = 1450
	}

	return sdnConfig, nil
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
// IPV6FIXME: multiple service cidrs
func (sdnConfig *SDNConfig) ServiceNetworkContains(ip net.IP) bool {
	if sdnConfig.ServiceNetwork != nil {
		if sdnConfig.ServiceNetwork.Contains(ip) {
			return true
		}
	}
	return false
}

func (sdnConfig *SDNConfig) ValidateNodeIP(nodeIP string) error {
	// IPV6FIXME: ipv4-specific
	if nodeIP == "" || nodeIP == "127.0.0.1" {
		return fmt.Errorf("invalid node IP %q", nodeIP)
	}

	// Ensure each node's NodeIP is not contained by the cluster network,
	// which could cause a routing loop. (rhbz#1295486)
	ipaddr := net.ParseIP(nodeIP)
	if ipaddr == nil {
		return fmt.Errorf("failed to parse node IP %s", nodeIP)
	}

	for _, cn := range sdnConfig.ClusterNetworks {
		if cn.CIDR.Contains(ipaddr) {
			return fmt.Errorf("node IP %s conflicts with cluster network %s", nodeIP, cn.CIDR.String())
		}
	}
	// IPV6FIXME: multiple service cidrs
	if sdnConfig.ServiceNetwork.Contains(ipaddr) {
		return fmt.Errorf("node IP %s conflicts with service network %s", nodeIP, sdnConfig.ServiceNetworkCIDRString)
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
		if cidrsOverlap(ipNet, sdnConfig.ServiceNetwork) {
			errList = append(errList, fmt.Errorf("service IP: %s conflicts with host network: %s", sdnConfig.ServiceNetworkCIDRString, ipNet.String()))
		}
	}
	return kerrors.NewAggregate(errList)
}

func (sdnConfig *SDNConfig) CheckClusterObjects(subnets []osdnv1.HostSubnet, pods []corev1.Pod, services []corev1.Service) error {
	var errList []error

	for _, subnet := range subnets {
		subnetIP, _, _ := net.ParseCIDR(subnet.Subnet)
		if subnetIP == nil {
			errList = append(errList, fmt.Errorf("failed to parse network address: %s", subnet.Subnet))
		} else if !sdnConfig.PodNetworkContains(subnetIP) {
			errList = append(errList, fmt.Errorf("existing node subnet: %s is not part of any cluster network CIDR", subnet.Subnet))
		}
		if len(errList) >= 10 {
			break
		}
	}
	for _, pod := range pods {
		if pod.Spec.HostNetwork {
			continue
		}
		podIP := net.ParseIP(pod.Status.PodIP)
		if podIP == nil {
			continue
		}
		if !sdnConfig.PodNetworkContains(podIP) {
			errList = append(errList, fmt.Errorf("existing pod %s:%s with IP %s is not part of cluster network", pod.Namespace, pod.Name, pod.Status.PodIP))
			if len(errList) >= 10 {
				break
			}
		}
	}
	for _, svc := range services {
		svcIP := net.ParseIP(svc.Spec.ClusterIP)
		if svcIP == nil {
			continue
		}
		if !sdnConfig.ServiceNetworkContains(svcIP) {
			errList = append(errList, fmt.Errorf("existing service %s:%s with IP %s is not part of service network %s", svc.Namespace, svc.Name, svc.Spec.ClusterIP, sdnConfig.ServiceNetworkCIDRString))
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

// NewTestSDNConfig creates a new basic SDNConfig for unit tests
// IPV6FIXME: will need to be able to test IPv6 and dual-stack configs
func NewTestSDNConfig() *SDNConfig {
	sdnConfig, err := ParseSDNConfig(
		&operv1.Network{
			Spec: operv1.NetworkSpec{
				DefaultNetwork: operv1.DefaultNetworkDefinition{
					Type: operv1.NetworkTypeOpenShiftSDN,
					OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
						Mode: operv1.SDNModeNetworkPolicy,
					},
				},
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 23},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
		},
	)
	if err != nil {
		panic(fmt.Sprintf("unexpected error parsing network info: %v", err))
	}
	return sdnConfig
}
