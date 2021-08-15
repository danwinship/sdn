package common

import (
	"context"
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"

	osdnv1 "github.com/openshift/api/network/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	"github.com/openshift/library-go/pkg/network/networkutils"
)

type SDNConfig struct {
	PluginName      string
	ClusterNetworks []ClusterNetworkEntry
	ServiceNetwork  *net.IPNet

	ClusterNetworkCIDRStrings []string
	ServiceNetworkCIDRString  string

	VXLANPort uint32
	MTU       uint32
}

type ClusterNetworkEntry struct {
	CIDR             *net.IPNet
	HostSubnetLength uint32
}

func GetSDNConfig(osdnClient osdnclient.Interface) (*SDNConfig, error) {
	cn, err := osdnClient.NetworkV1().ClusterNetworks().Get(context.TODO(), osdnv1.ClusterNetworkDefault, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if err = ValidateClusterNetwork(cn); err != nil {
		return nil, fmt.Errorf("ClusterNetwork is invalid (%v)", err)
	}
	return ParseSDNConfig(cn)
}

func ParseSDNConfig(cn *osdnv1.ClusterNetwork) (*SDNConfig, error) {
	sdnConfig := &SDNConfig{
		PluginName:                strings.ToLower(cn.PluginName),
		ClusterNetworks:           make([]ClusterNetworkEntry, 0, len(cn.ClusterNetworks)),
		ClusterNetworkCIDRStrings: make([]string, 0, len(cn.ClusterNetworks)),
	}

	for _, entry := range cn.ClusterNetworks {
		cidr, err := networkutils.ParseCIDRMask(entry.CIDR)
		if err != nil {
			_, cidr, err = net.ParseCIDR(entry.CIDR)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ClusterNetwork CIDR %s: %v", entry.CIDR, err)
			}
			klog.Errorf("Configured clusterNetworks value %q is invalid; treating it as %q", entry.CIDR, cidr.String())
		}
		sdnConfig.ClusterNetworks = append(sdnConfig.ClusterNetworks,
			ClusterNetworkEntry{
				CIDR:             cidr,
				HostSubnetLength: entry.HostSubnetLength,
			},
		)
		sdnConfig.ClusterNetworkCIDRStrings = append(sdnConfig.ClusterNetworkCIDRStrings, entry.CIDR)
	}

	var err error
	sdnConfig.ServiceNetwork, err = networkutils.ParseCIDRMask(cn.ServiceNetwork)
	if err != nil {
		_, sdnConfig.ServiceNetwork, err = net.ParseCIDR(cn.ServiceNetwork)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ServiceNetwork CIDR %s: %v", cn.ServiceNetwork, err)
		}
		klog.Errorf("Configured serviceNetworkCIDR value %q is invalid; treating it as %q", cn.ServiceNetwork, sdnConfig.ServiceNetwork.String())
	}
	sdnConfig.ServiceNetworkCIDRString = cn.ServiceNetwork

	if cn.VXLANPort != nil {
		sdnConfig.VXLANPort = *cn.VXLANPort
	} else {
		sdnConfig.VXLANPort = 4789
	}

	if cn.MTU != nil {
		sdnConfig.MTU = *cn.MTU
	} else {
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
func (sdnConfig *SDNConfig) ServiceNetworkContains(ip net.IP) bool {
	if sdnConfig.ServiceNetwork != nil {
		if sdnConfig.ServiceNetwork.Contains(ip) {
			return true
		}
	}
	return false
}

func (sdnConfig *SDNConfig) ValidateNodeIP(nodeIP string) error {
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
func NewTestSDNConfig() *SDNConfig {
	sdnConfig, err := ParseSDNConfig(
		&osdnv1.ClusterNetwork{
			PluginName: networkutils.NetworkPolicyPluginName,
			ClusterNetworks: []osdnv1.ClusterNetworkEntry{
				{
					CIDR:             "10.128.0.0/14",
					HostSubnetLength: 9,
				},
			},
			ServiceNetwork: "172.30.0.0/16",
		},
	)
	if err != nil {
		panic(fmt.Sprintf("unexpected error parsing network info: %v", err))
	}
	return sdnConfig
}
