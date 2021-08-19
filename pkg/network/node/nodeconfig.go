package node

import (
	"context"
	"fmt"
	"net"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	utilnet "k8s.io/utils/net"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
)

type NodeConfig struct {
	// Name is the node name, passed on the command line
	Name string
	// IPs are the node IP(s), passed on the command line
	IPs       []net.IP
	IPStrings []string

	// LocalSubnets are the local HostSubnet CIDR(s)
	LocalSubnets           []*net.IPNet
	LocalSubnetCIDRStrings []string
	// LocalGateways are the IP(s) of tun0, in CIDR form
	LocalGateways             []*net.IPNet
	LocalGatewayIPStrings     []string
	LocalGatewayIfAddrStrings []string

	// PluginID is the numeric ID used for the active network plugin
	PluginID int

	// UseConnTrack is true if we are using conntrack-based Service rules
	// (NetworkPolicy mode or Multitenant+IPTables proxy).
	UseConnTrack bool

	// MasqueradeBitMask is a bitmask with the KUBE-MARK-MASQ bit set.
	MasqueradeBitMask uint32

	sdnConfig *common.SDNConfig
}

func NewNodeConfig(nodeName string, nodeIPs []string,
	sdnConfig *common.SDNConfig,
	proxyConfig *kubeproxyconfig.KubeProxyConfiguration) (*NodeConfig, error) {

	nodeConfig := &NodeConfig{
		Name:      nodeName,
		IPStrings: nodeIPs,
		IPs:       make([]net.IP, len(nodeIPs)),
	}

	for i, nodeIP := range nodeIPs {
		nodeConfig.IPs[i] = net.ParseIP(nodeIP)
		if nodeConfig.IPs[i] == nil {
			return nil, fmt.Errorf("invalid node IP %q", nodeIP)
		}
	}

	switch sdnConfig.PluginName {
	case networkutils.SingleTenantPluginName:
		nodeConfig.PluginID = 0
	case networkutils.MultiTenantPluginName:
		nodeConfig.PluginID = 1
		// Use conntrack if and only if not using userspace proxy
		if proxyConfig.Mode != kubeproxyconfig.ProxyModeUserspace {
			nodeConfig.UseConnTrack = true
		}
	case networkutils.NetworkPolicyPluginName:
		nodeConfig.PluginID = 2
		if proxyConfig.Mode == kubeproxyconfig.ProxyModeUserspace {
			return nil, fmt.Errorf("%q plugin is not compatible with proxy-mode %q", sdnConfig.PluginName, proxyConfig.Mode)
		}
		nodeConfig.UseConnTrack = true
	default:
		return nil, fmt.Errorf("unknown plugin name %q", sdnConfig.PluginName)
	}

	if proxyConfig.IPTables.MasqueradeBit != nil {
		nodeConfig.MasqueradeBitMask = 1 << *proxyConfig.IPTables.MasqueradeBit
	}

	return nodeConfig, nil
}

// NewTestNodeConfig creates a new NodeConfig for unit tests
func NewTestNodeConfig(sdnConfig *common.SDNConfig) *NodeConfig {
	masqBit := int32(0)
	proxyConfig := &kubeproxyconfig.KubeProxyConfiguration{
		IPTables: kubeproxyconfig.KubeProxyIPTablesConfiguration{
			MasqueradeBit: &masqBit,
		},
	}

	var nodeIPs []string
	if sdnConfig.PrimaryIPFamily == corev1.IPv4Protocol {
		nodeIPs = append(nodeIPs, "172.17.0.4")
		if sdnConfig.HasIPv6 {
			nodeIPs = append(nodeIPs, "2001:172:17::4")
		}
	} else {
		nodeIPs = append(nodeIPs, "2001:172:17::4")
		if sdnConfig.HasIPv4 {
			nodeIPs = append(nodeIPs, "172.17.0.4")
		}
	}

	nodeConfig, err := NewNodeConfig("node1", nodeIPs, sdnConfig, proxyConfig)
	if err != nil {
		panic(fmt.Sprintf("unexpected error parsing nodeConfig: %v", err))
	}

	// Allocate the first subnets out of sdnConfig's cluster network
	var v4Subnet, v6Subnet *net.IPNet
	for _, cn := range sdnConfig.ClusterNetworks {
		if utilnet.IsIPv4CIDR(cn.CIDR) && v4Subnet == nil {
			v4Subnet = &net.IPNet{
				IP:   cn.CIDR.IP,
				Mask: net.CIDRMask(32-cn.HostSubnetLength, 32),
			}
		} else if utilnet.IsIPv6CIDR(cn.CIDR) && v6Subnet == nil {
			// SubnetAllocator skips the all-zero subnet for IPv6...
			baseIP := append([]byte{}, cn.CIDR.IP...)
			firstSubnetBit := cn.HostSubnetLength - 1
			baseIP[firstSubnetBit/8] |= 1 << (7 - firstSubnetBit%8)
			v6Subnet = &net.IPNet{
				IP:   baseIP,
				Mask: net.CIDRMask(128-cn.HostSubnetLength, 128),
			}
		}
	}

	var localSubnets []*net.IPNet
	if sdnConfig.PrimaryIPFamily == corev1.IPv4Protocol {
		localSubnets = append(localSubnets, v4Subnet)
		if v6Subnet != nil {
			localSubnets = append(localSubnets, v6Subnet)
		}
	} else {
		localSubnets = append(localSubnets, v6Subnet)
		if v4Subnet != nil {
			localSubnets = append(localSubnets, v4Subnet)
		}
	}

	err = nodeConfig.setLocalSubnets(localSubnets)
	if err != nil {
		panic(fmt.Sprintf("unexpected error setting local subnet: %v", err))
	}

	return nodeConfig
}

func (nodeConfig *NodeConfig) getLocalSubnet(clients *common.SDNClients) error {
	var subnet *osdnv1.HostSubnet

	// The HostSubnet should already have been created by the SDN master in response
	// to the kubelet creating its Node. Sometimes this takes unexpectedly long
	// though. (The timeout here is based on no-longer-correct assumptions and is
	// probably far longer than it really needs to be, but whatever.)
	backoff := utilwait.Backoff{
		// ~2 mins total
		Duration: time.Second,
		Factor:   1.5,
		Steps:    11,
	}
	err := utilwait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		subnet, err = clients.OSDNClient.NetworkV1().HostSubnets().Get(context.TODO(), nodeConfig.Name, metav1.GetOptions{})
		if err == nil {
			if err = common.ValidateHostSubnet(subnet); err != nil {
				return false, err
			// IPV6FIXME: validate both IPs
			} else if subnet.HostIP == nodeConfig.IPStrings[0] {
				return true, nil
			} else {
				klog.Warningf("HostIP %q for local subnet does not match with nodeIP %q, "+
					"Waiting for master to update subnet for node %q ...", subnet.HostIP, nodeConfig.IPs[0], nodeConfig.Name)
				return false, nil
			}
		} else if kapierrors.IsNotFound(err) {
			klog.Warningf("Could not find an allocated subnet for node: %s, Waiting...", nodeConfig.Name)
			return false, nil
		} else {
			return false, err
		}
	})
	if err != nil {
		return fmt.Errorf("failed to get subnet for this host: %s, error: %v", nodeConfig.Name, err)
	}

	cidr, err := nodeConfig.sdnConfig.ParseCIDR(subnet.Subnet, true)
	if err != nil {
		return fmt.Errorf("illegal subnet for host %q: %v", nodeConfig.Name, err)
	}
	return nodeConfig.setLocalSubnets([]*net.IPNet{cidr})
}

func (nodeConfig *NodeConfig) setLocalSubnets(subnets []*net.IPNet) error {
	nodeConfig.LocalSubnets = subnets
	nodeConfig.LocalSubnetCIDRStrings = make([]string, len(subnets))
	nodeConfig.LocalGateways = make([]*net.IPNet, len(subnets))
	nodeConfig.LocalGatewayIPStrings = make([]string, len(subnets))
	nodeConfig.LocalGatewayIfAddrStrings = make([]string, len(subnets))

	for i, subnet := range subnets {
		nodeConfig.LocalSubnetCIDRStrings[i] = subnet.String()
		nodeConfig.LocalGateways[i] = &net.IPNet{
			IP:   common.GenerateDefaultGateway(subnet),
			Mask: subnet.Mask,
		}
		nodeConfig.LocalGatewayIPStrings[i] = nodeConfig.LocalGateways[i].IP.String()
		nodeConfig.LocalGatewayIfAddrStrings[i] = nodeConfig.LocalGateways[i].String()
	}

	return nil
}
