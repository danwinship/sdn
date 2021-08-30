package node

import (
	"context"
	"fmt"
	"net"
	"time"

	"k8s.io/klog/v2"

	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
)

type NodeConfig struct {
	// Name is the node name, passed on the command line
	Name string
	// IP is the node IP, passed on the command line
	// IPV6FIXME: dual node IPs
	IP       net.IP
	IPString string

	// LocalSubnet is the local HostSubnet CIDR
	// IPV6FIXME: dual local subnets
	LocalSubnet           *net.IPNet
	LocalSubnetCIDRString string
	// LocalGateway is the IP of tun0, in CIDR form
	// IPV6FIXME: dual local gateways
	LocalGateway             *net.IPNet
	LocalGatewayIPString     string
	LocalGatewayIfAddrString string

	// PluginID is the numeric ID used for the active network plugin
	PluginID int

	// UseConnTrack is true if we are using conntrack-based Service rules
	// (NetworkPolicy mode or Multitenant+IPTables proxy).
	UseConnTrack bool

	// MasqueradeBitMask is a bitmask with the KUBE-MARK-MASQ bit set.
	MasqueradeBitMask uint32
}

func NewNodeConfig(nodeName, nodeIP string,
	sdnConfig *common.SDNConfig,
	proxyConfig *kubeproxyconfig.KubeProxyConfiguration) (*NodeConfig, error) {

	ip := net.ParseIP(nodeIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid node IP %q", nodeIP)
	}

	nodeConfig := &NodeConfig{
		Name:     nodeName,
		IP:       ip,
		IPString: nodeIP,
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

	nodeConfig, err := NewNodeConfig("node1", "172.17.0.4", sdnConfig, proxyConfig)
	if err != nil {
		panic(fmt.Sprintf("unexpected error parsing nodeConfig: %v", err))
	}

	// Allocate the first subnet out of sdnConfig's cluster network
	cn := sdnConfig.ClusterNetworks[0]
	_, bits := cn.CIDR.Mask.Size()
	localSubnet := fmt.Sprintf("%s/%d", cn.CIDR.IP.String(), bits-cn.HostSubnetLength)

	err = nodeConfig.setLocalSubnet(localSubnet)
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
			} else if subnet.HostIP == nodeConfig.IPString {
				return true, nil
			} else {
				klog.Warningf("HostIP %q for local subnet does not match with nodeIP %q, "+
					"Waiting for master to update subnet for node %q ...", subnet.HostIP, nodeConfig.IP, nodeConfig.Name)
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

	return nodeConfig.setLocalSubnet(subnet.Subnet)
}

func (nodeConfig *NodeConfig) setLocalSubnet(subnet string) error {
	var err error

	nodeConfig.LocalSubnet, err = networkutils.ParseCIDRMask(subnet)
	if err != nil {
		return fmt.Errorf("local HostSubnet has invalid Subnet: %v", err)
	}
	nodeConfig.LocalSubnetCIDRString = subnet

	nodeConfig.LocalGateway = &net.IPNet{
		IP:   common.GenerateDefaultGateway(nodeConfig.LocalSubnet),
		Mask: nodeConfig.LocalSubnet.Mask,
	}
	nodeConfig.LocalGatewayIPString = nodeConfig.LocalGateway.IP.String()
	nodeConfig.LocalGatewayIfAddrString = nodeConfig.LocalGateway.String()

	return nil
}
