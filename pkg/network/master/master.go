package master

import (
	"context"

	ktypes "k8s.io/apimachinery/pkg/types"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	osdnv1listers "github.com/openshift/client-go/network/listers/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	masterutil "github.com/openshift/sdn/pkg/network/master/util"
)

const (
	tun0 = "tun0"
)

type OsdnMaster struct {
	clients     *common.SDNClients
	networkInfo *common.ParsedClusterNetwork
	vnids       *masterVNIDMap

	// FIXME: move the subnet allocator stuff into its own struct

	// Used for allocating subnets in order
	subnetAllocator *masterutil.SubnetAllocator

	// Holds Node IP used in creating host subnet for a node
	hostSubnetNodeIPs map[ktypes.UID]string

	nodeLister       corev1listers.NodeLister
	hostSubnetLister osdnv1listers.HostSubnetLister
}

func Start(clients *common.SDNClients) error {
	klog.Infof("Initializing SDN master")

	networkInfo, err := common.GetParsedClusterNetwork(clients.OSDNClient)
	if err != nil {
		return err
	}

	master := &OsdnMaster{
		clients:     clients,
		networkInfo: networkInfo,

		hostSubnetNodeIPs: map[ktypes.UID]string{},
	}

	if err = master.checkClusterNetworkAgainstLocalNetworks(); err != nil {
		return err
	}
	if err = master.checkClusterNetworkAgainstClusterObjects(); err != nil {
		klog.Errorf("Cluster contains objects incompatible with ClusterNetwork: %v", err)
	}

	go master.startSubSystems(master.networkInfo.PluginName)

	return nil
}

func (master *OsdnMaster) startSubSystems(pluginName string) {
	if err := master.startSubnetMaster(); err != nil {
		klog.Fatalf("failed to start subnet master: %v", err)
	}

	switch pluginName {
	case networkutils.MultiTenantPluginName:
		master.vnids = newMasterVNIDMap(true)
	case networkutils.NetworkPolicyPluginName:
		master.vnids = newMasterVNIDMap(false)
	}
	if master.vnids != nil {
		if err := master.startVNIDMaster(); err != nil {
			klog.Fatalf("failed to start VNID master: %v", err)
		}
	}

	eim := newEgressIPManager(master.clients)
	eim.Start()
	enp := newEgressNetworkPolicyManager(master.clients)
	enp.start()

	master.clients.WaitForCacheSync("openshift-sdn-controller")
}

func (master *OsdnMaster) checkClusterNetworkAgainstLocalNetworks() error {
	hostIPNets, _, err := common.GetHostIPNetworks([]string{tun0})
	if err != nil {
		return err
	}
	return master.networkInfo.CheckHostNetworks(hostIPNets)
}

func (master *OsdnMaster) checkClusterNetworkAgainstClusterObjects() error {
	subnets, err := common.ListAllHostSubnets(context.TODO(), master.clients.OSDNClient)
	if err != nil {
		klog.Warningf("Failed to list subnets: %v", err)
	}

	pods, err := common.ListAllPods(context.TODO(), master.clients.KubeClient)
	if err != nil {
		klog.Warningf("Failed to list pods: %v", err)
	}

	services, err := common.ListAllServices(context.TODO(), master.clients.KubeClient)
	if err != nil {
		klog.Warningf("Failed to list services: %v", err)
	}

	return master.networkInfo.CheckClusterObjects(subnets, pods, services)
}
