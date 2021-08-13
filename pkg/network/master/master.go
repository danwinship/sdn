package master

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	kcoreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"

	osdnv1 "github.com/openshift/api/network/v1"
	osdninformersv1 "github.com/openshift/client-go/network/informers/externalversions/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	masterutil "github.com/openshift/sdn/pkg/network/master/util"
)

const (
	tun0 = "tun0"
)

type OsdnMaster struct {
	clients   *common.SDNClients
	sdnConfig *common.SDNConfig

	vnids *masterVNIDMap

	nodeInformer         kcoreinformers.NodeInformer
	namespaceInformer    kcoreinformers.NamespaceInformer
	hostSubnetInformer   osdninformersv1.HostSubnetInformer
	netNamespaceInformer osdninformersv1.NetNamespaceInformer

	// Used for allocating subnets in order
	subnetAllocator *masterutil.SubnetAllocator

	// Holds Node IP used in creating host subnet for a node
	hostSubnetNodeIPs map[ktypes.UID]string
}

func Start(clients *common.SDNClients, sdnConfig *common.SDNConfig) error {
	klog.Infof("Initializing SDN master")

	master := &OsdnMaster{
		clients:   clients,
		sdnConfig: sdnConfig,

		nodeInformer:         clients.KubeInformers.Core().V1().Nodes(),
		namespaceInformer:    clients.KubeInformers.Core().V1().Namespaces(),
		hostSubnetInformer:   clients.OSDNInformers.Network().V1().HostSubnets(),
		netNamespaceInformer: clients.OSDNInformers.Network().V1().NetNamespaces(),

		hostSubnetNodeIPs: map[ktypes.UID]string{},
	}

	if err := master.checkClusterNetworkAgainstLocalNetworks(); err != nil {
		return err
	}
	if err := master.checkClusterNetworkAgainstClusterObjects(); err != nil {
		klog.Errorf("Cluster contains objects incompatible with ClusterNetwork: %v", err)
	}

	// FIXME: this is required to register informers for the types we care about to ensure the informers are started.
	// FIXME: restructure this controller to add event handlers in Start() before returning, instead of inside startSubSystems.
	master.nodeInformer.Informer().GetController()
	master.namespaceInformer.Informer().GetController()
	master.hostSubnetInformer.Informer().GetController()
	master.netNamespaceInformer.Informer().GetController()

	go master.startSubSystems(master.sdnConfig.PluginName)

	return nil
}

func (master *OsdnMaster) startSubSystems(pluginName string) {
	// Wait for informer sync
	master.clients.WaitForCacheSync("SDN master",
		master.nodeInformer.Informer(),
		master.namespaceInformer.Informer(),
		master.hostSubnetInformer.Informer(),
		master.netNamespaceInformer.Informer())

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

	eim := newEgressIPManager()
	eim.Start(master.clients.OSDNClient, master.hostSubnetInformer, master.netNamespaceInformer, master.nodeInformer)
}

func (master *OsdnMaster) checkClusterNetworkAgainstLocalNetworks() error {
	hostIPNets, _, err := common.GetHostIPNetworks([]string{tun0})
	if err != nil {
		return err
	}
	return master.sdnConfig.CheckHostNetworks(hostIPNets)
}

func (master *OsdnMaster) checkClusterNetworkAgainstClusterObjects() error {
	var subnets []osdnv1.HostSubnet
	var pods []corev1.Pod
	var services []corev1.Service
	if subnetList, err := master.clients.OSDNClient.NetworkV1().HostSubnets().List(context.TODO(), metav1.ListOptions{}); err == nil {
		subnets = subnetList.Items
	}
	if podList, err := master.clients.KubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{}); err == nil {
		pods = podList.Items
	}
	if serviceList, err := master.clients.KubeClient.CoreV1().Services(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{}); err == nil {
		services = serviceList.Items
	}

	return master.sdnConfig.CheckClusterObjects(subnets, pods, services)
}
