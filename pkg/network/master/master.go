package master

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
)

const (
	tun0 = "tun0"
)

type OsdnMaster struct {
	clients   *common.SDNClients
	sdnConfig *common.SDNConfig

	subnetManager *subnetManager
	vnids         *masterVNIDMap
	eim           *egressIPManager
}

func Start(clients *common.SDNClients, sdnConfig *common.SDNConfig) error {
	klog.Infof("Initializing SDN master")

	master := &OsdnMaster{
		clients:   clients,
		sdnConfig: sdnConfig,

		subnetManager: newSubnetManager(clients, sdnConfig),
		eim:           newEgressIPManager(clients),
	}

	switch sdnConfig.PluginName {
	case networkutils.MultiTenantPluginName:
		master.vnids = newMasterVNIDMap(clients, true)
	case networkutils.NetworkPolicyPluginName:
		master.vnids = newMasterVNIDMap(clients, false)
	}

	if err := master.checkClusterNetworkAgainstLocalNetworks(); err != nil {
		return err
	}
	if err := master.checkClusterNetworkAgainstClusterObjects(); err != nil {
		klog.Errorf("Cluster contains objects incompatible with ClusterNetwork: %v", err)
	}

	// FIXME: this is required to register informers for the types we care about to ensure the informers are started.
	// FIXME: restructure this controller to add event handlers in Start() before returning, instead of inside startSubSystems.
	clients.KubeInformers.Core().V1().Nodes().Informer().GetController()
	clients.KubeInformers.Core().V1().Namespaces().Informer().GetController()
	clients.OSDNInformers.Network().V1().HostSubnets().Informer().GetController()
	clients.OSDNInformers.Network().V1().NetNamespaces().Informer().GetController()

	go master.startSubSystems(master.sdnConfig.PluginName)

	return nil
}

func (master *OsdnMaster) startSubSystems(pluginName string) {
	if err := master.subnetManager.start(); err != nil {
		klog.Fatalf("failed to start subnet manager: %v", err)
	}

	if master.vnids != nil {
		if err := master.vnids.startVNIDMaster(); err != nil {
			klog.Fatalf("failed to start VNID master: %v", err)
		}
	}

	master.eim.Start()
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
