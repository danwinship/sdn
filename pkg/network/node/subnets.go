package node

import (
	"fmt"
	"net"

	"k8s.io/klog/v2"

	ktypes "k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/watch"

	osdnv1 "github.com/openshift/api/network/v1"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/sdn/pkg/network/common"
)

type hostSubnetWatcher struct {
	oc        *ovsController
	localIPs  []net.IP
	sdnConfig *common.SDNConfig

	hostSubnetMap map[ktypes.UID]*common.ParsedHostSubnet
}

func newHostSubnetWatcher(oc *ovsController, sdnConfig *common.SDNConfig, nodeConfig *NodeConfig) *hostSubnetWatcher {
	return &hostSubnetWatcher{
		oc:         oc,
		localIPs:   nodeConfig.IPs,
		sdnConfig:  sdnConfig,

		hostSubnetMap: make(map[ktypes.UID]*common.ParsedHostSubnet),
	}
}

func (hsw *hostSubnetWatcher) Start(osdnInformers osdninformers.SharedInformerFactory) {
	funcs := common.InformerFuncs(&osdnv1.HostSubnet{}, hsw.handleAddOrUpdateHostSubnet, hsw.handleDeleteHostSubnet)
	osdnInformers.Network().V1().HostSubnets().Informer().AddEventHandler(funcs)
}

func (hsw *hostSubnetWatcher) handleAddOrUpdateHostSubnet(obj, _ interface{}, eventType watch.EventType) {
	hs := obj.(*osdnv1.HostSubnet)
	klog.V(5).Infof("Watch %s event for HostSubnet %q", eventType, hs.Name)

	if err := common.ValidateHostSubnet(hs); err != nil {
		klog.Errorf("Ignoring invalid HostSubnet %s: %v", common.HostSubnetToString(hs), err)
		return
	}

	if err := hsw.updateHostSubnet(hs); err != nil {
		klog.Errorf("Error processing new/updated HostSubnet: %v", err)
	}
}

func (hsw *hostSubnetWatcher) handleDeleteHostSubnet(obj interface{}) {
	hs := obj.(*osdnv1.HostSubnet)
	klog.V(5).Infof("Watch %s event for HostSubnet %q", watch.Deleted, hs.Name)

	if err := hsw.deleteHostSubnet(hs); err != nil {
		klog.Errorf("Error processing deleted HostSubnet: %v", err)
	}
}

func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func (hsw *hostSubnetWatcher) updateHostSubnet(hs *osdnv1.HostSubnet) error {
	phs, err := hsw.sdnConfig.ParseHostSubnet(hs)
	if err != nil {
		return fmt.Errorf("ignoring invalid subnet for node %s: %v", hs.Host, err)
	}

	if phs.HostIPs[0].Equal(hsw.localIPs[0]) {
		return nil
	}
	oldSubnet, exists := hsw.hostSubnetMap[hs.UID]
	if exists {
		if ipsEqual(oldSubnet.HostIPs, phs.HostIPs) {
			return nil
		} else {
			// Delete old subnet rules (ignore errors)
			hsw.oc.DeleteHostSubnetRules(hs)
		}
	}
	if err := hsw.sdnConfig.ValidateNodeIP(phs.HostIPs[0].String()); err != nil {
		return fmt.Errorf("ignoring invalid subnet for node %s: %v", phs.HostIPs[0].String(), err)
	}

	hsw.hostSubnetMap[hs.UID] = phs

	errList := []error{}
	if err := hsw.oc.AddHostSubnetRules(hs); err != nil {
		errList = append(errList, fmt.Errorf("error adding OVS flows for subnet %q: %v", hs.Subnet, err))
	}
	// Update multicast rules after all other changes have been processed
	if err := hsw.updateVXLANMulticastRules(); err != nil {
		errList = append(errList, fmt.Errorf("error updating OVS VXLAN multicast flows: %v", err))
	}

	return kerrors.NewAggregate(errList)
}

func (hsw *hostSubnetWatcher) deleteHostSubnet(hs *osdnv1.HostSubnet) error {
	phs, err := hsw.sdnConfig.ParseHostSubnet(hs)
	if err != nil {
		return fmt.Errorf("ignoring invalid subnet for node %s: %v", hs.Host, err)
	}

	if phs.HostIPs[0].Equal(hsw.localIPs[0]) {
		return nil
	}
	if _, exists := hsw.hostSubnetMap[hs.UID]; !exists {
		return nil
	}

	delete(hsw.hostSubnetMap, hs.UID)

	errList := []error{}
	if err := hsw.oc.DeleteHostSubnetRules(hs); err != nil {
		errList = append(errList, fmt.Errorf("error deleting OVS flows for subnet %q: %v", hs.Subnet, err))
	}
	if err := hsw.updateVXLANMulticastRules(); err != nil {
		errList = append(errList, fmt.Errorf("error updating OVS VXLAN multicast flows: %v", err))
	}

	return kerrors.NewAggregate(errList)
}

func (hsw *hostSubnetWatcher) updateVXLANMulticastRules() error {
	remoteIPs := make([]string, 0, len(hsw.hostSubnetMap))
	for _, phs := range hsw.hostSubnetMap {
		remoteIPs = append(remoteIPs, phs.HostIPs[0].String())
	}
	return hsw.oc.UpdateVXLANMulticastFlows(remoteIPs)
}
