package node

import (
	"errors"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/pkg/util/sysctl"

	"github.com/vishvananda/netlink"
)

func (node *OsdnNode) alreadySetUp() error {
	l, err := netlink.LinkByName(Tun0)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	found := 0
	for _, addr := range addrs {
		for _, gwAddr := range node.nodeConfig.LocalGatewayIfAddrStrings {
			if addr.IPNet.String() == gwAddr {
				found++
			}
		}
	}
	if found != len(node.nodeConfig.LocalGateways) {
		return errors.New("local subnet gateway CIDR(s) not found")
	}

	routes, err := netlink.RouteList(l, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, clusterCIDR := range node.sdnConfig.ClusterNetworkCIDRStrings {
		found := false
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == clusterCIDR {
				found = true
				break
			}
		}
		if !found {
			return errors.New("cluster CIDR(s) not found")
		}
	}

	if !node.oc.AlreadySetUp() {
		return errors.New("plugin is not setup")
	}

	return nil
}

func deleteLocalSubnetRoute(device, localSubnetCIDR string) {
	// ~1 sec total
	backoff := utilwait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.25,
		Steps:    7,
	}
	err := utilwait.ExponentialBackoff(backoff, func() (bool, error) {
		l, err := netlink.LinkByName(device)
		if err != nil {
			return false, fmt.Errorf("could not get interface %s: %v", device, err)
		}
		routes, err := netlink.RouteList(l, netlink.FAMILY_ALL)
		if err != nil {
			return false, fmt.Errorf("could not get routes: %v", err)
		}
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == localSubnetCIDR {
				err = netlink.RouteDel(&route)
				if err != nil {
					return false, fmt.Errorf("could not delete route: %v", err)
				}
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		klog.Errorf("Error removing %s route from dev %s: %v; if the route appears later it will not be deleted.", localSubnetCIDR, device, err)
	}
}

func (node *OsdnNode) SetupSDN() (bool, map[string]podNetworkInfo, error) {
	// Make sure IPv4 forwarding state is 1
	if node.sdnConfig.HasIPv4 {
		sysctl := sysctl.New()
		val, err := sysctl.GetSysctl("net/ipv4/ip_forward")
		if err != nil {
			return false, nil, fmt.Errorf("could not get IPv4 forwarding state: %s", err)
		}
		if val != 1 {
			return false, nil, fmt.Errorf("net/ipv4/ip_forward=0, it must be set to 1")
		}
	}

	klog.V(5).Infof("[SDN setup] node pod subnet %v gateway %v", node.nodeConfig.LocalSubnetCIDRStrings, node.nodeConfig.LocalGatewayIPStrings)

	if err := healthCheckOVS(); err != nil {
		return false, nil, err
	}

	var changed bool
	existingPods, err := node.oc.GetPodNetworkInfo()
	if err != nil {
		klog.Warningf("[SDN setup] Could not get details of existing pods: %v", err)
	}

	if err := node.alreadySetUp(); err == nil {
		klog.Infof("[SDN setup] SDN is already set up")
	} else {
		klog.Infof("[SDN setup] full SDN setup required (%v)", err)
		if err := node.setup(); err != nil {
			return false, nil, err
		}
		changed = true
	}

	return changed, existingPods, nil
}

func (node *OsdnNode) FinishSetupSDN() error {
	err := node.oc.FinishSetupOVS()
	if err != nil {
		return err
	}
	return nil
}

func (node *OsdnNode) setup() error {
	if err := node.oc.SetupOVS(); err != nil {
		return err
	}

	l, err := netlink.LinkByName(Tun0)
	if err == nil {
		for i, gw := range node.nodeConfig.LocalGateways {
			err = netlink.AddrAdd(l, &netlink.Addr{IPNet: gw})
			if err != nil {
				break
			}
			defer deleteLocalSubnetRoute(Tun0, node.nodeConfig.LocalSubnetCIDRStrings[i])
		}
	}
	if err == nil {
		err = netlink.LinkSetUp(l)
	}
	if err == nil {
		for _, clusterNetwork := range node.sdnConfig.ClusterNetworks {
			route := &netlink.Route{
				LinkIndex: l.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       clusterNetwork.CIDR,
			}
			if err = netlink.RouteAdd(route); err != nil {
				return err
			}
		}
	}
	if err == nil {
		for _, serviceCIDR := range node.sdnConfig.ServiceNetworks {
			route := &netlink.Route{
				LinkIndex: l.Attrs().Index,
				Dst:       serviceCIDR,
			}
			err = netlink.RouteAdd(route)
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}

	return nil
}

func (node *OsdnNode) updateEgressNetworkPolicyRules(vnid uint32) {
	policies := node.egressPolicies[vnid]
	namespaces := node.policy.GetNamespaces(vnid)
	if err := node.oc.UpdateEgressNetworkPolicyRules(policies, vnid, namespaces, node.egressDNS); err != nil {
		klog.Errorf("Error updating OVS flows for EgressNetworkPolicy: %v", err)
	}
}

func (node *OsdnNode) AddServiceRules(service *corev1.Service, netID uint32) {
	klog.V(5).Infof("AddServiceRules for %v", service)
	if err := node.oc.AddServiceRules(service, netID); err != nil {
		klog.Errorf("Error adding OVS flows for service %v, netid %d: %v", service, netID, err)
	}
}

func (node *OsdnNode) DeleteServiceRules(service *corev1.Service) {
	klog.V(5).Infof("DeleteServiceRules for %v", service)
	if err := node.oc.DeleteServiceRules(service); err != nil {
		klog.Errorf("Error deleting OVS flows for service %v: %v", service, err)
	}
}
