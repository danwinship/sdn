// +build linux

package node

import (
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"

	networkapi "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
)

func assertHostSubnetFlowChanges(hsw *hostSubnetWatcher, flows *[]string, changes ...flowChange) error {
	oldFlows := *flows
	newFlows, err := hsw.oc.ovs.DumpFlows("")
	if err != nil {
		return fmt.Errorf("unexpected error dumping OVS flows: %v", err)
	}

	err = assertFlowChanges(oldFlows, newFlows, changes...)
	if err != nil {
		return fmt.Errorf("unexpected flow changes: %v\nOrig:\n%s\nNew:\n%s", err,
			strings.Join(oldFlows, "\n"), strings.Join(newFlows, "\n"))
	}

	*flows = newFlows
	return nil
}

func setupHostSubnetWatcher(t *testing.T, ipFamilies common.IPSupport) (*hostSubnetWatcher, []string) {
	_, oc, _ := setupOVSController(t, ipFamilies)

	var cn *networkapi.ClusterNetwork
	if ipFamilies.AllowsIPv4() {
		cn = &networkapi.ClusterNetwork{
			ClusterNetworks: []networkapi.ClusterNetworkEntry{
				{
					CIDR:             "10.128.0.0/14",
					HostSubnetLength: 9,
				},
			},
			ServiceNetwork: "172.30.0.0/16",
		}
	} else {
		cn = &networkapi.ClusterNetwork{
			ClusterNetworks: []networkapi.ClusterNetworkEntry{
				{
					CIDR:             "fd01::/48",
					HostSubnetLength: 64,
				},
			},
			ServiceNetwork: "fd02::/112",
		}
	}

	networkInfo, err := common.ParseClusterNetwork(cn)
	if err != nil {
		t.Fatalf("unexpected error parsing network info: %v", err)
	}

	hsw := newHostSubnetWatcher(oc, oc.localIPs[0], networkInfo)

	flows, err := hsw.oc.ovs.DumpFlows("")
	if err != nil {
		t.Fatalf("unexpected error dumping OVS flows: %v", err)
	}

	return hsw, flows
}

func makeHostSubnet(name, hostIP, subnet string) *networkapi.HostSubnet {
	return &networkapi.HostSubnet{
		TypeMeta: metav1.TypeMeta{
			Kind: "HostSubnet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  ktypes.UID(name + "-uid"),
		},
		Host:   name,
		HostIP: hostIP,
		Subnet: subnet,
	}
}

func TestHostSubnetWatcher(t *testing.T) {
	hsw, flows := setupHostSubnetWatcher(t, common.IPv4Support)

	hs1 := makeHostSubnet("node1", "192.168.0.2", "10.128.0.0/23")
	hs2 := makeHostSubnet("node2", "192.168.1.2", "10.129.0.0/23")

	err := hsw.updateHostSubnet(hs1)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_src=192.168.0.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=50", "arp", "arp_tpa=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ip", "nw_dst=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:    flowRemoved,
			match:   []string{"table=111", "goto_table:120"},
			noMatch: []string{"->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=111", "192.168.0.2->tun_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hsw.updateHostSubnet(hs2)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_src=192.168.1.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=50", "arp", "arp_tpa=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ip", "nw_dst=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=111", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=111", "192.168.0.2->tun_dst", "192.168.1.2->tun_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hsw.deleteHostSubnet(hs1)
	if err != nil {
		t.Fatalf("Unexpected error deleting HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=10", "tun_src=192.168.0.2"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=50", "arp", "arp_tpa=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=90", "ip", "nw_dst=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=111", "192.168.0.2->tun_dst", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=111", "192.168.1.2->tun_dst"},
			noMatch: []string{"192.168.0.2"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hsw.deleteHostSubnet(hs2)
	if err != nil {
		t.Fatalf("Unexpected error deleting HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=10", "tun_src=192.168.1.2"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=50", "arp", "arp_tpa=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=90", "ip", "nw_dst=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=111", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=111", "goto_table:120"},
			noMatch: []string{"tun_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestHostSubnetWatcherIPv6(t *testing.T) {
	hsw, flows := setupHostSubnetWatcher(t, common.IPv6Support)

	hs1 := makeHostSubnet("node1", "2600:5200::2", "fd01:0:0:1::/64")
	hs2 := makeHostSubnet("node2", "2600:5200::3", "fd01:0:0:2::/64")

	err := hsw.updateHostSubnet(hs1)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_ipv6_src=2600:5200::2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ipv6", "ipv6_dst=fd01:0:0:1::/64", "2600:5200::2->tun_ipv6_dst"},
		},
		flowChange{
			kind:    flowRemoved,
			match:   []string{"table=111", "goto_table:120"},
			noMatch: []string{"->tun_ipv6_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=111", "2600:5200::2->tun_ipv6_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hsw.updateHostSubnet(hs2)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_ipv6_src=2600:5200::3"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ipv6", "ipv6_dst=fd01:0:0:2::/64", "2600:5200::3->tun_ipv6_dst"},
		},
		flowChange{
			kind:    flowRemoved,
			match:   []string{"table=111", "2600:5200::2->tun_ipv6_dst"},
			noMatch: []string{"2600:5200::3->tun_ipv6_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=111", "2600:5200::2->tun_ipv6_dst", "2600:5200::3->tun_ipv6_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hsw.deleteHostSubnet(hs1)
	if err != nil {
		t.Fatalf("Unexpected error deleting HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=10", "tun_ipv6_src=2600:5200::2"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=90", "ipv6", "ipv6_dst=fd01:0:0:1::/64", "2600:5200::2->tun_ipv6_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=111", "2600:5200::2->tun_ipv6_dst", "2600:5200::3->tun_ipv6_dst"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=111", "2600:5200::3->tun_ipv6_dst"},
			noMatch: []string{"2600:5200::2"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hsw.deleteHostSubnet(hs2)
	if err != nil {
		t.Fatalf("Unexpected error deleting HostSubnet: %v", err)
	}
	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=10", "tun_ipv6_src=2600:5200::3"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=90", "ipv6", "ipv6_dst=fd01:0:0:2::/64", "2600:5200::3->tun_ipv6_dst"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=111", "2600:5200::3->tun_ipv6_dst"},
		},
		flowChange{
			kind:    flowAdded,
			match:   []string{"table=111", "goto_table:120"},
			noMatch: []string{"tun_ipv6_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestHostSubnetReassignment(t *testing.T) {
	hsw, flows := setupHostSubnetWatcher(t, common.IPv4Support)

	hs1orig := makeHostSubnet("node1", "192.168.0.2", "10.128.0.0/23")
	hs2orig := makeHostSubnet("node2", "192.168.1.2", "10.129.0.0/23")

	// Create original HostSubnets

	err := hsw.updateHostSubnet(hs1orig)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}
	err = hsw.updateHostSubnet(hs2orig)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}

	err = assertHostSubnetFlowChanges(hsw, &flows,
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_src=192.168.0.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_src=192.168.1.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=50", "arp", "arp_tpa=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=50", "arp", "arp_tpa=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ip", "nw_dst=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ip", "nw_dst=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:    flowRemoved,
			match:   []string{"table=111", "goto_table:120"},
			noMatch: []string{"->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=111", "192.168.0.2->tun_dst", "192.168.1.2->tun_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Now both nodes go offline (without their Node objects being deleted), reboot and
	// get assigned the opposite IPs after reboot. They reregister with the master, which
	// updates their Node IPs, which causes the SDN master to update their HostSubnets.
	// After the first update, we'll have two HostSubnets with the same HostIP, which
	// used to cause us to break things when we got the second update.

	hs1new := hs1orig.DeepCopy()
	hs1new.HostIP = hs2orig.HostIP
	hs2new := hs2orig.DeepCopy()
	hs2new.HostIP = hs1orig.HostIP

	err = hsw.updateHostSubnet(hs1new)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}
	err = hsw.updateHostSubnet(hs2new)
	if err != nil {
		t.Fatalf("Unexpected error adding HostSubnet: %v", err)
	}

	err = assertHostSubnetFlowChanges(hsw, &flows,
		// (We have to check for these table=10 removes+adds because they're not
		// actually identical; the cookies will have changed.)
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=10", "tun_src=192.168.0.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_src=192.168.0.2"},
		},
		flowChange{
			kind:  flowRemoved,
			match: []string{"table=10", "tun_src=192.168.1.2"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=10", "tun_src=192.168.1.2"},
		},

		flowChange{
			kind:  flowRemoved,
			match: []string{"table=50", "arp", "arp_tpa=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=50", "arp", "arp_tpa=10.128.0.0/23", "192.168.1.2->tun_dst"},
		},

		flowChange{
			kind:  flowRemoved,
			match: []string{"table=50", "arp", "arp_tpa=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=50", "arp", "arp_tpa=10.129.0.0/23", "192.168.0.2->tun_dst"},
		},

		flowChange{
			kind:  flowRemoved,
			match: []string{"table=90", "ip", "nw_dst=10.128.0.0/23", "192.168.0.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ip", "nw_dst=10.128.0.0/23", "192.168.1.2->tun_dst"},
		},

		flowChange{
			kind:  flowRemoved,
			match: []string{"table=90", "ip", "nw_dst=10.129.0.0/23", "192.168.1.2->tun_dst"},
		},
		flowChange{
			kind:  flowAdded,
			match: []string{"table=90", "ip", "nw_dst=10.129.0.0/23", "192.168.0.2->tun_dst"},
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
