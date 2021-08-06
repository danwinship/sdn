package common

import (
	"net"
	"strings"
	"testing"

	osdnv1 "github.com/openshift/api/network/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
)

func TestCheckHostNetworks(t *testing.T) {
	hostIPNets := []*net.IPNet{
		mustParseCIDR("10.0.0.0/9"),
		mustParseCIDR("172.20.0.0/16"),
	}

	tests := []struct {
		name        string
		sdnConfig   *SDNConfig
		expectError bool
	}{
		{
			name: "valid",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
			},
			expectError: false,
		},
		{
			name: "valid multiple networks",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
					{ClusterCIDR: mustParseCIDR("15.128.0.0/14"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
			},
			expectError: false,
		},
		{
			name: "hostIPNet inside ClusterNetwork",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.0.0.0/8"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
			},
			expectError: true,
		},
		{
			name: "ClusterNetwork inside hostIPNet",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.1.0.0/16"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
			},
			expectError: true,
		},
		{
			name: "hostIPNet inside ServiceNetwork",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.0.0.0/8"),
			},
			expectError: true,
		},
		{
			name: "ServiceNetwork inside hostIPNet",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.20.30.0/8"),
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		err := test.sdnConfig.CheckHostNetworks(hostIPNets)
		if test.expectError {
			if err == nil {
				t.Fatalf("unexpected lack of error checking %q", test.name)
			}
		} else {
			if err != nil {
				t.Fatalf("unexpected error checking %q: %v", test.name, err)
			}
		}
	}
}

func dummySubnet(hostip string, subnet string) osdnv1.HostSubnet {
	return osdnv1.HostSubnet{HostIP: hostip, Subnet: subnet}
}

func dummyService(ip string) corev1.Service {
	return corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: ip}}
}

func dummyPod(ip string) corev1.Pod {
	return corev1.Pod{Status: corev1.PodStatus{PodIP: ip}}
}

func Test_checkClusterObjects(t *testing.T) {
	subnets := []osdnv1.HostSubnet{
		dummySubnet("192.168.1.2", "10.128.0.0/23"),
		dummySubnet("192.168.1.3", "10.129.0.0/23"),
		dummySubnet("192.168.1.4", "10.130.0.0/23"),
	}
	pods := []corev1.Pod{
		dummyPod("10.128.0.2"),
		dummyPod("10.128.0.4"),
		dummyPod("10.128.0.6"),
		dummyPod("10.128.0.8"),
		dummyPod("10.129.0.3"),
		dummyPod("10.129.0.5"),
		dummyPod("10.129.0.7"),
		dummyPod("10.129.0.9"),
		dummyPod("10.130.0.10"),
	}
	services := []corev1.Service{
		dummyService("172.30.0.1"),
		dummyService("172.30.0.128"),
		dummyService("172.30.99.99"),
		dummyService("None"),
	}

	tests := []struct {
		name      string
		sdnConfig *SDNConfig
		errs      []string
	}{
		{
			name: "valid",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
			},
			errs: []string{},
		},
		{
			name: "Subnet 10.130.0.0/23 and Pod 10.130.0.10 outside of ClusterNetwork",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/15"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/16"),
			},
			errs: []string{"10.130.0.0/23", "10.130.0.10"},
		},
		{
			name: "Service 172.30.99.99 outside of ServiceNetwork",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("10.128.0.0/14"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("172.30.0.0/24"),
			},
			errs: []string{"172.30.99.99"},
		},
		{
			name: "Too-many-error truncation",
			sdnConfig: &SDNConfig{
				ClusterNetworks: []ParsedClusterNetworkEntry{
					{ClusterCIDR: mustParseCIDR("1.2.3.0/24"), HostSubnetLength: 8},
				},
				ServiceNetwork: mustParseCIDR("4.5.6.0/24"),
			},
			errs: []string{"10.128.0.0/23", "10.129.0.0/23", "10.130.0.0/23", "10.128.0.2", "10.128.0.4", "10.128.0.6", "10.128.0.8", "10.129.0.3", "10.129.0.5", "10.129.0.7", "172.30.0.1", "too many errors"},
		},
	}

	for _, test := range tests {
		err := test.sdnConfig.CheckClusterObjects(subnets, pods, services)
		if err == nil {
			if len(test.errs) > 0 {
				t.Fatalf("test %q unexpectedly did not get an error", test.name)
			}
			continue
		}
		errs := err.(kerrors.Aggregate).Errors()
		if len(errs) != len(test.errs) {
			t.Fatalf("test %q expected %d errors, got %v", test.name, len(test.errs), err)
		}
		for i, match := range test.errs {
			if !strings.Contains(errs[i].Error(), match) {
				t.Fatalf("test %q: error %d did not match %q: %v", test.name, i, match, errs[i])
			}
		}
	}
}

func TestParseSDNConfig(t *testing.T) {
	tests := []struct {
		name string
		cn   osdnv1.ClusterNetwork
		err  string
	}{
		{
			name: "valid single cidr",
			cn: osdnv1.ClusterNetwork{
				ClusterNetworks: []osdnv1.ClusterNetworkEntry{{CIDR: "10.0.0.0/16"}},
				ServiceNetwork:  "172.30.0.0/16",
			},
			err: "",
		},
		{
			name: "valid multiple cidr",
			cn: osdnv1.ClusterNetwork{
				ClusterNetworks: []osdnv1.ClusterNetworkEntry{{CIDR: "10.0.0.0/16"}, {CIDR: "10.4.0.0/16"}},
				ServiceNetwork:  "172.30.0.0/16",
			},
			err: "",
		},
		{
			name: "invalid CIDR address",
			cn: osdnv1.ClusterNetwork{
				ClusterNetworks: []osdnv1.ClusterNetworkEntry{{CIDR: "Invalid"}},
				ServiceNetwork:  "172.30.0.0/16",
			},
			err: "Invalid",
		},
		{
			name: "invalid serviceNetwork",
			cn: osdnv1.ClusterNetwork{
				ClusterNetworks: []osdnv1.ClusterNetworkEntry{{CIDR: "10.0.0.0/16"}},
				ServiceNetwork:  "172.30.0.0i/16",
			},
			err: "172.30.0.0i/16",
		},
	}
	for _, test := range tests {
		_, err := ParseSDNConfig(&test.cn)
		if err == nil {
			if len(test.err) > 0 {
				t.Fatalf("test %q unexpectedly did not get an error", test.name)
			}
		} else {
			if !strings.Contains(err.Error(), test.err) {
				t.Fatalf("test %q: error did not match %q: %v", test.name, test.err, err)
			}
		}
	}
}
