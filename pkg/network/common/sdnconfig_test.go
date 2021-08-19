package common

import (
	"net"
	"reflect"
	"strings"
	"testing"

	osdnv1 "github.com/openshift/api/network/v1"
	operv1 "github.com/openshift/api/operator/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
)

func TestCheckHostNetworks(t *testing.T) {
	hostIPNets := []*net.IPNet{
		mustParseCIDR("10.0.0.0/9"),
		mustParseCIDR("172.20.0.0/16"),
	}

	tests := []struct {
		name        string
		cfg         operv1.NetworkSpec
		expectError bool
	}{
		{
			name: "valid",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
			expectError: false,
		},
		{
			name: "valid multiple networks",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 24},
					{CIDR: "15.128.0.0/14", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
			expectError: false,
		},
		{
			name: "hostIPNet inside ClusterNetwork",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.0.0.0/8", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
			expectError: true,
		},
		{
			name: "ClusterNetwork inside hostIPNet",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.1.0.0/16", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
			expectError: true,
		},
		{
			name: "hostIPNet inside ServiceNetwork",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.0.0.0/8",
				},
			},
			expectError: true,
		},
		{
			name: "ServiceNetwork inside hostIPNet",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.20.30.0/24",
				},
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		cfg := &operv1.Network{Spec: test.cfg}
		cfg.Spec.DefaultNetwork = operv1.DefaultNetworkDefinition{
			Type: operv1.NetworkTypeOpenShiftSDN,
			OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
				Mode: operv1.SDNModeNetworkPolicy,
			},
		}
		sdnConfig, err := ParseSDNConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error parsing sdnConfig %q: %v", test.name, err)
		}

		err = sdnConfig.CheckHostNetworks(hostIPNets)
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
		name string
		cfg  operv1.NetworkSpec
		errs []string
	}{
		{
			name: "valid",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
			errs: []string{},
		},
		{
			name: "Subnet 10.130.0.0/23 and Pod 10.130.0.10 outside of ClusterNetwork",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/15", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/16",
				},
			},
			errs: []string{"10.130.0.0/23", "10.130.0.10"},
		},
		{
			name: "Service 172.30.99.99 outside of ServiceNetwork",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "10.128.0.0/14", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"172.30.0.0/24",
				},
			},
			errs: []string{"172.30.99.99"},
		},
		{
			name: "Too-many-error truncation",
			cfg: operv1.NetworkSpec{
				ClusterNetwork: []operv1.ClusterNetworkEntry{
					{CIDR: "1.2.3.0/24", HostPrefix: 24},
				},
				ServiceNetwork: []string{
					"4.5.6.0/24",
				},
			},
			errs: []string{"10.128.0.0/23", "10.129.0.0/23", "10.130.0.0/23", "10.128.0.2", "10.128.0.4", "10.128.0.6", "10.128.0.8", "10.129.0.3", "10.129.0.5", "10.129.0.7", "172.30.0.1", "too many errors"},
		},
	}

	for _, test := range tests {
		cfg := &operv1.Network{Spec: test.cfg}
		cfg.Spec.DefaultNetwork = operv1.DefaultNetworkDefinition{
			Type: operv1.NetworkTypeOpenShiftSDN,
			OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
				Mode: operv1.SDNModeNetworkPolicy,
			},
		}
		sdnConfig, err := ParseSDNConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error parsing sdnConfig %q: %v", test.name, err)
		}

		err = sdnConfig.CheckClusterObjects(subnets, pods, services)
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
		cfg  operv1.Network
		err  string
	}{
		{
			name: "valid single cidr",
			cfg: operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						Type: operv1.NetworkTypeOpenShiftSDN,
						OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
							Mode: operv1.SDNModeNetworkPolicy,
						},
					},
					ClusterNetwork: []operv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/16", HostPrefix: 24},
					},
					ServiceNetwork: []string{
						"172.30.0.0/16",
					},
				},
			},
			err: "",
		},
		{
			name: "valid multiple cidr",
			cfg: operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						Type: operv1.NetworkTypeOpenShiftSDN,
						OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
							Mode: operv1.SDNModeNetworkPolicy,
						},
					},
					ClusterNetwork: []operv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/16", HostPrefix: 24},
						{CIDR: "10.4.0.0/16", HostPrefix: 24},
					},
					ServiceNetwork: []string{
						"172.30.0.0/16",
					},
				},
			},
			err: "",
		},
		{
			name: "invalid CIDR address",
			cfg: operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						Type: operv1.NetworkTypeOpenShiftSDN,
						OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
							Mode: operv1.SDNModeNetworkPolicy,
						},
					},
					ClusterNetwork: []operv1.ClusterNetworkEntry{
						{CIDR: "Invalid", HostPrefix: 24},
					},
					ServiceNetwork: []string{
						"172.30.0.0/16",
					},
				},
			},
			err: "Invalid",
		},
		{
			name: "invalid serviceNetwork",
			cfg: operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						Type: operv1.NetworkTypeOpenShiftSDN,
						OpenShiftSDNConfig: &operv1.OpenShiftSDNConfig{
							Mode: operv1.SDNModeNetworkPolicy,
						},
					},
					ClusterNetwork: []operv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/16", HostPrefix: 24},
					},
					ServiceNetwork: []string{
						"172.30.0.0i/16",
					},
				},
			},
			err: "172.30.0.0i/16",
		},
	}
	for _, test := range tests {
		_, err := ParseSDNConfig(&test.cfg)
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

func TestParseHostSubnet(t *testing.T) {
	v4Config := NewTestSDNConfig(corev1.IPv4Protocol)
	v6Config := NewTestSDNConfig(corev1.IPv6Protocol)
	dsConfig := NewTestSDNConfig(corev1.IPv4Protocol, corev1.IPv6Protocol)

	tests := []struct {
		name string
		cfg  *SDNConfig
		hs   osdnv1.HostSubnet
		phs  ParsedHostSubnet

		err string
	}{
		{
			name: "valid",
			cfg: v4Config,
			hs: osdnv1.HostSubnet{
				HostIP: "10.0.0.1",
				Subnet: "10.128.0.0/23",
			},
			phs: ParsedHostSubnet{
				HostIPs: []net.IP{
					net.ParseIP("10.0.0.1"),
				},
				Subnets: []*net.IPNet{
					mustParseCIDR("10.128.0.0/23"),
				},
			},
		},
		{
			name: "bad HostIP",
			cfg: v4Config,
			hs: osdnv1.HostSubnet{
				HostIP: "10.0.0.1/24",
				Subnet: "10.128.0.0/23",
			},
			err: "bad HostIP",
		},
		{
			name: "IPv6 IP in single-stack IPv4",
			cfg: v4Config,
			hs: osdnv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						HostSubnetIPv6HostIPAnnotation: "fd00::1234",
					},
				},
				HostIP: "10.0.0.1",
				Subnet: "10.128.0.0/23",
			},
			err: "wrong family",
		},
		{
			name: "valid IPv6",
			cfg: v6Config,
			hs: osdnv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						HostSubnetIPv6HostIPAnnotation: "fd00::1234",
						HostSubnetIPv6SubnetAnnotation: "fd01::/64",
					},
				},
				HostIP: "0.0.0.0",
				Subnet: "0.0.0.0/0",
			},
			phs: ParsedHostSubnet{
				HostIPs: []net.IP{
					net.ParseIP("fd00::1234"),
				},
				Subnets: []*net.IPNet{
					mustParseCIDR("fd01::/64"),
				},
			},
		},
		{
			name: "valid dual-stack",
			cfg: dsConfig,
			hs: osdnv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						HostSubnetIPv6HostIPAnnotation: "fd00::1234",
						HostSubnetIPv6SubnetAnnotation: "fd01::/64",
					},
				},
				HostIP: "10.0.0.1",
				Subnet: "10.128.0.0/23",
			},
			phs: ParsedHostSubnet{
				HostIPs: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("fd00::1234"),
				},
				Subnets: []*net.IPNet{
					mustParseCIDR("10.128.0.0/23"),
					mustParseCIDR("fd01::/64"),
				},
			},
		},
		{
			name: "bad Subnet",
			cfg: v4Config,
			hs: osdnv1.HostSubnet{
				HostIP: "10.0.0.1",
				Subnet: "10.128.0.0",
			},
			err: "bad Subnet",
		},
	}
	for _, test := range tests {
		phs, err := test.cfg.ParseHostSubnet(&test.hs)
		if err == nil {
			if test.err != "" {
				t.Fatalf("test %q unexpectedly did not get an error", test.name)
			}
			if !reflect.DeepEqual(&test.phs, phs) {
				t.Fatalf("test %q expected %s, got %s", test.name, &test.phs, phs)
			}
		} else {
			if test.err != "" && !strings.Contains(err.Error(), test.err) {
				t.Fatalf("test %q: error did not match %q: %v", test.name, test.err, err)
			} else if test.err == "" {
				t.Fatalf("test %q: error did not match %q: %v", test.name, test.err, err)
			}
		}
	}
}

func (phs *ParsedHostSubnet) String() string {
	b := strings.Builder{}
	b.WriteString("{Host:")
	b.WriteString(phs.Host)
	b.WriteString(", HostIPs:[")
	for i, ip := range phs.HostIPs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(ip.String())
	}
	b.WriteString("], Subnets:[")
	for i, cidr := range phs.Subnets {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(cidr.String())
	}
	b.WriteString("]}")
	return b.String()
}
