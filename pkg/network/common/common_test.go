package common

import (
	"net"
	"strings"
	"testing"

	osdnv1 "github.com/openshift/api/network/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mustParseCIDR(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("bad CIDR string constant " + cidr)
	}
	return net
}

func TestGenerateGateway(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("10.1.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	gatewayIP := GenerateDefaultGateway(ipNet)
	if gatewayIP.String() != "10.1.0.1" {
		t.Fatalf("Did not get expected gateway IP Address (gatewayIP=%s)", gatewayIP.String())
	}
}

func TestValidateHostSubnetEgress(t *testing.T) {
	tests := []struct {
		name string
		hs   osdnv1.HostSubnet
		err  string
	}{
		{
			name: "valid egress ip",
			hs: osdnv1.HostSubnet{
				EgressIPs:   []osdnv1.HostSubnetEgressIP{"10.0.0.10", "10.0.0.11"},
				EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"10.0.0.0/16"},
				ObjectMeta:  metav1.ObjectMeta{Name: "any"},
			},
			err: "",
		},
		{
			name: "valid egress cidr",
			hs: osdnv1.HostSubnet{
				EgressIPs:   []osdnv1.HostSubnetEgressIP{"10.0.0.10", "10.0.0.11"},
				EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"10.0.0.0/16"},
				ObjectMeta:  metav1.ObjectMeta{Name: "any"},
			},
			err: "",
		},
		{
			name: "invalid CIDR address",
			hs: osdnv1.HostSubnet{
				EgressIPs:   []osdnv1.HostSubnetEgressIP{"10.0.0.10", "10.0.0.11"},
				EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"10.139.125.80/27"},
				ObjectMeta:  metav1.ObjectMeta{Name: "any"},
			},
			err: "Invalid",
		},
		{
			name: "invalid egress ip",
			hs: osdnv1.HostSubnet{
				EgressIPs:   []osdnv1.HostSubnetEgressIP{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
				EgressCIDRs: []osdnv1.HostSubnetEgressCIDR{"10.139.125.64/27"},
				ObjectMeta:  metav1.ObjectMeta{Name: "any"},
			},
			err: "Invalid",
		},
	}
	for _, test := range tests {
		err := ValidateHostSubnetEgress(&test.hs)
		if err == nil {
			if len(test.err) > 0 {
				t.Fatalf("test %q unexpectedly did not get an error", test.name)
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
