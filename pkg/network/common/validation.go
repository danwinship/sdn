package common

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/api/validation/path"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/core/validation"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
)

func validateCIDRv4(cidr string) (*net.IPNet, error) {
	ipnet, err := networkutils.ParseCIDRMask(cidr)
	if err != nil {
		return nil, err
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("must be an IPv4 network")
	}
	return ipnet, nil
}

func validateIPv4(ip string) (net.IP, error) {
	bytes := net.ParseIP(ip)
	if bytes == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	if bytes.To4() == nil {
		return nil, fmt.Errorf("must be an IPv4 address")
	}
	return bytes, nil
}

// ValidateHostSubnet checks if the system-maintained fields of hostsubnet are valid.
// Note that these are required to be IPv4-only by the CRD, and that ValidateHostSubnet
// does not validate the IPv6-specific annotations.
func ValidateHostSubnet(hs *osdnv1.HostSubnet) error {
	allErrs := validation.ValidateObjectMeta(&hs.ObjectMeta, false, path.ValidatePathSegmentName, field.NewPath("metadata"))

	if hs.Host != hs.Name {
		allErrs = append(allErrs, field.Invalid(field.NewPath("host"), hs.Host, fmt.Sprintf("must be the same as metadata.name: %q", hs.Name)))
	}

	if hs.Subnet == "" {
		// check if annotation exists, then let the Subnet field be empty
		if _, ok := hs.Annotations[osdnv1.AssignHostSubnetAnnotation]; !ok {
			allErrs = append(allErrs, field.Invalid(field.NewPath("subnet"), hs.Subnet, "field cannot be empty"))
		}
	} else {
		_, err := validateCIDRv4(hs.Subnet)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("subnet"), hs.Subnet, err.Error()))
		}
	}
	_, err := validateIPv4(hs.HostIP)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("hostIP"), hs.HostIP, "invalid IP address"))
	}

	if len(allErrs) > 0 {
		return allErrs.ToAggregate()
	} else {
		return nil
	}
}

// ValidateHostSubnetEgress checks if the egress-related fields of hostsubnet are valid.
// Note that these are required to be IPv4-only by the CRD.
func ValidateHostSubnetEgress(hs *osdnv1.HostSubnet) error {
	allErrs := validation.ValidateObjectMeta(&hs.ObjectMeta, false, path.ValidatePathSegmentName, field.NewPath("metadata"))

	for i, egressIP := range hs.EgressIPs {
		if _, err := validateIPv4(string(egressIP)); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("egressIPs").Index(i), egressIP, err.Error()))
		}
	}

	for i, egressCIDR := range hs.EgressCIDRs {
		if _, err := validateCIDRv4(string(egressCIDR)); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("egressCIDRs").Index(i), egressCIDR, err.Error()))
		}
	}

	if len(allErrs) > 0 {
		return allErrs.ToAggregate()
	}

	return nil
}

func cidrsOverlap(cidr1, cidr2 *net.IPNet) bool {
	return cidr1.Contains(cidr2.IP) || cidr2.Contains(cidr1.IP)
}
