package common

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/api/validation/path"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/core/validation"

	networkapi "github.com/openshift/api/network/v1"
)

// ValidateClusterNetwork tests if required fields in the ClusterNetwork are set, and ensures that the "default" ClusterNetwork can only be set to the correct values
func ValidateClusterNetwork(clusterNet *networkapi.ClusterNetwork) error {
	allErrs := validation.ValidateObjectMeta(&clusterNet.ObjectMeta, false, path.ValidatePathSegmentName, field.NewPath("metadata"))

	// Figure out if this is an IPv4 or IPv6 cluster
	firstClusterNetwork := ""
	if len(clusterNet.ClusterNetworks) > 0 {
		firstClusterNetwork = clusterNet.ClusterNetworks[0].CIDR
	} else {
		firstClusterNetwork = clusterNet.Network
	}
	version := ParseIPVersion(firstClusterNetwork)

	serviceIPNet, err := ParseCIDRv(clusterNet.ServiceNetwork, version)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("serviceNetwork"), clusterNet.ServiceNetwork, err.Error()))
	}

	var testedCIDRS []*net.IPNet
	if len(clusterNet.ClusterNetworks) == 0 {
		// legacy ClusterNetwork; old fields must be set
		if clusterNet.Network == "" {
			allErrs = append(allErrs, field.Required(field.NewPath("network"), "network must be set (if clusterNetworks is empty)"))
		} else if clusterNet.HostSubnetLength == 0 {
			allErrs = append(allErrs, field.Required(field.NewPath("hostsubnetlength"), "hostsubnetlength must be set (if clusterNetworks is empty)"))
		} else {
			clusterIPNet, err := ParseCIDRv(clusterNet.Network, version)
			if err != nil {
				allErrs = append(allErrs, field.Invalid(field.NewPath("network"), clusterNet.Network, err.Error()))
			}
			maskLen, addrLen := clusterIPNet.Mask.Size()
			if clusterNet.HostSubnetLength > uint32(addrLen-maskLen) {
				allErrs = append(allErrs, field.Invalid(field.NewPath("hostsubnetlength"), clusterNet.HostSubnetLength, "subnet length is too large for cidr"))
			} else if clusterNet.HostSubnetLength < 2 {
				allErrs = append(allErrs, field.Invalid(field.NewPath("hostsubnetlength"), clusterNet.HostSubnetLength, "subnet length must be at least 2"))
			}

			if (clusterIPNet != nil) && (serviceIPNet != nil) && cidrsOverlap(clusterIPNet, serviceIPNet) {
				allErrs = append(allErrs, field.Invalid(field.NewPath("serviceNetwork"), clusterNet.ServiceNetwork, "service network overlaps with cluster network"))
			}
		}
	} else {
		// "new" ClusterNetwork
		if clusterNet.Name == networkapi.ClusterNetworkDefault {
			if clusterNet.Network != clusterNet.ClusterNetworks[0].CIDR {
				allErrs = append(allErrs, field.Invalid(field.NewPath("network"), clusterNet.Network, "network must be identical to clusterNetworks[0].cidr"))
			}
			if clusterNet.HostSubnetLength != clusterNet.ClusterNetworks[0].HostSubnetLength {
				allErrs = append(allErrs, field.Invalid(field.NewPath("hostsubnetlength"), clusterNet.HostSubnetLength, "hostsubnetlength must be identical to clusterNetworks[0].hostSubnetLength"))
			}
		} else if clusterNet.Network != "" || clusterNet.HostSubnetLength != 0 {
			if clusterNet.Network != clusterNet.ClusterNetworks[0].CIDR || clusterNet.HostSubnetLength != clusterNet.ClusterNetworks[0].HostSubnetLength {
				allErrs = append(allErrs, field.Invalid(field.NewPath("clusterNetworks").Index(0), clusterNet.ClusterNetworks[0], "network and hostsubnetlength must be unset or identical to clusterNetworks[0]"))
			}
		}
	}

	for i, cn := range clusterNet.ClusterNetworks {
		clusterIPNet, err := ParseCIDRv(cn.CIDR, version)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("clusterNetworks").Index(i).Child("cidr"), cn.CIDR, err.Error()))
			continue
		}
		maskLen, addrLen := clusterIPNet.Mask.Size()
		if cn.HostSubnetLength > uint32(addrLen-maskLen) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("clusterNetworks").Index(i).Child("hostSubnetLength"), cn.HostSubnetLength, "subnet length is too large for clusterNetwork "))
		} else if cn.HostSubnetLength < 2 {
			allErrs = append(allErrs, field.Invalid(field.NewPath("clusterNetworks").Index(i).Child("hostSubnetLength"), cn.HostSubnetLength, "subnet length must be at least 2"))
		}

		for _, cidr := range testedCIDRS {
			if cidrsOverlap(clusterIPNet, cidr) {
				allErrs = append(allErrs, field.Invalid(field.NewPath("clusterNetworks").Index(i).Child("cidr"), cn.CIDR, fmt.Sprintf("cidr range overlaps with another cidr %q", cidr.String())))
			}
		}
		testedCIDRS = append(testedCIDRS, clusterIPNet)

		if (clusterIPNet != nil) && (serviceIPNet != nil) && cidrsOverlap(clusterIPNet, serviceIPNet) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("serviceNetwork"), clusterNet.ServiceNetwork, fmt.Sprintf("service network overlaps with cluster network cidr: %s", clusterIPNet.String())))
		}
	}

	if clusterNet.VXLANPort != nil {
		for _, msg := range utilvalidation.IsValidPortNum(int(*clusterNet.VXLANPort)) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("vxlanPort"), clusterNet.VXLANPort, msg))
		}
	}

	if len(allErrs) > 0 {
		return allErrs.ToAggregate()
	} else {
		return nil
	}
}

func ValidateHostSubnet(hs *networkapi.HostSubnet, version IPVersion) error {
	allErrs := validation.ValidateObjectMeta(&hs.ObjectMeta, false, path.ValidatePathSegmentName, field.NewPath("metadata"))

	if hs.Host != hs.Name {
		allErrs = append(allErrs, field.Invalid(field.NewPath("host"), hs.Host, fmt.Sprintf("must be the same as metadata.name: %q", hs.Name)))
	}

	if hs.Subnet == "" {
		// check if annotation exists, then let the Subnet field be empty
		if _, ok := hs.Annotations[networkapi.AssignHostSubnetAnnotation]; !ok {
			allErrs = append(allErrs, field.Invalid(field.NewPath("subnet"), hs.Subnet, "field cannot be empty"))
		}
	} else {
		_, err := ParseCIDRv(hs.Subnet, version)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("subnet"), hs.Subnet, err.Error()))
		}
	}
	if _, err := ParseIPv(hs.HostIP, version); err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("hostIP"), hs.HostIP, err.Error()))
	}

	for i, egressIP := range hs.EgressIPs {
		if _, err := ParseIPv(egressIP, version); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("egressIPs").Index(i), egressIP, err.Error()))
		}
	}

	for i, egressCIDR := range hs.EgressCIDRs {
		if _, err := ParseCIDRv(egressCIDR, version); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("egressCIDRs").Index(i), egressCIDR, err.Error()))
		}
	}

	if len(allErrs) > 0 {
		return allErrs.ToAggregate()
	} else {
		return nil
	}
}

func cidrsOverlap(cidr1, cidr2 *net.IPNet) bool {
	return cidr1.Contains(cidr2.IP) || cidr2.Contains(cidr1.IP)
}
