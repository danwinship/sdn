package unidler

import (
	"fmt"
	"net"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/metaproxier"
	"k8s.io/kubernetes/pkg/proxy/userspace"
	utilproxy "k8s.io/kubernetes/pkg/proxy/util"
	"k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	unidlingapi "github.com/openshift/api/unidling/v1alpha1"
)

type NeedPodsSignaler interface {
	// NeedPods signals that endpoint addresses are needed in order to
	// service a traffic coming to the given service and port
	NeedPods(serviceName types.NamespacedName, port string) error
}

type eventSignaler struct {
	recorder record.EventRecorder
}

func (sig *eventSignaler) NeedPods(serviceName types.NamespacedName, port string) error {
	// TODO: we need to fake this since upstream removed our handle to the ObjectReference
	// This *should* be sufficient for the unidling controller
	serviceRef := v1.ObjectReference{
		Kind:      "Service",
		Namespace: serviceName.Namespace,
		Name:      serviceName.Name,
	}

	// HACK: make the message different to prevent event aggregation
	sig.recorder.Eventf(&serviceRef, v1.EventTypeNormal, unidlingapi.NeedPodsReason, "The service-port %s:%s needs pods.", serviceRef.Name, port)

	return nil
}

// NewEventSignaler constructs a NeedPodsSignaler which signals by recording
// an event for the service with the "NeedPods" reason.
func NewEventSignaler(eventRecorder record.EventRecorder) NeedPodsSignaler {
	return &eventSignaler{
		recorder: eventRecorder,
	}
}

// NewUnidlerProxier creates a new Proxier for the given LoadBalancer and address which fires off
// unidling signals connections and traffic.  It is intended to be used as one half of a HybridProxier.
func NewUnidlerProxier(
	loadBalancer userspace.LoadBalancer,
	listenIP net.IP,
	iptables iptables.Interface,
	exec utilexec.Interface,
	pr utilnet.PortRange,
	syncPeriod, minSyncPeriod,
	udpIdleTimeout time.Duration,
	nodePortAddresses []string,
	signaler NeedPodsSignaler,
) (*userspace.Proxier, error) {
	newFunc := func(protocol v1.Protocol, ip net.IP, port int) (userspace.ProxySocket, error) {
		return newUnidlerSocket(protocol, ip, port, signaler)
	}
	return userspace.NewCustomProxier(loadBalancer, listenIP, iptables, exec, pr, syncPeriod, minSyncPeriod, udpIdleTimeout, nodePortAddresses, newFunc)
}

func NewDualStackUnidlerProxier(
	loadBalancer userspace.LoadBalancer,
	listenIPs [2]net.IP,
	iptables [2]iptables.Interface,
	exec utilexec.Interface,
	pr utilnet.PortRange,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	udpIdleTimeout time.Duration,
	nodePortAddresses []string,
	signaler NeedPodsSignaler,
) (proxy.Provider, error) {
	ipFamilyMap := utilproxy.MapCIDRsByIPFamily(nodePortAddresses)

	ipv4Proxier, err := NewUnidlerProxier(loadBalancer, listenIPs[0], iptables[0],
		exec, pr, syncPeriod, minSyncPeriod, udpIdleTimeout,
		ipFamilyMap[v1.IPv4Protocol], signaler)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
	}

	ipv6Proxier, err := NewUnidlerProxier(loadBalancer, listenIPs[1], iptables[1],
		exec, pr, syncPeriod, minSyncPeriod, udpIdleTimeout,
		ipFamilyMap[v1.IPv6Protocol], signaler)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
	}

	return metaproxier.NewMetaProxier(ipv4Proxier, ipv6Proxier), nil
}
