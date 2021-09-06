package proxy

import (
	"sync"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/util/async"
	utilnet "k8s.io/utils/net"

	unidlingapi "github.com/openshift/api/unidling/v1alpha1"
)

// HybridizableProxy is an extra interface we layer on top of Provider
type HybridizableProxy interface {
	proxy.Provider

	SyncProxyRules()
	SetSyncRunner(b *async.BoundedFrequencyRunner)

	ReloadIPTables()
}

// hybridProxierService is our cached state for a given Service/Endpoints.
//
// A running Service can be in one of three states:
//
//   - Not Idled (known to the mainProxy but not the unidlingProxy). A Not Idled Service
//     becomes Idled when its Service gets annotated and its Endpoints is empty. (Both
//     conditions must be true.)
//
//   - Idled (known to the unidlingProxy but not the mainProxy). An Idled Service becomes
//     Unidling when either its Service annotation is removed or its Endpoints become
//     non-empty.
//
//   - Unidling (the Service and Endpoints are known to the mainProxy, and the Endpoints
//     are known to the unidling proxy). While a Service is Unidling, Endpoints events are
//     sent to both proxies (so the unidling proxy socket can redirect its connection to
//     the correct place). An Unidling Service becomes Not Idled if its Endpoints are
//     deleted, or else the next time it receives an Endpoints event more than 1 minute
//     after becoming Unidling. (Alternatively it could also become Idled again.)
type hybridProxierService struct {
	// What we know about the Service
	knownService             bool
	serviceHasIdleAnnotation bool

	// What we know about the Endpoints/EndpointSlices; these are ints rather
	// than booleans because a Service may have multiple slices
	knownEndpoints int
	emptyEndpoints int

	// In the Unidling state, we only track the first EndpointSlice to have appeared
	v4UnidlingSlice string
	v6UnidlingSlice string

	// idling/unidling state
	isIdled   bool
	unidledAt *time.Time
}

const unidlingEndpointsLag = time.Minute

func (hsvc *hybridProxierService) shouldBeIdled() bool {
	return hsvc.serviceHasIdleAnnotation && hsvc.knownEndpoints > 0 && (hsvc.emptyEndpoints == hsvc.knownEndpoints)
}

func (hsvc *hybridProxierService) unidlingProxyWantsEndpoints() bool {
	return hsvc.isIdled || (hsvc.unidledAt != nil && time.Since(*hsvc.unidledAt) < unidlingEndpointsLag)
}

func (hsvc *hybridProxierService) unidlingPeriodHasExpired() bool {
	return hsvc.unidledAt != nil && !hsvc.unidlingProxyWantsEndpoints()
}

func (hsvc *hybridProxierService) unidlingSlicePtr(slice *discoveryv1.EndpointSlice) *string {
	if slice.AddressType == discoveryv1.AddressTypeIPv4 {
		return &hsvc.v4UnidlingSlice
	} else if slice.AddressType == discoveryv1.AddressTypeIPv6 {
		return &hsvc.v6UnidlingSlice
	} else {
		dummy := ""
		return &dummy
	}
}

// HybridProxier runs an unidling proxy and a primary proxy at the same time,
// delegating idled services to the unidling proxy and other services to the
// primary proxy.
type HybridProxier struct {
	mainProxy       HybridizableProxy
	unidlingProxies []HybridizableProxy
	v4UnidlingProxy HybridizableProxy
	v6UnidlingProxy HybridizableProxy

	serviceLister corev1listers.ServiceLister
	syncRunner    *async.BoundedFrequencyRunner

	serviceLock sync.Mutex
	services    map[types.NamespacedName]*hybridProxierService
}

func NewHybridProxier(
	mainProxy HybridizableProxy,
	v4UnidlingProxy HybridizableProxy,
	v6UnidlingProxy HybridizableProxy,
	minSyncPeriod time.Duration,
	serviceLister corev1listers.ServiceLister,
) *HybridProxier {
	p := &HybridProxier{
		mainProxy:       mainProxy,
		v4UnidlingProxy: v4UnidlingProxy,
		v6UnidlingProxy: v6UnidlingProxy,

		serviceLister: serviceLister,

		services: make(map[types.NamespacedName]*hybridProxierService),
	}
	if v4UnidlingProxy != nil {
		p.unidlingProxies = append(p.unidlingProxies, v4UnidlingProxy)
	}
	if v6UnidlingProxy != nil {
		p.unidlingProxies = append(p.unidlingProxies, v6UnidlingProxy)
	}

	p.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", p.syncProxyRules, minSyncPeriod, time.Hour, 4)

	// Hackery abound: we want to make sure that changes are applied
	// to both proxies at approximately the same time. That means that we
	// need to stop the two proxy's independent loops and take them over.
	mainProxy.SetSyncRunner(p.syncRunner)
	for _, unidlingProxy := range p.unidlingProxies {
		unidlingProxy.SetSyncRunner(p.syncRunner)
	}

	return p
}

func (proxier *HybridProxier) OnNodeAdd(node *corev1.Node) {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

func (proxier *HybridProxier) OnNodeUpdate(oldNode, node *corev1.Node) {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

func (proxier *HybridProxier) OnNodeDelete(node *corev1.Node) {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

func (proxier *HybridProxier) OnNodeSynced() {
	// TODO implement https://github.com/kubernetes/enhancements/pull/640
}

func emptyEndpoints(meta *metav1.ObjectMeta) *corev1.Endpoints {
	return &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: *meta,
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{},
				Ports:     []corev1.EndpointPort{},
			},
		},
	}
}

// serviceForProxy returns either svc, a copy of it, or nil, ensuring that ClusterIP is of
// the correct family for unidlingProxy. It does not make any attempt to fix up the other
// dual-stack-related fields, so the returned Service may be invalid according to
// present-day API standards.
func (p *HybridProxier) serviceForProxy(svc *corev1.Service, proxy HybridizableProxy) *corev1.Service {
	if p.rightFamilyForProxy(svc.Spec.ClusterIP, proxy) {
		return svc
	}

	for _, clusterIP := range svc.Spec.ClusterIPs {
		if p.rightFamilyForProxy(clusterIP, proxy) {
			svcForProxy := svc.DeepCopy()
			svcForProxy.Spec.ClusterIP = clusterIP
			return svcForProxy
		}
	}
	return nil
}

func (p *HybridProxier) rightFamilyForProxy(ip string, proxy HybridizableProxy) bool {
	if proxy == p.v4UnidlingProxy {
		return utilnet.IsIPv4String(ip)
	} else {
		return utilnet.IsIPv6String(ip)
	}
}

// getService locks p.serviceLock and then gets/creates the hybridProxierService for
// svcName. You must call p.releaseService(name) to unlock p.serviceLock.
func (p *HybridProxier) getService(svcName types.NamespacedName) *hybridProxierService {
	p.serviceLock.Lock()
	// caller must call p.releaseService to unlock p.serviceLock

	hsvc := p.services[svcName]
	if hsvc == nil {
		hsvc = &hybridProxierService{}
		p.services[svcName] = hsvc
	}
	return hsvc
}

// releaseService deletes the hybridProxierService for svcName if it is no longer needed,
// and unlocks p.serviceLock.
func (p *HybridProxier) releaseService(svcName types.NamespacedName) {
	defer p.serviceLock.Unlock()

	hsvc := p.services[svcName]
	if hsvc == nil {
		return
	}

	// If necessary, switch the service to the other proxy
	if hsvc.knownService && (hsvc.shouldBeIdled() != hsvc.isIdled) {
		service, err := p.serviceLister.Services(svcName.Namespace).Get(svcName.Name)
		if err != nil {
			klog.Errorf("Error while getting service %s from cache: %v", svcName, err)
			return
		}

		if hsvc.shouldBeIdled() {
			klog.Infof("switching svc %s to unidling proxy", svcName)
			p.mainProxy.OnServiceDelete(service)
			for _, unidlingProxy := range p.unidlingProxies {
				svcForProxy := p.serviceForProxy(service, unidlingProxy)
				if svcForProxy != nil {
					unidlingProxy.OnServiceAdd(svcForProxy)
				}
			}
			if !hsvc.unidlingProxyWantsEndpoints() {
				for _, unidlingProxy := range p.unidlingProxies {
					unidlingProxy.OnEndpointsAdd(emptyEndpoints(&service.ObjectMeta))
				}
			}
			hsvc.isIdled = true
			hsvc.unidledAt = nil
		} else {
			klog.Infof("switching svc %s to main proxy", svcName)
			for _, unidlingProxy := range p.unidlingProxies {
				svcForProxy := p.serviceForProxy(service, unidlingProxy)
				if svcForProxy != nil {
					unidlingProxy.OnServiceDelete(svcForProxy)
				}
			}
			p.mainProxy.OnServiceAdd(service)
			hsvc.isIdled = false
			now := time.Now()
			hsvc.unidledAt = &now
		}
	}

	if !hsvc.knownService && hsvc.knownEndpoints == 0 {
		delete(p.services, svcName)
	}
}

func serviceHasIdleAnnotation(service *corev1.Service) bool {
	_, annotationSet := service.Annotations[unidlingapi.IdledAtAnnotation]
	return annotationSet
}

func (p *HybridProxier) OnServiceAdd(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = true
	hsvc.serviceHasIdleAnnotation = serviceHasIdleAnnotation(service)

	// Services should never actually be created pre-idled. But if we do end up
	// getting an OnServiceAdd for an already-idle Service due to dropped/compressed
	// events, then releaseService() will fix this up.
	klog.V(6).Infof("add svc %s in main proxy", svcName)
	p.mainProxy.OnServiceAdd(service)
}

func (p *HybridProxier) OnServiceUpdate(oldService, service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.serviceHasIdleAnnotation = serviceHasIdleAnnotation(service)

	if hsvc.isIdled == hsvc.shouldBeIdled() {
		// Send the Update to the proxy that already knows about the service
		if hsvc.isIdled {
			klog.V(6).Infof("update svc %s in unidling proxy", svcName)
			for _, unidlingProxy := range p.unidlingProxies {
				svcForProxy := p.serviceForProxy(service, unidlingProxy)
				if svcForProxy != nil {
					oldSvcForProxy := p.serviceForProxy(oldService, unidlingProxy)
					unidlingProxy.OnServiceUpdate(oldSvcForProxy, svcForProxy)
				}
			}
		} else {
			klog.V(6).Infof("update svc %s in main proxy", svcName)
			p.mainProxy.OnServiceUpdate(oldService, service)
		}
	}
	// otherwise, releaseService will deal with deleting the service from one proxy
	// and adding it to the other.
}

func (p *HybridProxier) OnServiceDelete(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = false
	hsvc.serviceHasIdleAnnotation = false

	if hsvc.isIdled {
		klog.V(6).Infof("del svc %s in unidling proxy", svcName)
		for _, unidlingProxy := range p.unidlingProxies {
			svcForProxy := p.serviceForProxy(service, unidlingProxy)
			if svcForProxy != nil {
				unidlingProxy.OnServiceDelete(svcForProxy)
			}
		}
	} else {
		klog.V(6).Infof("del svc %s in main proxy", svcName)
		p.mainProxy.OnServiceDelete(service)
	}
}

func (p *HybridProxier) OnServiceSynced() {
	for _, unidlingProxy := range p.unidlingProxies {
		unidlingProxy.OnServiceSynced()
	}
	p.mainProxy.OnServiceSynced()
}

func (p *HybridProxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	panic("not reached")
}

func (p *HybridProxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	panic("not reached")
}

func (p *HybridProxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	panic("not reached")
}

func (p *HybridProxier) OnEndpointsSynced() {
	panic("not reached")
}

func endpointSliceServiceName(slice *discoveryv1.EndpointSlice) string {
	serviceName := slice.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		klog.Warningf("EndpointSlice %s/%s has no %q label",
			slice.Namespace, slice.Name, discoveryv1.LabelServiceName)
		return slice.Name
	}
	return serviceName
}

func (p *HybridProxier) sliceToEndpointsForProxy(slice *discoveryv1.EndpointSlice, unidlingProxy HybridizableProxy) *corev1.Endpoints {
	if slice == nil {
		return nil
	}
	if unidlingProxy == p.v4UnidlingProxy {
		if slice.AddressType == discoveryv1.AddressTypeIPv6 {
			return nil
		}
	} else {
		if slice.AddressType == discoveryv1.AddressTypeIPv4 {
			return nil
		}
	}

	endpoints := &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: slice.ObjectMeta,
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{},
				Ports:     []corev1.EndpointPort{},
			},
		},
	}
	endpoints.Name = endpointSliceServiceName(slice)
	for _, ep := range slice.Endpoints {
		addr := corev1.EndpointAddress{
			NodeName:  ep.NodeName,
			TargetRef: ep.TargetRef,
		}
		if ep.Hostname != nil {
			addr.Hostname = *ep.Hostname
		}
		for _, ip := range ep.Addresses {
			addr.IP = ip
			endpoints.Subsets[0].Addresses = append(endpoints.Subsets[0].Addresses, addr)
		}
	}
	for _, slicePort := range slice.Ports {
		port := corev1.EndpointPort{AppProtocol: slicePort.AppProtocol}
		if slicePort.Name != nil {
			port.Name = *slicePort.Name
		}
		if slicePort.Port != nil {
			port.Port = *slicePort.Port
		}
		if slicePort.Protocol != nil {
			port.Protocol = *slicePort.Protocol
		}
		endpoints.Subsets[0].Ports = append(endpoints.Subsets[0].Ports, port)
	}

	return endpoints
}

func endpointSliceIsEmpty(slice *discoveryv1.EndpointSlice) bool {
	for _, ep := range slice.Endpoints {
		if len(ep.Addresses) > 0 {
			return false
		}
	}
	return true
}

func (p *HybridProxier) OnEndpointSliceAdd(slice *discoveryv1.EndpointSlice) {
	svcName := types.NamespacedName{Namespace: slice.Namespace, Name: endpointSliceServiceName(slice)}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints++
	if endpointSliceIsEmpty(slice) {
		hsvc.emptyEndpoints++
	}

	klog.V(6).Infof("hybrid proxy: add slice %s", svcName)
	p.mainProxy.OnEndpointSliceAdd(slice)

	unidlingSlice := hsvc.unidlingSlicePtr(slice)
	if *unidlingSlice != "" && *unidlingSlice != slice.Name {
		return
	}

	if hsvc.unidlingProxyWantsEndpoints() {
		*unidlingSlice = slice.Name
		for _, unidlingProxy := range p.unidlingProxies {
			sliceForProxy := p.sliceToEndpointsForProxy(slice, unidlingProxy)
			if sliceForProxy != nil {
				unidlingProxy.OnEndpointsAdd(sliceForProxy)
			}
		}
	}
}

func (p *HybridProxier) OnEndpointSliceUpdate(oldSlice, slice *discoveryv1.EndpointSlice) {
	svcName := types.NamespacedName{Namespace: slice.Namespace, Name: endpointSliceServiceName(slice)}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	wasEmpty := endpointSliceIsEmpty(oldSlice)
	isEmpty := endpointSliceIsEmpty(slice)

	if wasEmpty && !isEmpty {
		hsvc.emptyEndpoints--
	} else if isEmpty && !wasEmpty {
		hsvc.emptyEndpoints++
	}

	klog.V(6).Infof("hybrid proxy: update slice %s", svcName)
	p.mainProxy.OnEndpointSliceUpdate(oldSlice, slice)

	unidlingSlice := hsvc.unidlingSlicePtr(slice)
	if *unidlingSlice != "" && *unidlingSlice != slice.Name {
		return
	}

	if hsvc.unidlingProxyWantsEndpoints() {
		*unidlingSlice = slice.Name
		for _, unidlingProxy := range p.unidlingProxies {
			sliceForProxy := p.sliceToEndpointsForProxy(slice, unidlingProxy)
			if sliceForProxy != nil {
				oldSliceForProxy := p.sliceToEndpointsForProxy(oldSlice, unidlingProxy)
				unidlingProxy.OnEndpointsUpdate(oldSliceForProxy, sliceForProxy)
			}
		}
	} else if hsvc.unidlingPeriodHasExpired() {
		for _, unidlingProxy := range p.unidlingProxies {
			sliceForProxy := p.sliceToEndpointsForProxy(slice, unidlingProxy)
			if sliceForProxy != nil {
				unidlingProxy.OnEndpointsDelete(sliceForProxy)
			}
		}
		*unidlingSlice = ""
		hsvc.unidledAt = nil
	}
}

func (p *HybridProxier) OnEndpointSliceDelete(slice *discoveryv1.EndpointSlice) {
	svcName := types.NamespacedName{Namespace: slice.Namespace, Name: endpointSliceServiceName(slice)}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints--
	if endpointSliceIsEmpty(slice) {
		hsvc.emptyEndpoints--
	}

	klog.V(6).Infof("hybrid proxy: del slice %s", svcName)
	p.mainProxy.OnEndpointSliceDelete(slice)

	unidlingSlice := hsvc.unidlingSlicePtr(slice)
	if *unidlingSlice != "" && *unidlingSlice != slice.Name {
		return
	}

	if hsvc.unidlingProxyWantsEndpoints() {
		for _, unidlingProxy := range p.unidlingProxies {
			sliceForProxy := p.sliceToEndpointsForProxy(slice, unidlingProxy)
			if sliceForProxy != nil {
				unidlingProxy.OnEndpointsDelete(sliceForProxy)
			}
		}
		*unidlingSlice = ""
		hsvc.unidledAt = nil
	}
}

func (p *HybridProxier) OnEndpointSlicesSynced() {
	klog.V(6).Infof("hybrid proxy: endpointslices synced")
	for _, unidlingProxy := range p.unidlingProxies {
		unidlingProxy.OnEndpointsSynced()
	}
	p.mainProxy.OnEndpointSlicesSynced()
}

// Sync is called to synchronize the proxier state to iptables
// this doesn't take immediate effect - rather, it requests that the
// BoundedFrequencyRunner call syncProxyRules()
func (p *HybridProxier) Sync() {
	p.syncRunner.Run()
}

// syncProxyRules actually applies the proxy rules to the node.
// It is called by our SyncRunner.
// We do this so that we can guarantee that changes are applied to both
// proxies, especially when unidling a newly-awoken service.
func (p *HybridProxier) syncProxyRules() {
	klog.V(3).Infof("syncProxyRules start")

	p.mainProxy.SyncProxyRules()
	for _, unidlingProxy := range p.unidlingProxies {
		unidlingProxy.SyncProxyRules()
	}

	klog.V(3).Infof("syncProxyRules finished")
}

// SyncLoop runs periodic work.  This is expected to run as a goroutine or as the main loop of the app.  It does not return.
func (p *HybridProxier) SyncLoop() {
	// All this does is start our syncRunner, since we pass it *back* in to
	// the mainProxy
	p.mainProxy.SyncLoop()
}

func (p *HybridProxier) SyncProxyRules() {
}

func (p *HybridProxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
}

func (p *HybridProxier) ReloadIPTables() {
	p.mainProxy.ReloadIPTables()
	for _, unidlingProxy := range p.unidlingProxies {
		unidlingProxy.ReloadIPTables()
	}
}
