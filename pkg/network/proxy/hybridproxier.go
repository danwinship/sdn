package proxy

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/util/async"

	unidlingapi "github.com/openshift/api/unidling/v1alpha1"
)

// HybridizableProxy is an extra interface we layer on top of Provider
type HybridizableProxy interface {
	proxy.Provider

	SyncProxyRules()
	SetSyncRunner(b *async.BoundedFrequencyRunner)
}

// HybridProxier runs an unidling proxy and a primary proxy at the same time,
// delegating idled services to the unidling proxy and other services to the
// primary proxy.
type HybridProxier struct {
	proxyconfig.NoopEndpointSliceHandler

	mainProxy     HybridizableProxy
	unidlingProxy HybridizableProxy

	serviceLister corev1listers.ServiceLister
	syncRunner    *async.BoundedFrequencyRunner

	// TODO(directxman12): figure out a good way to avoid duplicating this information
	// (it's saved in the individual proxies as well)
	// usingUserspace is *NOT* a set -- we care about the value, and use it to keep track of
	// when we need to delete from an existing proxier when adding to a new one.
	usingUserspace     map[types.NamespacedName]bool
	usingUserspaceLock sync.Mutex

	// There are some bugs where we can call switchService() multiple times
	// even though we don't actually want to switch. This calls OnServiceDelete()
	// multiple times for the underlying proxies, which causes bugs.
	// See bz 1635330
	// So, add an additional state store to ensure we only switch once
	switchedToUserspace     map[types.NamespacedName]bool
	switchedToUserspaceLock sync.Mutex

	// This map is used in unidling proxy mode to ensure the service is correctly deleted
	// if it's deletion occurs after the deletion of the endpoint.
	pendingDeletion map[types.NamespacedName]bool
}

func NewHybridProxier(
	mainProxy HybridizableProxy,
	unidlingProxy HybridizableProxy,
	minSyncPeriod time.Duration,
	serviceLister corev1listers.ServiceLister,
) *HybridProxier {
	p := &HybridProxier{
		mainProxy:     mainProxy,
		unidlingProxy: unidlingProxy,

		serviceLister: serviceLister,

		usingUserspace:      make(map[types.NamespacedName]bool),
		switchedToUserspace: make(map[types.NamespacedName]bool),
		pendingDeletion:     make(map[types.NamespacedName]bool),
	}

	p.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", p.syncProxyRules, minSyncPeriod, time.Hour, 4)

	// Hackery abound: we want to make sure that changes are applied
	// to both proxies at approximately the same time. That means that we
	// need to stop the two proxy's independent loops and take them over.
	mainProxy.SetSyncRunner(p.syncRunner)
	unidlingProxy.SetSyncRunner(p.syncRunner)

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

func (p *HybridProxier) OnServiceAdd(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}

	p.usingUserspaceLock.Lock()
	defer p.usingUserspaceLock.Unlock()

	// since this is an Add, we know the service isn't already in another
	// proxy, so don't bother trying to remove like on an update
	if isUsingUserspace, ok := p.usingUserspace[svcName]; ok && isUsingUserspace {
		klog.V(6).Infof("add svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceAdd(service)
	} else {
		klog.V(6).Infof("add svc %s in main proxy", svcName)
		p.mainProxy.OnServiceAdd(service)
	}
}

func (p *HybridProxier) OnServiceUpdate(oldService, service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}

	p.usingUserspaceLock.Lock()
	defer p.usingUserspaceLock.Unlock()

	// NB: usingUserspace can only change in the endpoints handler,
	// so that should deal with calling OnServiceDelete on switches
	if isUsingUserspace, ok := p.usingUserspace[svcName]; ok && isUsingUserspace {
		klog.V(6).Infof("update svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceUpdate(oldService, service)
	} else {
		klog.V(6).Infof("update svc %s in main proxy", svcName)
		p.mainProxy.OnServiceUpdate(oldService, service)
	}
}

// cleanupState handles the deletion of endpoints and service in any order.
// svcName should be the NamespacedName of a service (or endpoint).
func (p *HybridProxier) cleanupState(svcName types.NamespacedName) {
	_, isPendingDeletion := p.pendingDeletion[svcName]
	if isPendingDeletion {
		klog.V(6).Infof("removing %s entry from pendingDeletion", svcName)
		delete(p.pendingDeletion, svcName)
		delete(p.usingUserspace, svcName)
		delete(p.switchedToUserspace, svcName)
	} else {
		klog.V(6).Infof("adding %s entry to pendingDeletion", svcName)
		p.pendingDeletion[svcName] = true
	}
}

func (p *HybridProxier) OnServiceDelete(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}

	p.usingUserspaceLock.Lock()
	defer p.usingUserspaceLock.Unlock()

	// Careful, we always need to get this lock after usingUserspace, or else we could deadlock
	p.switchedToUserspaceLock.Lock()
	defer p.switchedToUserspaceLock.Unlock()

	if isUsingUserspace, ok := p.usingUserspace[svcName]; ok && isUsingUserspace {
		klog.V(6).Infof("del svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceDelete(service)
	} else {
		klog.V(6).Infof("del svc %s in main proxy", svcName)
		p.mainProxy.OnServiceDelete(service)
	}

	p.cleanupState(svcName)
}

func (p *HybridProxier) OnServiceSynced() {
	p.unidlingProxy.OnServiceSynced()
	p.mainProxy.OnServiceSynced()
	klog.V(6).Infof("services synced")
}

// shouldEndpointsUseUserspace checks to see if the given endpoints have the correct
// annotations and size to use the unidling proxy.
func (p *HybridProxier) shouldEndpointsUseUserspace(endpoints *corev1.Endpoints) bool {
	hasEndpoints := false
	for _, subset := range endpoints.Subsets {
		if len(subset.Addresses) > 0 {
			hasEndpoints = true
			break
		}
	}

	if !hasEndpoints {
		if _, ok := endpoints.Annotations[unidlingapi.IdledAtAnnotation]; ok {
			return true
		}
	}

	return false
}

// switchService moves a service between the unidling and main proxies.
func (p *HybridProxier) switchService(svcName types.NamespacedName) {
	// We shouldn't call switchService more than once (per switch), but there
	// are some logic bugs where this happens
	// So, cache the real state and don't allow this to be called twice.
	// This assumes the caller already holds usingUserspaceLock
	p.switchedToUserspaceLock.Lock()
	defer p.switchedToUserspaceLock.Unlock()

	switched, ok := p.switchedToUserspace[svcName]
	if ok && p.usingUserspace[svcName] == switched {
		klog.V(6).Infof("ignoring duplicate switchService(%s)", svcName)
		return
	}

	svc, err := p.serviceLister.Services(svcName.Namespace).Get(svcName.Name)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Error while getting service %s from cache: %v", svcName, err))
		return
	}

	if p.usingUserspace[svcName] {
		klog.Infof("switching svc %s to unidling proxy", svcName)
		p.unidlingProxy.OnServiceAdd(svc)
		p.mainProxy.OnServiceDelete(svc)
	} else {
		klog.Infof("switching svc %s to main proxy", svcName)
		p.mainProxy.OnServiceAdd(svc)
		p.unidlingProxy.OnServiceDelete(svc)
	}

	p.switchedToUserspace[svcName] = p.usingUserspace[svcName]
}

func (p *HybridProxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}

	klog.V(6).Infof("add ep %s", svcName)
	p.unidlingProxy.OnEndpointsAdd(endpoints)
	p.mainProxy.OnEndpointsAdd(endpoints)

	p.usingUserspaceLock.Lock()
	defer p.usingUserspaceLock.Unlock()

	wasUsingUserspace, knownEndpoints := p.usingUserspace[svcName]
	p.usingUserspace[svcName] = p.shouldEndpointsUseUserspace(endpoints)

	// a service could appear before endpoints, so we have to treat this as a potential
	// state modification for services, and not just an addition (since we could flip proxies).
	if knownEndpoints && wasUsingUserspace != p.usingUserspace[svcName] {
		p.switchService(svcName)
	}
}

func (p *HybridProxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}

	klog.V(6).Infof("update ep %s", svcName)
	p.unidlingProxy.OnEndpointsUpdate(oldEndpoints, endpoints)
	p.mainProxy.OnEndpointsUpdate(oldEndpoints, endpoints)

	p.usingUserspaceLock.Lock()
	defer p.usingUserspaceLock.Unlock()

	wasUsingUserspace, knownEndpoints := p.usingUserspace[svcName]
	p.usingUserspace[svcName] = p.shouldEndpointsUseUserspace(endpoints)

	if !knownEndpoints {
		utilruntime.HandleError(fmt.Errorf("received update for unknown endpoints %s", svcName.String()))
		return
	}

	if wasUsingUserspace != p.usingUserspace[svcName] {
		p.switchService(svcName)
	}
}

func (p *HybridProxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}

	klog.V(6).Infof("del ep %s", svcName)
	p.unidlingProxy.OnEndpointsDelete(endpoints)
	p.mainProxy.OnEndpointsDelete(endpoints)

	p.cleanupState(svcName)
}

func (p *HybridProxier) OnEndpointsSynced() {
	p.unidlingProxy.OnEndpointsSynced()
	p.mainProxy.OnEndpointsSynced()
	klog.V(6).Infof("endpoints synced")
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
	klog.V(4).Infof("syncProxyRules start")

	p.mainProxy.SyncProxyRules()
	p.unidlingProxy.SyncProxyRules()

	klog.V(4).Infof("syncProxyRules finished")
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
