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

// hybridProxierService is our cached state for a given Service/Endpoints
type hybridProxierService struct {
	// whether the Service/Endpoints are known to us
	knownService   bool
	knownEndpoints bool

	// cached info about the Service/Endpoints
	serviceHasIdleAnnotation bool
	endpointsNonEmpty        bool

	// idling/unidling state
	isIdled bool
}

func (hsvc *hybridProxierService) shouldBeIdled() bool {
	return hsvc.serviceHasIdleAnnotation && !hsvc.endpointsNonEmpty
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

	serviceLock sync.Mutex
	services    map[types.NamespacedName]*hybridProxierService
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

		services: make(map[types.NamespacedName]*hybridProxierService),
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

func (p *HybridProxier) getService(svcName types.NamespacedName) *hybridProxierService {
	p.serviceLock.Lock()

	hsvc := p.services[svcName]
	if hsvc == nil {
		hsvc = &hybridProxierService{}
		p.services[svcName] = hsvc
	}
	return hsvc
}

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
			utilruntime.HandleError(fmt.Errorf("Error while getting service %s from cache: %v", svcName, err))
			return
		}

		if hsvc.shouldBeIdled() {
			klog.Infof("switching svc %s to unidling proxy", svcName)
			p.mainProxy.OnServiceDelete(service)
			p.unidlingProxy.OnServiceAdd(service)
			hsvc.isIdled = true
		} else {
			klog.Infof("switching svc %s to main proxy", svcName)
			p.unidlingProxy.OnServiceDelete(service)
			p.mainProxy.OnServiceAdd(service)
			hsvc.isIdled = false
		}
	}

	if !hsvc.knownService && !hsvc.knownEndpoints {
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
			p.unidlingProxy.OnServiceUpdate(oldService, service)
		} else {
			klog.V(6).Infof("update svc %s in main proxy", svcName)
			p.mainProxy.OnServiceUpdate(oldService, service)
		}
	}
	// otherwise, releaseService will deal with switching the service to the other proxy
}

func (p *HybridProxier) OnServiceDelete(service *corev1.Service) {
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownService = false
	hsvc.serviceHasIdleAnnotation = false

	if hsvc.isIdled {
		klog.V(6).Infof("del svc %s in unidling proxy", svcName)
		p.unidlingProxy.OnServiceDelete(service)
	} else {
		klog.V(6).Infof("del svc %s in main proxy", svcName)
		p.mainProxy.OnServiceDelete(service)
	}
}

func (p *HybridProxier) OnServiceSynced() {
	p.unidlingProxy.OnServiceSynced()
	p.mainProxy.OnServiceSynced()
}

func endpointsNonEmpty(endpoints *corev1.Endpoints) bool {
	for _, subset := range endpoints.Subsets {
		if len(subset.Addresses) > 0 {
			return true
		}
	}
	return false
}

func (p *HybridProxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints = true
	hsvc.endpointsNonEmpty = endpointsNonEmpty(endpoints)

	klog.V(6).Infof("add ep %s", svcName)
	p.unidlingProxy.OnEndpointsAdd(endpoints)
	p.mainProxy.OnEndpointsAdd(endpoints)
}

func (p *HybridProxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.endpointsNonEmpty = endpointsNonEmpty(endpoints)

	klog.V(6).Infof("update ep %s", svcName)
	p.unidlingProxy.OnEndpointsUpdate(oldEndpoints, endpoints)
	p.mainProxy.OnEndpointsUpdate(oldEndpoints, endpoints)
}

func (p *HybridProxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	svcName := types.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}
	hsvc := p.getService(svcName)
	defer p.releaseService(svcName)

	hsvc.knownEndpoints = false
	hsvc.endpointsNonEmpty = false

	klog.V(6).Infof("del ep %s", svcName)
	p.unidlingProxy.OnEndpointsDelete(endpoints)
	p.mainProxy.OnEndpointsDelete(endpoints)
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
