package metaproxier

// Some extra hacking for openshift-specific stuff

import (
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/util/async"
)

var _ proxy.HybridizableProxy = &metaProxier{}

func (p *metaProxier) SyncProxyRules() {
	p.Sync()
}

func (p *metaProxier) SetSyncRunner(b *async.BoundedFrequencyRunner) {
	ipv4Proxier := p.ipv4Proxier.(proxy.HybridizableProxy)
	ipv6Proxier := p.ipv6Proxier.(proxy.HybridizableProxy)

	ipv4Proxier.SetSyncRunner(b)
	ipv6Proxier.SetSyncRunner(b)
}
