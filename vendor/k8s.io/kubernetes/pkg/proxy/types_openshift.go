package proxy

import (
	"k8s.io/kubernetes/pkg/util/async"
)

// HybridizableProxy is an extra interface openshift-sdn layers on top of Provider
type HybridizableProxy interface {
	Provider

	SyncProxyRules()
	SetSyncRunner(b *async.BoundedFrequencyRunner)
}
