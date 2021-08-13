package common

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	kinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	kfake "k8s.io/client-go/kubernetes/fake"
	kcache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdnfake "github.com/openshift/client-go/network/clientset/versioned/fake"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
)

// SDNClients holds the clients and informers used by openshift-sdn
type SDNClients struct {
	KubeClient kubernetes.Interface
	OSDNClient osdnclient.Interface

	KubeInformers kinformers.SharedInformerFactory
	OSDNInformers osdninformers.SharedInformerFactory
}

// Start starts the client's informers
func (clients *SDNClients) Start(stopCh <-chan struct{}) {
	clients.KubeInformers.Start(stopCh)
	clients.OSDNInformers.Start(stopCh)
}

// WaitForCacheSync waits for a list of informers to be synced, or aborts on failure.
func (clients *SDNClients) WaitForCacheSync(controllerName string, informers ...kcache.SharedInformer) {
	syncFuncs := make([]kcache.InformerSynced, len(informers))
	for i, informer := range informers {
		syncFuncs[i] = informer.HasSynced
	}
	if !kcache.WaitForNamedCacheSync(controllerName, utilwait.NeverStop, syncFuncs...) {
		klog.Fatalf("Unable to sync caches")
	}
}

// NewFakeSDNClients creates new fake clients for unit tests
func NewFakeSDNClients() *SDNClients {
	clients := &SDNClients{
		KubeClient: kfake.NewSimpleClientset(),
		OSDNClient: osdnfake.NewSimpleClientset(),
	}
	clients.KubeInformers = kinformers.NewSharedInformerFactory(clients.KubeClient, time.Hour)
	clients.OSDNInformers = osdninformers.NewSharedInformerFactory(clients.OSDNClient, time.Hour)

	return clients
}

type InformerAddOrUpdateFunc func(interface{}, interface{}, watch.EventType)
type InformerDeleteFunc func(interface{})

func InformerFuncs(objType runtime.Object, addOrUpdateFunc InformerAddOrUpdateFunc, deleteFunc InformerDeleteFunc) kcache.ResourceEventHandlerFuncs {
	handlerFuncs := kcache.ResourceEventHandlerFuncs{}
	if addOrUpdateFunc != nil {
		handlerFuncs.AddFunc = func(obj interface{}) {
			addOrUpdateFunc(obj, nil, watch.Added)
		}
		handlerFuncs.UpdateFunc = func(old, cur interface{}) {
			addOrUpdateFunc(cur, old, watch.Modified)
		}
	}
	if deleteFunc != nil {
		handlerFuncs.DeleteFunc = func(obj interface{}) {
			if reflect.TypeOf(objType) != reflect.TypeOf(obj) {
				tombstone, ok := obj.(kcache.DeletedFinalStateUnknown)
				if !ok {
					klog.Errorf("Couldn't get object from tombstone: %+v", obj)
					return
				}

				obj = tombstone.Obj
				if reflect.TypeOf(objType) != reflect.TypeOf(obj) {
					klog.Errorf("Tombstone contained object, expected resource type: %v but got: %v", reflect.TypeOf(objType), reflect.TypeOf(obj))
					return
				}
			}
			deleteFunc(obj)
		}
	}
	return handlerFuncs
}
