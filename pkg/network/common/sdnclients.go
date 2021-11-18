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

	cloudnetworkclient "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkfake "github.com/openshift/client-go/cloudnetwork/clientset/versioned/fake"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdnfake "github.com/openshift/client-go/network/clientset/versioned/fake"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
)

// SDNClients holds the clients and informers used by openshift-sdn
type SDNClients struct {
	KubeClient         kubernetes.Interface
	OSDNClient         osdnclient.Interface
	CloudNetworkClient cloudnetworkclient.Interface

	KubeInformers         kinformers.SharedInformerFactory
	OSDNInformers         osdninformers.SharedInformerFactory
	CloudNetworkInformers cloudnetworkinformers.SharedInformerFactory

	syncFuncs []kcache.InformerSynced
}

// Start starts the client's informers
func (clients *SDNClients) Start(stopCh <-chan struct{}) {
	clients.KubeInformers.Start(stopCh)
	clients.OSDNInformers.Start(stopCh)
	if clients.CloudNetworkInformers != nil {
		clients.CloudNetworkInformers.Start(stopCh)
	}
}

type InformerAddOrUpdateFunc func(interface{}, interface{}, watch.EventType)
type InformerDeleteFunc func(interface{})

// AddEventHandler adds an event handler for an informer (also recording the fact that the
// informer is in use so we can wait for it to sync later).
func (clients *SDNClients) AddEventHandler(informer kcache.SharedIndexInformer, objType runtime.Object, addOrUpdateFunc InformerAddOrUpdateFunc, deleteFunc InformerDeleteFunc) {
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
	informer.AddEventHandler(handlerFuncs)

	clients.syncFuncs = append(clients.syncFuncs, informer.HasSynced)
}

// WaitForCacheSync waits for all of the informers passed to UseInformer to have synced.
// (Note that if the call this multiple times, the second and later times will just
// return immediately.)
func (clients *SDNClients) WaitForCacheSync(controllerName string) {
	if !kcache.WaitForNamedCacheSync(controllerName, utilwait.NeverStop, clients.syncFuncs...) {
		klog.Fatalf("Unable to sync caches")
	}
}

// NewFakeSDNClients creates new fake clients for unit tests
func NewFakeSDNClients() *SDNClients {
	clients := &SDNClients{
		KubeClient:         kfake.NewSimpleClientset(),
		OSDNClient:         osdnfake.NewSimpleClientset(),
		CloudNetworkClient: cloudnetworkfake.NewSimpleClientset(),
	}
	clients.KubeInformers = kinformers.NewSharedInformerFactory(clients.KubeClient, time.Hour)
	clients.OSDNInformers = osdninformers.NewSharedInformerFactory(clients.OSDNClient, time.Hour)
	clients.CloudNetworkInformers = cloudnetworkinformers.NewSharedInformerFactory(clients.CloudNetworkClient, time.Hour)

	return clients
}
