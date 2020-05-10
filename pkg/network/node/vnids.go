// +build linux

package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"

	networkapi "github.com/openshift/api/network/v1"
	networkclient "github.com/openshift/client-go/network/clientset/versioned"
	networkinformers "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/sdn/pkg/network/common"
)

type nodeVNIDMap struct {
	policy           osdnPolicy
	networkClient    networkclient.Interface
	networkInformers networkinformers.SharedInformerFactory

	// Synchronizes add or remove ids/namespaces
	lock       sync.Mutex
	ids        map[string]uint32
	mcEnabled  map[uint32]bool
	namespaces map[uint32]string
}

func newNodeVNIDMap(policy osdnPolicy, networkClient networkclient.Interface) *nodeVNIDMap {
	return &nodeVNIDMap{
		policy:        policy,
		networkClient: networkClient,
		ids:           make(map[string]uint32),
		mcEnabled:     make(map[uint32]bool),
		namespaces:    make(map[uint32]string),
	}
}

func (vmap *nodeVNIDMap) GetNamespace(id uint32) string {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	return vmap.namespaces[id]
}

func (vmap *nodeVNIDMap) GetMulticastEnabled(id uint32) bool {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	return vmap.mcEnabled[id]
}

// Nodes asynchronously watch for both NetNamespaces and services
// NetNamespaces populates vnid map and services/pod-setup depend on vnid map
// If for some reason, vnid map propagation from master to node is slow
// and if service/pod-setup tries to lookup vnid map then it may fail.
// So, use this method to alleviate this problem. This method will
// retry vnid lookup before giving up.
func (vmap *nodeVNIDMap) WaitAndGetVNID(name string) (uint32, error) {
	var id uint32
	// ~5 sec timeout
	backoff := utilwait.Backoff{
		Duration: 400 * time.Millisecond,
		Factor:   1.5,
		Steps:    6,
	}
	err := utilwait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		id, err = vmap.getVNID(name)
		return err == nil, nil
	})
	if err == nil {
		return id, nil
	} else {
		// We may find netid when we check with api server but we will
		// still treat this as an error if we don't find it in vnid map.
		// So that we can imply insufficient timeout if we see many VnidNotFoundErrors.
		VnidNotFoundErrors.Inc()

		netns, err := vmap.networkClient.NetworkV1().NetNamespaces().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return 0, fmt.Errorf("failed to find netid for namespace: %s, %v", name, err)
		}
		klog.Warningf("Netid for namespace: %s exists but not found in vnid map", name)
		vmap.handleAddOrUpdateNetNamespace(netns, nil, watch.Added)
		return netns.NetID, nil
	}
}

func (vmap *nodeVNIDMap) getVNID(name string) (uint32, error) {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	if id, ok := vmap.ids[name]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("failed to find netid for namespace: %s in vnid map", name)
}

func (vmap *nodeVNIDMap) setVNID(name string, id uint32, mcEnabled bool) {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	vmap.namespaces[id] = name
	vmap.ids[name] = id
	vmap.mcEnabled[id] = mcEnabled

	klog.V(4).Infof("Associate netid %d to namespace %q with mcEnabled %v", id, name, mcEnabled)
}

func (vmap *nodeVNIDMap) unsetVNID(name string) (id uint32, err error) {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	id, found := vmap.ids[name]
	if !found {
		return 0, fmt.Errorf("failed to find netid for namespace: %s in vnid map", name)
	}
	delete(vmap.namespaces, id)
	delete(vmap.ids, name)
	delete(vmap.mcEnabled, id)
	klog.V(4).Infof("Dissociate netid %d from namespace %q", id, name)
	return id, nil
}

func netnsIsMulticastEnabled(netns *networkapi.NetNamespace) bool {
	enabled, ok := netns.Annotations[networkapi.MulticastEnabledAnnotation]
	return enabled == "true" && ok
}

func (vmap *nodeVNIDMap) populateVNIDs() error {
	nets, err := vmap.networkClient.NetworkV1().NetNamespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, net := range nets.Items {
		vmap.setVNID(net.Name, net.NetID, netnsIsMulticastEnabled(&net))
	}
	return nil
}

func (vmap *nodeVNIDMap) Start(networkInformers networkinformers.SharedInformerFactory) error {
	vmap.networkInformers = networkInformers

	// Populate vnid map synchronously so that existing services can fetch vnid
	err := vmap.populateVNIDs()
	if err != nil {
		return err
	}

	vmap.watchNetNamespaces()
	return nil
}

func (vmap *nodeVNIDMap) watchNetNamespaces() {
	funcs := common.InformerFuncs(&networkapi.NetNamespace{}, vmap.handleAddOrUpdateNetNamespace, vmap.handleDeleteNetNamespace)
	vmap.networkInformers.Network().V1().NetNamespaces().Informer().AddEventHandler(funcs)
}

func (vmap *nodeVNIDMap) handleAddOrUpdateNetNamespace(obj, _ interface{}, eventType watch.EventType) {
	netns := obj.(*networkapi.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", eventType, netns.Name)

	// Skip this event if nothing has changed
	oldNetID, err := vmap.getVNID(netns.NetName)
	oldMCEnabled := vmap.mcEnabled[netns.NetID]
	mcEnabled := netnsIsMulticastEnabled(netns)
	if err == nil && oldNetID == netns.NetID && oldMCEnabled == mcEnabled {
		return
	}
	vmap.setVNID(netns.NetName, netns.NetID, mcEnabled)

	if eventType == watch.Added {
		vmap.policy.AddNetNamespace(netns)
	} else {
		vmap.policy.UpdateNetNamespace(netns, oldNetID)
	}
}

func (vmap *nodeVNIDMap) handleDeleteNetNamespace(obj interface{}) {
	netns := obj.(*networkapi.NetNamespace)
	klog.V(5).Infof("Watch %s event for NetNamespace %q", watch.Deleted, netns.Name)

	// Unset VNID first so further operations don't see the deleted VNID
	vmap.unsetVNID(netns.NetName)
	vmap.policy.DeleteNetNamespace(netns)
}
