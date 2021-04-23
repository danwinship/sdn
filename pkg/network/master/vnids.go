package master

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	kapi "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"

	networkv1 "github.com/openshift/api/network/v1"
	networkclient "github.com/openshift/client-go/network/clientset/versioned"
	"github.com/openshift/sdn/pkg/network"
	"github.com/openshift/sdn/pkg/network/common"
	pnetid "github.com/openshift/sdn/pkg/network/master/netid"
)

type masterVNIDMap struct {
	// Synchronizes assign, revoke and update VNID
	lock         sync.Mutex
	ids          map[string]uint32
	netIDManager *pnetid.Allocator
}

func newMasterVNIDMap() *masterVNIDMap {
	netIDRange, err := pnetid.NewNetIDRange(network.MinVNID, network.MaxVNID)
	if err != nil {
		panic(err)
	}

	return &masterVNIDMap{
		netIDManager: pnetid.NewInMemory(netIDRange),
		ids:          make(map[string]uint32),
	}
}

func (vmap *masterVNIDMap) getVNID(name string) (uint32, bool) {
	id, found := vmap.ids[name]
	return id, found
}

func (vmap *masterVNIDMap) setVNID(name string, id uint32) {
	vmap.ids[name] = id
}

func (vmap *masterVNIDMap) unsetVNID(name string) (uint32, bool) {
	id, found := vmap.ids[name]
	delete(vmap.ids, name)
	return id, found
}

func (vmap *masterVNIDMap) getVNIDCount(id uint32) int {
	count := 0
	for _, netid := range vmap.ids {
		if id == netid {
			count = count + 1
		}
	}
	return count
}

func (vmap *masterVNIDMap) isAdminNamespace(nsName string) bool {
	return nsName == metav1.NamespaceDefault
}

func (vmap *masterVNIDMap) markAllocatedNetID(netid uint32) error {
	// Skip GlobalVNID, not part of netID allocation range
	if netid < network.MinVNID {
		return nil
	}

	switch err := vmap.netIDManager.Allocate(netid); err {
	case nil: // Expected normal case
	case pnetid.ErrAllocated: // Expected when project networks are joined
	default:
		return fmt.Errorf("unable to allocate netid %d: %v", netid, err)
	}
	return nil
}

func (vmap *masterVNIDMap) allocateNetID(nsName string) (uint32, bool, error) {
	// Nothing to do if the netid is in the vnid map
	exists := false
	if netid, found := vmap.getVNID(nsName); found {
		exists = true
		return netid, exists, nil
	}

	// NetNamespace not found, so allocate new NetID
	var netid uint32
	if vmap.isAdminNamespace(nsName) {
		netid = network.GlobalVNID
	} else {
		var err error
		netid, err = vmap.netIDManager.AllocateNext()
		if err != nil {
			return 0, exists, err
		}
	}

	vmap.setVNID(nsName, netid)
	klog.Infof("Allocated netid %d for namespace %q", netid, nsName)
	return netid, exists, nil
}

func (vmap *masterVNIDMap) releaseNetID(nsName string) error {
	// Remove NetID from vnid map
	netid, found := vmap.unsetVNID(nsName)
	if !found {
		return fmt.Errorf("netid not found for namespace %q", nsName)
	}

	// Skip network.GlobalVNID as it is not part of NetID allocation
	if netid == network.GlobalVNID {
		return nil
	}

	// Check if this netid is used by any other namespaces
	// If not, then release the netid
	if count := vmap.getVNIDCount(netid); count == 0 {
		if err := vmap.netIDManager.Release(netid); err != nil {
			return fmt.Errorf("error while releasing netid %d for namespace %q, %v", netid, nsName, err)
		}
		klog.Infof("Released netid %d for namespace %q", netid, nsName)
	} else {
		klog.V(5).Infof("netid %d for namespace %q is still in use", netid, nsName)
	}
	return nil
}

// assignVNID, revokeVNID and updateVNID methods updates in-memory structs and persists etcd objects
func (vmap *masterVNIDMap) assignVNID(networkClient networkclient.Interface, nsName string) error {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	netid, exists, err := vmap.allocateNetID(nsName)
	if err != nil {
		return err
	}

	if !exists {
		// Create NetNamespace Object and update vnid map
		netns := &networkv1.NetNamespace{
			TypeMeta:   metav1.TypeMeta{Kind: "NetNamespace"},
			ObjectMeta: metav1.ObjectMeta{Name: nsName},
			NetName:    nsName,
			NetID:      netid,
		}
		if _, err := networkClient.NetworkV1().NetNamespaces().Create(context.TODO(), netns, metav1.CreateOptions{}); err != nil {
			if er := vmap.releaseNetID(nsName); er != nil {
				utilruntime.HandleError(er)
			}
			return err
		}
	}
	return nil
}

func (vmap *masterVNIDMap) revokeVNID(networkClient networkclient.Interface, nsName string) error {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	// Delete NetNamespace object
	if err := networkClient.NetworkV1().NetNamespaces().Delete(context.TODO(), nsName, metav1.DeleteOptions{}); err != nil {
		// If the netnamespace is already deleted, emit a warning and move forward
		if kapierrors.IsNotFound(err) {
			klog.Warningf("Could not find the netnamespace %s: Must be already deleted.", nsName)
		} else {
			return err
		}
	}

	if err := vmap.releaseNetID(nsName); err != nil {
		return err
	}
	return nil
}

//--------------------- Master methods ----------------------

func (master *OsdnMaster) startVNIDMaster() error {
	if err := master.initNetIDAllocator(); err != nil {
		return err
	}

	master.watchNamespaces()
	return nil
}

func (master *OsdnMaster) initNetIDAllocator() error {
	netnsList, err := master.networkClient.NetworkV1().NetNamespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, netns := range netnsList.Items {
		if err := master.vnids.markAllocatedNetID(netns.NetID); err != nil {
			utilruntime.HandleError(err)
		}
		master.vnids.setVNID(netns.Name, netns.NetID)
	}

	return nil
}

func (master *OsdnMaster) watchNamespaces() {
	funcs := common.InformerFuncs(&kapi.Namespace{}, master.handleAddOrUpdateNamespace, master.handleDeleteNamespace)
	master.namespaceInformer.Informer().AddEventHandler(funcs)
}

func (master *OsdnMaster) handleAddOrUpdateNamespace(obj, _ interface{}, eventType watch.EventType) {
	ns := obj.(*kapi.Namespace)
	klog.V(5).Infof("Watch %s event for Namespace %q", eventType, ns.Name)

	if err := master.vnids.assignVNID(master.networkClient, ns.Name); err != nil {
		utilruntime.HandleError(fmt.Errorf("Error assigning netid: %v", err))
	}
}

func (master *OsdnMaster) handleDeleteNamespace(obj interface{}) {
	ns := obj.(*kapi.Namespace)
	klog.V(5).Infof("Watch %s event for Namespace %q", watch.Deleted, ns.Name)
	if err := master.vnids.revokeVNID(master.networkClient, ns.Name); err != nil {
		utilruntime.HandleError(fmt.Errorf("Error revoking netid: %v", err))
	}
}
