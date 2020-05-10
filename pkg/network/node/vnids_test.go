// +build linux

package node

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/sdn/pkg/network"
)

func TestNodeVNIDMap(t *testing.T) {
	vmap := newNodeVNIDMap(nil, nil)

	// empty vmap

	checkNotExists(t, vmap, "alpha")
	checkNamespace(t, vmap, 1, "")
	checkAllocatedVNIDs(t, vmap, []uint32{})

	// set vnids, non-overlapping

	vmap.setVNID("alpha", 1, false)
	vmap.setVNID("bravo", 2, false)
	vmap.setVNID("charlie", 3, false)
	vmap.setVNID("delta", 4, false)

	checkExists(t, vmap, "alpha", 1)
	checkExists(t, vmap, "bravo", 2)
	checkExists(t, vmap, "charlie", 3)
	checkExists(t, vmap, "delta", 4)
	checkNotExists(t, vmap, "echo")

	checkNamespace(t, vmap, 1, "alpha")
	checkNamespace(t, vmap, 2, "bravo")
	checkNamespace(t, vmap, 3, "charlie")
	checkNamespace(t, vmap, 4, "delta")

	checkAllocatedVNIDs(t, vmap, []uint32{1, 2, 3, 4})

	// unset vnids

	id, err := vmap.unsetVNID("alpha")
	if id != 1 || err != nil {
		t.Fatalf("Unexpected failure: %d, %v", id, err)
	}
	id, err = vmap.unsetVNID("charlie")
	if id != 3 || err != nil {
		t.Fatalf("Unexpected failure: %d, %v", id, err)
	}

	checkNotExists(t, vmap, "alpha")
	checkExists(t, vmap, "bravo", 2)
	checkNotExists(t, vmap, "charlie")
	checkExists(t, vmap, "delta", 4)

	id, err = vmap.unsetVNID("alpha")
	if err == nil {
		t.Fatalf("Unexpected success: %d", id)
	}
	id, err = vmap.unsetVNID("echo")
	if err == nil {
		t.Fatalf("Unexpected success: %d", id)
	}

	checkNamespace(t, vmap, 1, "")
	checkNamespace(t, vmap, 2, "bravo")
	checkNamespace(t, vmap, 3, "")
	checkNamespace(t, vmap, 4, "delta")

	checkAllocatedVNIDs(t, vmap, []uint32{2, 4})
}

func checkExists(t *testing.T, vmap *nodeVNIDMap, name string, expected uint32) {
	id, err := vmap.getVNID(name)
	if id != expected || err != nil {
		t.Fatalf("Unexpected failure: %d, %v", id, err)
	}
}

func checkNotExists(t *testing.T, vmap *nodeVNIDMap, name string) {
	id, err := vmap.getVNID(name)
	if err == nil {
		t.Fatalf("Unexpected success: %d", id)
	}
}

func checkNamespace(t *testing.T, vmap *nodeVNIDMap, vnid uint32, match string) {
	namespace := vmap.GetNamespace(vnid)
	if namespace != match {
		t.Fatalf("Wrong namespace: %v vs %v", namespace, match)
	}
}

func checkAllocatedVNIDs(t *testing.T, vmap *nodeVNIDMap, match []uint32) {
	ids := []uint32{}
	idSet := sets.Int{}
	for _, id := range vmap.ids {
		if id != network.GlobalVNID {
			if !idSet.Has(int(id)) {
				ids = append(ids, id)
				idSet.Insert(int(id))
			}
		}
	}
	if len(ids) != len(match) {
		t.Fatalf("Wrong number of VNIDs: %d vs %d", len(ids), len(match))
	}

	for _, m := range match {
		found := false
		for _, n := range ids {
			if n == m {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Missing VNID: %d", m)
		}
	}
}
