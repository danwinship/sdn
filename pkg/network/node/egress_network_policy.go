package node

import (
	"context"
	"fmt"

	"k8s.io/klog/v2"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
)

func (node *OsdnNode) SetupEgressNetworkPolicy() error {
	policies, err := node.clients.OSDNClient.NetworkV1().EgressNetworkPolicies(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("could not get EgressNetworkPolicies: %s", err)
	}

	node.egressPoliciesLock.Lock()
	defer node.egressPoliciesLock.Unlock()

	for _, policy := range policies.Items {
		vnid, err := node.policy.GetVNID(policy.Namespace)
		if err != nil {
			klog.Warningf("Could not find netid for namespace %q: %v", policy.Namespace, err)
			continue
		}
		node.egressPolicies[vnid] = append(node.egressPolicies[vnid], policy)

		node.egressDNS.Add(policy)
	}

	for vnid := range node.egressPolicies {
		node.updateEgressNetworkPolicyRules(vnid)
	}

	go utilwait.Forever(node.syncEgressDNSPolicyRules, 0)
	node.watchEgressNetworkPolicies()
	return nil
}

func (node *OsdnNode) watchEgressNetworkPolicies() {
	funcs := common.InformerFuncs(&osdnv1.EgressNetworkPolicy{}, node.handleAddOrUpdateEgressNetworkPolicy, node.handleDeleteEgressNetworkPolicy)
	node.clients.OSDNInformers.Network().V1().EgressNetworkPolicies().Informer().AddEventHandler(funcs)
}

func (node *OsdnNode) handleAddOrUpdateEgressNetworkPolicy(obj, _ interface{}, eventType watch.EventType) {
	policy := obj.(*osdnv1.EgressNetworkPolicy)
	klog.V(5).Infof("Watch %s event for EgressNetworkPolicy %s/%s", eventType, policy.Namespace, policy.Name)

	node.handleEgressNetworkPolicy(policy, eventType)
}

func (node *OsdnNode) handleDeleteEgressNetworkPolicy(obj interface{}) {
	policy := obj.(*osdnv1.EgressNetworkPolicy)
	klog.V(5).Infof("Watch %s event for EgressNetworkPolicy %s/%s", watch.Deleted, policy.Namespace, policy.Name)

	node.handleEgressNetworkPolicy(policy, watch.Deleted)
}

func (node *OsdnNode) handleEgressNetworkPolicy(policy *osdnv1.EgressNetworkPolicy, eventType watch.EventType) {
	vnid, err := node.policy.GetVNID(policy.Namespace)
	if err != nil {
		klog.Errorf("Could not find netid for namespace %q: %v", policy.Namespace, err)
		return
	}

	node.egressPoliciesLock.Lock()
	defer node.egressPoliciesLock.Unlock()

	policies := node.egressPolicies[vnid]
	for i, oldPolicy := range policies {
		if oldPolicy.UID == policy.UID {
			policies = append(policies[:i], policies[i+1:]...)
			break
		}
	}
	node.egressDNS.Delete(*policy)

	if eventType != watch.Deleted && len(policy.Spec.Egress) > 0 {
		policies = append(policies, *policy)
		node.egressDNS.Add(*policy)
	}
	node.egressPolicies[vnid] = policies

	node.updateEgressNetworkPolicyRules(vnid)
}

func (node *OsdnNode) UpdateEgressNetworkPolicyVNID(namespace string, oldVnid, newVnid uint32) {
	var policy *osdnv1.EgressNetworkPolicy

	node.egressPoliciesLock.Lock()
	defer node.egressPoliciesLock.Unlock()

	policies := node.egressPolicies[oldVnid]
	for i, oldPolicy := range policies {
		if oldPolicy.Namespace == namespace {
			policy = &oldPolicy
			node.egressPolicies[oldVnid] = append(policies[:i], policies[i+1:]...)
			node.updateEgressNetworkPolicyRules(oldVnid)
			break
		}
	}

	if policy != nil {
		node.egressPolicies[newVnid] = append(node.egressPolicies[newVnid], *policy)
		node.updateEgressNetworkPolicyRules(newVnid)
	}
}

func (node *OsdnNode) syncEgressDNSPolicyRules() {
	go utilwait.Forever(node.egressDNS.Sync, 0)

	for {
		policyUpdates := <-node.egressDNS.Updates
		for _, policyUpdate := range policyUpdates {
			klog.V(5).Infof("Egress dns sync: updating policy: %v", policyUpdate.UID)
			vnid, err := node.policy.GetVNID(policyUpdate.Namespace)
			if err != nil {
				klog.Warningf("Could not find netid for namespace %q: %v", policyUpdate.Namespace, err)
				continue
			}

			func() {
				node.egressPoliciesLock.Lock()
				defer node.egressPoliciesLock.Unlock()

				node.updateEgressNetworkPolicyRules(vnid)
			}()
		}
	}
}
