package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	metrics "github.com/openshift/sdn/pkg/network/node/metrics"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	kubeletapi "k8s.io/cri-api/pkg/apis"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	kapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/core/v1/helper"
	ktypes "k8s.io/kubernetes/pkg/kubelet/types"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/util/iptables"
	taints "k8s.io/kubernetes/pkg/util/taints"
	kexec "k8s.io/utils/exec"

	osdnv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/library-go/pkg/network/networkutils"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/network/common/cniserver"
	"github.com/openshift/sdn/pkg/util/ovs"
)

type osdnPolicy interface {
	Name() string
	Start(node *OsdnNode) error
	SupportsVNIDs() bool
	AllowDuplicateNetID() bool

	AddNetNamespace(netns *osdnv1.NetNamespace)
	UpdateNetNamespace(netns *osdnv1.NetNamespace, oldNetID uint32)
	DeleteNetNamespace(netns *osdnv1.NetNamespace)

	GetVNID(namespace string) (uint32, error)
	GetNamespaces(vnid uint32) []string
	GetMulticastEnabled(vnid uint32) bool

	EnsureVNIDRules(vnid uint32)
	SyncVNIDRules()
}

type OsdnNodeConfig struct {
	NodeName string
	NodeIP   string

	SDNClients  *common.SDNClients
	SDNConfig   *common.SDNConfig
	ProxyConfig *kubeproxyconfig.KubeProxyConfiguration

	Recorder record.EventRecorder
	IPTables iptables.Interface
}

type OsdnNode struct {
	clients   *common.SDNClients
	sdnConfig *common.SDNConfig

	policy       osdnPolicy
	recorder     record.EventRecorder
	oc           *ovsController
	podManager   *podManager
	ipt          iptables.Interface
	nodeIPTables *NodeIPTables

	localSubnetCIDR   string
	localGatewayCIDR  string
	localIP           string
	hostName          string
	useConnTrack      bool
	masqueradeBitMask uint32

	// Synchronizes operations on egressPolicies
	egressPoliciesLock sync.Mutex
	egressPolicies     map[uint32][]osdnv1.EgressNetworkPolicy
	egressDNS          *common.EgressDNS

	// Holds runtime endpoint shim to make SDN <-> runtime communication
	runtimeService kubeletapi.RuntimeService

	egressIP *egressIPWatcher
}

// Called by higher layers to create the SDN node instance
func New(c *OsdnNodeConfig) (*OsdnNode, error) {
	node := &OsdnNode{
		clients:   c.SDNClients,
		sdnConfig: c.SDNConfig,
		recorder:  c.Recorder,
		localIP:   c.NodeIP,
		hostName:  c.NodeName,
		ipt:       c.IPTables,
	}

	if err := c.validateNodeIP(); err != nil {
		return nil, err
	}

	var pluginId int
	switch node.sdnConfig.PluginName {
	case networkutils.SingleTenantPluginName:
		node.policy = NewSingleTenantPlugin()
		pluginId = 0
	case networkutils.MultiTenantPluginName:
		node.policy = NewMultiTenantPlugin()
		pluginId = 1
		// Userspace proxy is incompatible with conntrack.
		if c.ProxyConfig.Mode != kubeproxyconfig.ProxyModeUserspace {
			node.useConnTrack = true
		}
	case networkutils.NetworkPolicyPluginName:
		node.policy = NewNetworkPolicyPlugin()
		pluginId = 2
		node.useConnTrack = true
	default:
		return nil, fmt.Errorf("Unknown plugin name %q", node.sdnConfig.PluginName)
	}

	if node.useConnTrack && c.ProxyConfig.Mode == kubeproxyconfig.ProxyModeUserspace {
		return nil, fmt.Errorf("%q plugin is not compatible with proxy-mode %q", node.sdnConfig.PluginName, c.ProxyConfig.Mode)
	}

	klog.Infof("Initializing SDN node %q (%s) of type %q", c.NodeName, c.NodeIP, node.sdnConfig.PluginName)

	ovsif, err := ovs.New(kexec.New(), Br0)
	if err != nil {
		return nil, err
	}
	node.oc = NewOVSController(node.sdnConfig, ovsif, pluginId, node.useConnTrack, node.localIP)

	node.podManager = newPodManager(node.clients, node.sdnConfig, node.policy, node.oc)

	if c.ProxyConfig.IPTables.MasqueradeBit != nil {
		node.masqueradeBitMask = 1 << uint32(*c.ProxyConfig.IPTables.MasqueradeBit)
	}

	node.nodeIPTables = newNodeIPTables(node.sdnConfig, c.IPTables, !node.useConnTrack, node.masqueradeBitMask)

	node.egressPolicies = make(map[uint32][]osdnv1.EgressNetworkPolicy)
	node.egressDNS, err = common.NewEgressDNS(true, false)
	if err != nil {
		return nil, err
	}

	node.egressIP = newEgressIPWatcher(node.clients, node.oc, node.nodeIPTables, node.localIP, node.masqueradeBitMask)

	metrics.RegisterMetrics()

	return node, nil
}

func (c *OsdnNodeConfig) validateNodeIP() error {
	if _, _, err := GetLinkDetails(c.NodeIP); err != nil {
		if err == ErrorNetworkInterfaceNotFound {
			err = fmt.Errorf("node IP %q is not a local/private address (hostname %q)", c.NodeIP, c.NodeName)
		}
		klog.Errorf("Unable to find network interface for node IP; some features will not work! (%v)", err)
	}

	hostIPNets, _, err := common.GetHostIPNetworks([]string{Tun0})
	if err != nil {
		return fmt.Errorf("failed to get host network information: %v", err)
	}
	if err := c.SDNConfig.CheckHostNetworks(hostIPNets); err != nil {
		// checkHostNetworks() errors *should* be fatal, but we didn't used to check this, and we can't break (mostly-)working nodes on upgrade.
		klog.Errorf("Local networks conflict with SDN; this will eventually cause problems: %v", err)
	}

	return nil
}

var (
	ErrorNetworkInterfaceNotFound = fmt.Errorf("could not find network interface")
)

func GetLinkDetails(ip string) (netlink.Link, *net.IPNet, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			klog.Warningf("Could not get addresses of interface %q: %v", link.Attrs().Name, err)
			continue
		}

		for _, addr := range addrs {
			if addr.IP.String() == ip {
				_, ipNet, err := net.ParseCIDR(addr.IPNet.String())
				if err != nil {
					return nil, nil, fmt.Errorf("could not parse CIDR network from address %q: %v", ip, err)
				}
				return link, ipNet, nil
			}
		}
	}

	return nil, nil, ErrorNetworkInterfaceNotFound
}

func (node *OsdnNode) validateMTU() error {
	klog.V(2).Infof("Checking default interface MTU")

	// Get the interface with the default route
	// TODO(cdc) handle v6-only nodes
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("could not list routes while validating MTU: %v", err)
	}
	if len(routes) == 0 {
		return fmt.Errorf("got no routes while validating MTU")
	}

	const maxMTU = 65536
	mtu := maxMTU + 1
	for _, route := range routes {
		// Skip non-default routes
		if route.Dst != nil {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return fmt.Errorf("could not retrieve link id %d while validating MTU", route.LinkIndex)
		}

		// we want to check the mtu only for the interface assigned to the node's primary ip
		found := false
		addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
		for _, address := range addresses {
			if node.localIP == address.IP.String() {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		newmtu := link.Attrs().MTU
		if newmtu > 0 && newmtu < mtu {
			mtu = newmtu
		}
	}
	if mtu > maxMTU {
		return fmt.Errorf("unable to determine MTU while performing validation")
	}

	needsTaint := mtu < node.sdnConfig.MTU+50
	const MTUTaintKey string = "network.openshift.io/mtu-too-small"
	mtuTooSmallTaint := &corev1.Taint{Key: MTUTaintKey, Value: "value", Effect: "NoSchedule"}
	nodeObj, err := node.clients.KubeClient.CoreV1().Nodes().Get(context.TODO(), node.hostName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("could not get Kubernetes Node object by hostname: %v", err)
	}
	tainted := taints.TaintExists(nodeObj.Spec.Taints, mtuTooSmallTaint)
	if needsTaint != tainted {
		resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			nodeObj, err = node.clients.KubeClient.CoreV1().Nodes().Get(context.TODO(), node.hostName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("could not get Kubernetes Node object by hostname: %v", err)
			}
			nodeObjCopy := nodeObj.DeepCopy()
			var nodeWithTaintMods *corev1.Node

			if needsTaint && !tainted {
				klog.V(2).Infof("Default interface MTU is less than VXLAN overhead, tainting node...")
				nodeWithTaintMods, _, err = taints.AddOrUpdateTaint(nodeObjCopy, mtuTooSmallTaint)
				if err != nil {
					return fmt.Errorf("could not taint the node with key %s: %v", MTUTaintKey, err)
				}
			} else if !needsTaint && tainted {
				klog.V(2).Infof("Node has too small MTU taint but default interface MTU is big enough, untainting node...")
				nodeWithTaintMods, _, err = taints.RemoveTaint(nodeObjCopy, mtuTooSmallTaint)
				if err != nil {
					return fmt.Errorf("could not untaint the node with key %s: %v", MTUTaintKey, err)
				}
			}

			nodeObjJson, err := json.Marshal(nodeObj)
			if err != nil {
				return fmt.Errorf("could not marshal old Node object: %v", err)
			}

			newNodeObjJson, err := json.Marshal(nodeWithTaintMods)
			if err != nil {
				return fmt.Errorf("could not marshal new Node object: %v", err)
			}

			patchBytes, err := strategicpatch.CreateTwoWayMergePatch(nodeObjJson, newNodeObjJson, corev1.Node{})
			if err != nil {
				return fmt.Errorf("could not create patch for object: %v", err)
			}

			_, err = node.clients.KubeClient.CoreV1().Nodes().Patch(context.TODO(), node.hostName, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})

			return err
		})

		if resultErr != nil {
			return fmt.Errorf("could not update node taints after many retries: %v", resultErr)
		}
	}

	return nil
}

func (node *OsdnNode) Start() error {
	klog.V(2).Infof("Starting openshift-sdn")

	var err error
	node.localSubnetCIDR, err = node.getLocalSubnet()
	if err != nil {
		return err
	}

	if err = node.nodeIPTables.Setup(); err != nil {
		return fmt.Errorf("failed to set up iptables: %v", err)
	}

	networkChanged, existingOFPodNetworks, err := node.SetupSDN()
	if err != nil {
		return fmt.Errorf("node SDN setup failed: %v", err)
	}

	hsw := newHostSubnetWatcher(node.oc, node.localIP, node.sdnConfig)
	hsw.Start(node.clients.OSDNInformers)

	if err = node.policy.Start(node); err != nil {
		return err
	}
	if node.policy.SupportsVNIDs() {
		if err := node.SetupEgressNetworkPolicy(); err != nil {
			return err
		}
		if err := node.egressIP.Start(); err != nil {
			return err
		}
	}
	if !node.useConnTrack {
		node.watchServices()
	}

	existingPodSandboxes, err := node.getSDNPodSandboxes()
	if err != nil {
		return err
	}

	if err = node.podManager.InitRunningPods(existingPodSandboxes, existingOFPodNetworks); err != nil {
		return err
	}

	klog.V(2).Infof("Starting openshift-sdn pod manager")
	if err := node.podManager.Start(cniserver.CNIServerRunDir, node.localSubnetCIDR); err != nil {
		return err
	}

	if networkChanged && len(existingOFPodNetworks) > 0 {
		err := node.reattachPods(existingPodSandboxes, existingOFPodNetworks)
		if err != nil {
			return err
		}
	}

	if err := node.FinishSetupSDN(); err != nil {
		return fmt.Errorf("could not complete SDN setup: %v", err)
	}

	if err := node.validateMTU(); err != nil {
		klog.Errorf("Error validating node MTU: %v", err)
	}

	go kwait.Forever(node.policy.SyncVNIDRules, time.Hour)
	go kwait.Forever(func() {
		metrics.GatherPeriodicMetrics()
		node.oc.ovs.UpdateOVSMetrics()
	}, time.Minute*2)

	return nil
}

// reattachPods takes an array containing the information about pods that had been
// attached to the OVS bridge before restart, and either reattaches or kills each of the
// corresponding pods.
func (node *OsdnNode) reattachPods(existingPodSandboxes map[string]*kruntimeapi.PodSandbox, existingOFPodNetworks map[string]podNetworkInfo) error {
	for sandboxID, podInfo := range existingOFPodNetworks {
		sandbox, ok := existingPodSandboxes[sandboxID]
		if !ok {
			klog.V(5).Infof("Sandbox for pod with IP %s no longer exists", podInfo.ip)
			continue
		}
		if _, err := netlink.LinkByName(podInfo.vethName); err != nil {
			klog.Infof("Interface %s for pod '%s/%s' no longer exists", podInfo.vethName, sandbox.Metadata.Namespace, sandbox.Metadata.Name)
			continue
		}

		req := &cniserver.PodRequest{
			Command:      cniserver.CNI_ADD,
			PodNamespace: sandbox.Metadata.Namespace,
			PodName:      sandbox.Metadata.Name,
			SandboxID:    sandboxID,
			HostVeth:     podInfo.vethName,
			AssignedIP:   podInfo.ip,
			Result:       make(chan *cniserver.PodResult),
		}
		klog.Infof("Reattaching pod '%s/%s' to SDN", req.PodNamespace, req.PodName)
		// NB: we don't need to worry about locking here because the cniserver
		// isn't running for real yet.
		if _, err := node.podManager.handleCNIRequest(req); err == nil {
			delete(existingPodSandboxes, sandboxID)
		} else {
			klog.Warningf("Could not reattach pod '%s/%s' to SDN: %v", req.PodNamespace, req.PodName, err)
		}
	}

	// Kill any remaining pods in another thread, after letting SDN startup proceed
	go node.killFailedPods(existingPodSandboxes)

	return nil
}

func (node *OsdnNode) killFailedPods(failed map[string]*kruntimeapi.PodSandbox) {
	// Kill pods we couldn't recover; they will get restarted and then
	// we'll be able to set them up correctly
	for _, sandbox := range failed {
		podRef := &corev1.ObjectReference{Kind: "Pod", Name: sandbox.Metadata.Name, Namespace: sandbox.Metadata.Namespace, UID: types.UID(sandbox.Metadata.Uid)}
		node.recorder.Eventf(podRef, corev1.EventTypeWarning, "NetworkFailed", "The pod's network interface has been lost and the pod will be stopped.")

		klog.V(5).Infof("Killing pod '%s/%s' sandbox", podRef.Namespace, podRef.Name)
		if err := node.runtimeService.StopPodSandbox(sandbox.Id); err != nil {
			klog.Warningf("Failed to kill pod '%s/%s' sandbox: %v", podRef.Namespace, podRef.Name, err)
		}
	}
}

// FIXME: this should eventually go into kubelet via a CNI UPDATE/CHANGE action
// See https://github.com/containernetworking/cni/issues/89
func (node *OsdnNode) UpdatePod(pod corev1.Pod) error {
	filter := &kruntimeapi.PodSandboxFilter{
		LabelSelector: map[string]string{ktypes.KubernetesPodUIDLabel: string(pod.UID)},
	}
	sandboxID, err := node.getPodSandboxID(filter)
	if err != nil {
		return err
	}

	req := &cniserver.PodRequest{
		Command:      cniserver.CNI_UPDATE,
		PodNamespace: pod.Namespace,
		PodName:      pod.Name,
		SandboxID:    sandboxID,
		Result:       make(chan *cniserver.PodResult),
	}

	// Send request and wait for the result
	_, err = node.podManager.handleCNIRequest(req)
	return err
}

func (node *OsdnNode) GetRunningPods(namespace string) ([]corev1.Pod, error) {
	fieldSelector := fields.Set{"spec.nodeName": node.hostName}.AsSelector()
	opts := metav1.ListOptions{
		LabelSelector: labels.Everything().String(),
		FieldSelector: fieldSelector.String(),
	}
	podList, err := node.clients.KubeClient.CoreV1().Pods(namespace).List(context.TODO(), opts)
	if err != nil {
		return nil, err
	}

	// Filter running pods
	pods := make([]corev1.Pod, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			pods = append(pods, pod)
		}
	}
	return pods, nil
}

func isServiceChanged(oldsvc, newsvc *corev1.Service) bool {
	if len(oldsvc.Spec.Ports) == len(newsvc.Spec.Ports) {
		for i := range oldsvc.Spec.Ports {
			if oldsvc.Spec.Ports[i].Protocol != newsvc.Spec.Ports[i].Protocol ||
				oldsvc.Spec.Ports[i].Port != newsvc.Spec.Ports[i].Port {
				return true
			}
		}
		return false
	}
	return true
}

func (node *OsdnNode) watchServices() {
	funcs := common.InformerFuncs(&kapi.Service{}, node.handleAddOrUpdateService, node.handleDeleteService)
	node.clients.KubeInformers.Core().V1().Services().Informer().AddEventHandler(funcs)
}

func (node *OsdnNode) handleAddOrUpdateService(obj, oldObj interface{}, eventType watch.EventType) {
	serv := obj.(*corev1.Service)
	// Ignore headless/external services
	if !helper.IsServiceIPSet(serv) {
		return
	}

	klog.V(5).Infof("Watch %s event for Service %q", eventType, serv.Name)
	oldServ, exists := oldObj.(*corev1.Service)
	if exists {
		if !isServiceChanged(oldServ, serv) {
			return
		}
		node.DeleteServiceRules(oldServ)
	}

	netid, err := node.policy.GetVNID(serv.Namespace)
	if err != nil {
		klog.Errorf("Skipped adding service rules for serviceEvent: %v, Error: %v", eventType, err)
		return
	}

	node.AddServiceRules(serv, netid)
	node.policy.EnsureVNIDRules(netid)
}

func (node *OsdnNode) handleDeleteService(obj interface{}) {
	serv := obj.(*corev1.Service)
	// Ignore headless/external services
	if !helper.IsServiceIPSet(serv) {
		return
	}

	klog.V(5).Infof("Watch %s event for Service %q", watch.Deleted, serv.Name)
	node.DeleteServiceRules(serv)
}

func (node *OsdnNode) ReloadIPTables() error {
	return node.nodeIPTables.syncIPTableRules()
}
