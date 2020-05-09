// +build linux

package node

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"k8s.io/klog/v2"

	networkapi "github.com/openshift/api/network/v1"
	"github.com/openshift/sdn/pkg/network/common"
	"github.com/openshift/sdn/pkg/network/node/ovs"

	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilnet "k8s.io/utils/net"
)

// openshift-sdn OVS flows

// Table 0: preliminaries, and initial dispatch based on in_port
//   acceptable incoming VXLAN traffic (in_port=1) goes to table 10 for validation
//   outbound service traffic returning from iptables goes to table 25
//   acceptable incoming tun0 traffic (in_port=2) goes to table 30 (general routing)
//   traffic from any other port is assumed to be from a container and goes to table 20

// Table 10: VXLAN ingress filtering
//   per-remote-node rules are filled in by AddHostSubnetRules()
//   any VXLAN traffic from a non-node IP is dropped

// Table 20: from OpenShift container
//   filled in by setupPodFlows
//   validates IP/MAC, assigns VNID to reg0
//   accepted traffic goes to table 21

// Table 21: from OpenShift container, part 2
//   NetworkPolicy mode uses this for connection tracking
//   all traffic then goes to table 30

// Table 25: IP from OpenShift container via Service IP
//   filled in by setupPodFlows
//   catches traffic which was originally sent from a local container to a service IP which
//     has been sent through iptables and now returned into the pod network with a rewritten
//     destination IP. Reloads the VNID to reg0 then passes to table 30

// Table 30: general routing
//   ARP/IP to local subnet gateway IP is output on tun0
//   ARP to local containers goes to table 40
//   ARP to remote containers goes to table 50
//   IP to service IPs goes to table 60
//   IP to local containers goes to table 70
//   multicast from local pods goes to table 110
//   multicast from the VXLAN goes to table 120

// Table 40: ARP to local container
//   filled in by setupPodFlows
//   traffic is output to container port

// Table 50: ARP to remote container
//   filled in by AddHostSubnetRules()
//   traffic is output to vxlan0 with correct tun_dst

// Table 60: Multitenant IP to service from pod
//   was used in Multitenant mode. Now unused

// Table 70: IP to local container
//   filled in by setupPodFlows
//   loads the VNID and port number of the destination pod into reg1 and reg2 then
//     goes to table 80

// Table 80: IP policy enforcement
//   rules implementing NetworkPolicies
//   accepted traffic is output to the port in reg2

// Table 90: IP to remote container
//   filled in by AddHostSubnetRules()
//   traffic is output to vxlan0 with correct tun_dst

// Table 100: egress routing
//   edited by SetNamespaceEgress*()
//   traffic destined for an egress IP is forwarded to the correct node
//   other traffic goes to table 101

// Table 101: egress network policy dispatch
//   edited by UpdateEgressNetworkPolicy()
//   rules implementing EgressNetworkPolicies
//   unmatched/allowed traffic is output to tun0

// Table 110: outbound multicast filtering
//   updated by UpdateLocalMulticastFlows()
//   per-Namespace rules for namespaces that accept multicast, forwarding to table 111
//   unmatched traffic is dropped

// Table 111: multicast delivery from local pods to the VXLAN
//   only one rule, updated by UpdateVXLANMulticastRule
//   send to every other node then goes to table 120

// Table 120: multicast delivery to local pods
//   updated by UpdateLocalMulticastFlows()
//   per-Namespace rules to output multicast packets to each pod port in that namespace

type ovsController struct {
	ovs      ovs.Interface
	localIPs []string
	tunMAC   string
}

const (
	Br0    = "br0"
	Tun0   = "tun0"
	Vxlan0 = "vxlan0"

	// plugin ID; 2 for ovs-networkpolicy
	pluginID = 2

	// rule versioning; increment each time flow rules change
	ruleVersion = 11

	ruleVersionTable = 253
)

func NewOVSController(ovsif ovs.Interface, localIPs []string) *ovsController {
	return &ovsController{ovs: ovsif, localIPs: localIPs}
}

func (oc *ovsController) getVersionNote() string {
	if ruleVersion > 254 {
		panic("Version too large!")
	}
	return fmt.Sprintf("%02X.%02X", pluginID, ruleVersion)
}

func (oc *ovsController) AlreadySetUp(vxlanPort uint32) bool {
	flows, err := oc.ovs.DumpFlows("table=%d", ruleVersionTable)
	if err != nil || len(flows) != 1 {
		return false
	}

	port, err := oc.ovs.Get("Interface", Vxlan0, "options:dst_port")
	// the call to ovs.Get() returns the port number surrounded by double quotes
	// so add them to the structs value for purposes of comparison
	if err != nil || fmt.Sprintf("\"%d\"", vxlanPort) != port {
		return false
	}
	if parsed, err := ovs.ParseFlow(ovs.ParseForDump, flows[0]); err == nil {
		return parsed.NoteHasPrefix(oc.getVersionNote())
	}
	return false
}

func (oc *ovsController) SetupOVS(clusterNetworkCIDRs, serviceNetworkCIDRs, localSubnetCIDRs, localSubnetGateways []string, mtu uint32, vxlanPort uint32) error {
	err := oc.ovs.DeleteBridge()
	if err != nil {
		return err
	}
	err = oc.ovs.AddBridge("fail_mode=secure", "protocols=OpenFlow13")
	if err != nil {
		return err
	}
	err = oc.ovs.SetFrags("nx-match")
	if err != nil {
		return err
	}
	_ = oc.ovs.DeletePort(Vxlan0)
	_, err = oc.ovs.AddPort(Vxlan0, 1, "type=vxlan", `options:remote_ip="flow"`, `options:key="flow"`, fmt.Sprintf("options:dst_port=%d", vxlanPort))
	if err != nil {
		return err
	}
	_ = oc.ovs.DeletePort(Tun0)
	_, err = oc.ovs.AddPort(Tun0, 2, "type=internal", fmt.Sprintf("mtu_request=%d", mtu))
	if err != nil {
		return err
	}

	otx := oc.ovs.NewTransaction()
	oc.addCoreFlows(otx, vxlanPort)

	for i, localSubnetCIDR := range localSubnetCIDRs {
		isIPv6 := utilnet.IsIPv6CIDRString(localSubnetCIDR)

		matchingClusterCIDRs := make([]string, 0, 1)
		for _, cidr := range clusterNetworkCIDRs {
			if utilnet.IsIPv6CIDRString(cidr) == isIPv6 {
				matchingClusterCIDRs = append(matchingClusterCIDRs, cidr)
			}
		}
		oc.addBaseFlowsForIPFamily(otx, matchingClusterCIDRs, serviceNetworkCIDRs[i], localSubnetCIDRs[i], localSubnetGateways[i])
	}

	return otx.Commit()
}

func (oc *ovsController) addCoreFlows(otx ovs.Transaction, vxlanPort uint32) {
	// Initial rule to load conntrack info
	otx.AddFlow("table=0, priority=1000, ip, ct_state=-trk, actions=ct(table=0)")

	// Every table ends with either "drop anything that wasn't recognized" or "send
	// anything that wasn't recognized to another table"
	otx.AddFlow("table=0, priority=0, actions=drop")
	otx.AddFlow("table=10, priority=0, actions=drop")
	otx.AddFlow("table=20, priority=0, actions=drop")
	otx.AddFlow("table=21, priority=0, actions=goto_table:30")
	otx.AddFlow("table=25, priority=0, actions=drop")
	otx.AddFlow("table=30, priority=0, arp, actions=drop")
	otx.AddFlow("table=30, priority=0, ip, actions=goto_table:100")
	otx.AddFlow("table=40, priority=0, actions=drop")
	otx.AddFlow("table=50, priority=0, actions=drop")
	otx.AddFlow("table=70, priority=0, actions=drop")
	otx.AddFlow("table=80, priority=0, actions=drop")
	otx.AddFlow("table=90, priority=0, actions=drop")
	otx.AddFlow("table=100, priority=0, actions=goto_table:101")
	otx.AddFlow("table=101, priority=0, actions=output:2")
	otx.AddFlow("table=110, priority=0, actions=drop")
	otx.AddFlow("table=111, priority=0, actions=goto_table:120")
	otx.AddFlow("table=120, priority=0, actions=drop")

	// Table 0 (initial dispatch) has different rules depending on in_port
	// (FIXME: this could be split into multiple tables)
	otx.AddFlow("table=0, priority=150, in_port=1, actions=drop")
	otx.AddFlow("table=0, priority=200, in_port=2, ip, actions=goto_table:30")
	otx.AddFlow("table=0, priority=150, in_port=2, actions=drop")
	otx.AddFlow("table=0, priority=100, arp, actions=goto_table:20")
	otx.AddFlow("table=0, priority=100, ip, actions=goto_table:20")

	// Table 100 (egress routing) starts with a security-related rule
	otx.AddFlow("table=100, priority=300, udp, udp_dst=%d, actions=drop", vxlanPort)

	// Special rule to always allow DNS to the node, bypassing EgressNetworkPolicy
	for _, localIP := range oc.localIPs {
		otx.AddFlow("table=100, priority=200, tcp, tcp_dst=53, nw_dst=%s, actions=output:2", localIP)
		otx.AddFlow("table=100, priority=200, udp, udp_dst=53, nw_dst=%s, actions=output:2", localIP)
	}

	// Likewise always allow replies through
	otx.AddFlow("table=100, priority=150, ct_state=+rpl, actions=goto_table:101")
}

func (oc *ovsController) addBaseFlowsForIPFamily(otx ovs.Transaction, clusterNetworkCIDRs []string, serviceNetworkCIDR, localSubnetCIDR, localSubnetGateway string) {
	isIPv6 := utilnet.IsIPv6String(localSubnetGateway)
	var multicastCIDR, localSubnetGatewayMatch string
	if isIPv6 {
		multicastCIDR = "ff00::/8"
		localSubnetGatewayMatch = localSubnetGateway + "/128"
	} else {
		multicastCIDR = "224.0.0.0/4"
		localSubnetGatewayMatch = localSubnetGateway + "/32"
	}

	// On vxlan0, accept incoming ARP packets for local pods, and incoming IP packets either to or from
	// anywhere in the cluster. (Notably, packets being sent to an egress IP will not have a destination
	// within the cluster, but are valid as long as they came from within the cluster.)
	for _, clusterCIDR := range clusterNetworkCIDRs {
		otx.AddFlow("table=0, priority=200, in_port=1, arp, nw_src=%s, nw_dst=%s, actions=move:NXM_NX_TUN_ID[0..31]->NXM_NX_REG0[],goto_table:10", clusterCIDR, localSubnetCIDR)
		otx.AddFlow("table=0, priority=200, in_port=1, ip, nw_src=%s, actions=move:NXM_NX_TUN_ID[0..31]->NXM_NX_REG0[],goto_table:10", clusterCIDR)
		otx.AddFlow("table=0, priority=200, in_port=1, ip, nw_dst=%s, actions=move:NXM_NX_TUN_ID[0..31]->NXM_NX_REG0[],goto_table:10", clusterCIDR)
	}

	// If we receive a packet from tun0 whose source IP is a local pod IP, that means we previously
	// sent it out tun0 to run through Service iptables rules, and now we need to send it to table 25
	// to reload its VNID
	otx.AddFlow("table=0, priority=400, in_port=2, ip, nw_src=%s, actions=goto_table:30", localSubnetGateway)
	for _, clusterCIDR := range clusterNetworkCIDRs {
		otx.AddFlow("table=0, priority=300, in_port=2, ip, nw_src=%s, nw_dst=%s, actions=goto_table:25", localSubnetCIDR, clusterCIDR)
	}
	// Otherwise, from tun0, we reject multicast IPs, and accept ARP requests from the
	// local node for cluster network IPs. (Other IPs will be accepted, and other ARPs
	// rejected, by the rules from addCoreFlows.)
	otx.AddFlow("table=0, priority=250, in_port=2, ip, nw_dst=%s, actions=drop", multicastCIDR)
	for _, clusterCIDR := range clusterNetworkCIDRs {
		otx.AddFlow("table=0, priority=200, in_port=2, arp, nw_src=%s, nw_dst=%s, actions=goto_table:30", localSubnetGateway, clusterCIDR)
	}

	// Table 30: general routing
	otx.AddFlow("table=30, priority=300, arp, nw_dst=%s, actions=output:2", localSubnetGateway)
	otx.AddFlow("table=30, priority=200, arp, nw_dst=%s, actions=goto_table:40", localSubnetCIDR)
	for _, clusterCIDR := range clusterNetworkCIDRs {
		otx.AddFlow("table=30, priority=100, arp, nw_dst=%s, actions=goto_table:50", clusterCIDR)
	}
	otx.AddFlow("table=30, priority=300, ip, nw_dst=%s, actions=output:2", localSubnetGateway)
	otx.AddFlow("table=30, priority=100, ip, nw_dst=%s, actions=output:2", serviceNetworkCIDR)
	otx.AddFlow("table=30, priority=250, ip, nw_dst=%s, ct_state=+rpl, actions=ct(nat,table=70)", localSubnetCIDR)
	otx.AddFlow("table=30, priority=200, ip, nw_dst=%s, actions=goto_table:70", localSubnetCIDR)
	for _, clusterCIDR := range clusterNetworkCIDRs {
		otx.AddFlow("table=30, priority=100, ip, nw_dst=%s, actions=goto_table:90", clusterCIDR)
	}

	// Multicast coming from the VXLAN
	otx.AddFlow("table=30, priority=50, in_port=1, ip, nw_dst=%s, actions=goto_table:120", multicastCIDR)
	// Multicast coming from local pods
	otx.AddFlow("table=30, priority=25, ip, nw_dst=224.0.0.0/4, actions=goto_table:110")
	otx.AddFlow("table=30, priority=25, ip, nw_dst=ff00::/8, actions=goto_table:110")

	otx.AddFlow("table=30, priority=0, ip, actions=goto_table:100")
	otx.AddFlow("table=30, priority=0, arp, actions=drop")

	// Table 40: ARP to local container, filled in by setupPodFlows
	// eg, "table=40, priority=100, arp, nw_dst=${container_ip}, actions=output:${ovs_port}"
	otx.AddFlow("table=40, priority=0, actions=drop")

	// Table 50: ARP to remote container; filled in by AddHostSubnetRules()
	// eg, "table=50, priority=100, arp, nw_dst=${remote_subnet_cidr}, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31], set_field:${remote_node_ip}->tun_dst,output:1"
	otx.AddFlow("table=50, priority=0, actions=drop")

	// Table 60 was "IP to service from pod" in the multitenant plugin but is unused now

	// Table 70: IP to local container: vnid/port mappings; filled in by setupPodFlows
	// eg, "table=70, priority=100, ip, nw_dst=${ipaddr}, actions=load:${tenant_id}->NXM_NX_REG1[], load:${ovs_port}->NXM_NX_REG2[], goto_table:80"
	otx.AddFlow("table=70, priority=0, actions=drop")

	// Special rule to always allow connections from the node to the pod, bypassing NetworkPolicy
	otx.AddFlow("table=80, priority=300, ip, nw_src=%s, actions=output:NXM_NX_REG2[]", localSubnetGatewayMatch)
}

// Perform the final step of SDN setup; this is done after everything else, so if the SDN
// pod is killed partway through setup, then when it is restarted, oc.AlreadySetUp() will
// fail and we'll destroy and recreate the bridge again.
func (oc *ovsController) FinishSetupOVS() error {
	otx := oc.ovs.NewTransaction()

	// Table 253: rule version note
	otx.AddFlow("table=%d, actions=note:%s", ruleVersionTable, oc.getVersionNote())

	return otx.Commit()
}

type podNetworkInfo struct {
	vethName string
	ips      []string
	ofport   int
}

// GetPodNetworkInfo returns network interface information about all currently-attached pods.
func (oc *ovsController) GetPodNetworkInfo() (map[string]podNetworkInfo, error) {
	rows, err := oc.ovs.Find("interface", []string{"name", "external_ids", "ofport"}, "external_ids:sandbox!=\"\"")
	if err != nil {
		return nil, err
	}

	results := make(map[string]podNetworkInfo)
	for _, row := range rows {
		if row["name"] == "" || row["external_ids"] == "" || row["ofport"] == "" {
			utilruntime.HandleError(fmt.Errorf("ovs-vsctl output missing one or more fields: %v", row))
			continue
		}

		ids, err := ovs.ParseExternalIDs(row["external_ids"])
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("Could not parse external_ids %q: %v", row["external_ids"], err))
			continue
		}
		if ids["ips"] == "" || ids["sandbox"] == "" {
			utilruntime.HandleError(fmt.Errorf("ovs-vsctl output missing one or more external_ids: %v", ids))
			continue
		}
		ips := strings.Split(ids["ips"], " ")
		for _, ip := range ips {
			if net.ParseIP(ip) == nil {
				utilruntime.HandleError(fmt.Errorf("Could not parse IP %q for sandbox %q", ip, ids["sandbox"]))
				ips = nil
				break
			}
		}
		if ips == nil {
			continue
		}

		ofport, err := strconv.Atoi(row["ofport"])
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("Could not parse ofport %q: %v", row["ofport"], err))
			continue
		}

		results[ids["sandbox"]] = podNetworkInfo{
			vethName: row["name"],
			ips:      ips,
			ofport:   ofport,
		}
	}

	return results, nil
}

func (oc *ovsController) NewTransaction() ovs.Transaction {
	return oc.ovs.NewTransaction()
}

func (oc *ovsController) ensureOvsPort(hostVeth, sandboxID string, podIPs []net.IP) (int, error) {
	ipStrings := make([]string, len(podIPs))
	for i := range podIPs {
		ipStrings[i] = podIPs[i].String()
	}
	ofport, err := oc.ovs.AddPort(hostVeth, -1,
		fmt.Sprintf(`external_ids=sandbox="%s",ips="%s"`, sandboxID, strings.Join(ipStrings, " ")),
	)
	if err != nil {
		// If hostVeth doesn't exist, ovs-vsctl will return an error, but will
		// still add an entry to the database anyway.
		_ = oc.ovs.DeletePort(hostVeth)
	}
	return ofport, err
}

func (oc *ovsController) setupPodFlows(ofport int, podIP net.IP, vnid uint32) error {
	otx := oc.ovs.NewTransaction()

	ipstr := podIP.String()

	// IPV6FIXME - sdn-cni-plugin is currently leaving the MAC random for IPv6
	ipmacMatch := ""
	if !utilnet.IsIPv6(podIP) {
		podIP = podIP.To4()
		ipmacMatch = fmt.Sprintf(", arp_sha=00:00:%02x:%02x:%02x:%02x/00:00:ff:ff:ff:ff", podIP[0], podIP[1], podIP[2], podIP[3])
	}

	// ARP/IP traffic from container
	otx.AddFlow("table=20, priority=100, in_port=%d, arp, nw_src=%s%s, actions=load:%d->NXM_NX_REG0[], goto_table:21", ofport, ipstr, ipmacMatch, vnid)
	otx.AddFlow("table=20, priority=100, in_port=%d, ip, nw_src=%s, actions=load:%d->NXM_NX_REG0[], goto_table:21", ofport, ipstr, vnid)
	otx.AddFlow("table=25, priority=100, ip, nw_src=%s, actions=load:%d->NXM_NX_REG0[], goto_table:30", ipstr, vnid)

	// ARP request/response to container (not isolated)
	otx.AddFlow("table=40, priority=100, arp, nw_dst=%s, actions=output:%d", ipstr, ofport)

	// IP traffic to container
	otx.AddFlow("table=70, priority=100, ip, nw_dst=%s, actions=load:%d->NXM_NX_REG1[], load:%d->NXM_NX_REG2[], goto_table:80", ipstr, vnid, ofport)

	return otx.Commit()
}

func (oc *ovsController) cleanupPodFlows(podIP net.IP) error {
	ipstr := podIP.String()

	otx := oc.ovs.NewTransaction()
	otx.DeleteFlows("ip, nw_dst=%s", ipstr)
	otx.DeleteFlows("ip, nw_src=%s", ipstr)
	otx.DeleteFlows("arp, nw_dst=%s", ipstr)
	otx.DeleteFlows("arp, nw_src=%s", ipstr)
	return otx.Commit()
}

func (oc *ovsController) SetUpPod(sandboxID, hostVeth string, podIPs []net.IP, vnid uint32) (int, error) {
	ofport, err := oc.ensureOvsPort(hostVeth, sandboxID, podIPs)
	if err != nil {
		return -1, err
	}
	for _, podIP := range podIPs {
		err = oc.setupPodFlows(ofport, podIP, vnid)
		if err != nil {
			return -1, err
		}
	}
	return ofport, nil
}

// Returned list can also be used for port names
func (oc *ovsController) getInterfacesForSandbox(sandboxID string) ([]string, error) {
	return oc.ovs.FindOne("interface", "name", "external_ids:sandbox="+sandboxID)
}

func (oc *ovsController) ClearPodBandwidth(portList []string, sandboxID string) error {
	// Clear the QoS for any ports of this sandbox
	for _, port := range portList {
		if err := oc.ovs.Clear("port", port, "qos"); err != nil {
			return err
		}
	}

	// Now that the QoS is unused remove it
	qosList, err := oc.ovs.FindOne("qos", "_uuid", "external_ids:sandbox="+sandboxID)
	if err != nil {
		return err
	}
	for _, qos := range qosList {
		if err := oc.ovs.Destroy("qos", qos); err != nil {
			return err
		}
	}

	return nil
}

func (oc *ovsController) SetPodBandwidth(hostVeth, sandboxID string, ingressBPS, egressBPS int64) error {
	// note pod ingress == OVS egress and vice versa

	ports, err := oc.getInterfacesForSandbox(sandboxID)
	if err != nil {
		return err
	}

	if err := oc.ClearPodBandwidth(ports, sandboxID); err != nil {
		return err
	}

	if ingressBPS > 0 {
		qos, err := oc.ovs.Create("qos", "type=linux-htb", fmt.Sprintf("other_config:max-rate=%d", ingressBPS), "external_ids=sandbox="+sandboxID)
		if err != nil {
			return err
		}
		err = oc.ovs.Set("port", hostVeth, fmt.Sprintf("qos=%s", qos))
		if err != nil {
			return err
		}
	}
	if egressBPS > 0 {
		// ingress_policing_rate is in Kbps
		err := oc.ovs.Set("interface", hostVeth, fmt.Sprintf("ingress_policing_rate=%d", egressBPS/1024))
		if err != nil {
			return err
		}
	}

	return nil
}

func (oc *ovsController) getPodDetailsBySandboxID(sandboxID string) (int, []net.IP, error) {
	rows, err := oc.ovs.Find("interface", []string{"ofport", "external_ids"}, "external_ids:sandbox="+sandboxID)
	if err != nil {
		return 0, nil, err
	}

	if len(rows) == 0 {
		return 0, nil, fmt.Errorf("failed to find pod details in OVS database")
	} else if len(rows) > 1 {
		return 0, nil, fmt.Errorf("found multiple pods for sandbox ID %q: %#v", sandboxID, rows)
	}

	ofport, err := strconv.Atoi(rows[0]["ofport"])
	if err != nil {
		return 0, nil, fmt.Errorf("could not parse ofport %q: %v", rows[0]["ofport"], err)
	}

	ids, err := ovs.ParseExternalIDs(rows[0]["external_ids"])
	if err != nil {
		return 0, nil, fmt.Errorf("could not parse external_ids %q: %v", rows[0]["external_ids"], err)
	} else if ids["ips"] == "" {
		return 0, nil, fmt.Errorf("external_ids %#v does not contain IPs", ids)
	}
	var podIPs []net.IP
	for _, ipstr := range strings.Split(ids["ips"], " ") {
		podIP := net.ParseIP(ipstr)
		if podIP == nil {
			return 0, nil, fmt.Errorf("failed to parse IP %q", ipstr)
		}
		podIPs = append(podIPs, podIP)
	}

	return ofport, podIPs, nil
}

func (oc *ovsController) UpdatePod(sandboxID string, vnid uint32) error {
	ofport, podIPs, err := oc.getPodDetailsBySandboxID(sandboxID)
	if err != nil {
		return err
	} else if ofport == -1 {
		return fmt.Errorf("can't update pod %q with missing veth interface", sandboxID)
	}
	for _, podIP := range podIPs {
		err = oc.cleanupPodFlows(podIP)
		if err != nil {
			return err
		}
		err = oc.setupPodFlows(ofport, podIP, vnid)
		if err != nil {
			return err
		}
	}
	return nil
}

func (oc *ovsController) TearDownPod(sandboxID string) error {
	_, podIPs, err := oc.getPodDetailsBySandboxID(sandboxID)
	if err != nil {
		// OVS flows related to sandboxID not found
		// Nothing needs to be done in that case
		return nil
	}

	for _, podIP := range podIPs {
		if err := oc.cleanupPodFlows(podIP); err != nil {
			return err
		}
	}

	ports, err := oc.getInterfacesForSandbox(sandboxID)
	if err != nil {
		return err
	}

	if err := oc.ClearPodBandwidth(ports, sandboxID); err != nil {
		return err
	}

	for _, port := range ports {
		if err := oc.ovs.DeletePort(port); err != nil {
			return err
		}
	}

	return nil
}

func policyNames(policies []networkapi.EgressNetworkPolicy) string {
	names := make([]string, len(policies))
	for i, policy := range policies {
		names[i] = policy.Namespace + ":" + policy.Name
	}
	return strings.Join(names, ", ")
}

func (oc *ovsController) UpdateEgressNetworkPolicyRules(policies []networkapi.EgressNetworkPolicy, vnid uint32, egressDNS *common.EgressDNS) error {
	otx := oc.ovs.NewTransaction()
	errs := []error{}

	if len(policies) == 0 {
		otx.DeleteFlows("table=101, reg0=%d", vnid)
	} else if vnid == 0 {
		errs = append(errs, fmt.Errorf("EgressNetworkPolicy in global network namespace is not allowed (%s); ignoring", policyNames(policies)))
	} else if len(policies) > 1 {
		// Rationale: If we have allowed more than one policy, we could end up with different network restrictions depending
		// on the order of policies that were processed and also it doesn't give more expressive power than a single policy.
		errs = append(errs, fmt.Errorf("multiple EgressNetworkPolicies in same network namespace (%s) is not allowed; dropping all traffic", policyNames(policies)))
		otx.DeleteFlows("table=101, reg0=%d", vnid)
		otx.AddFlow("table=101, reg0=%d, priority=1, actions=drop", vnid)
	} else /* vnid != 0 && len(policies) == 1 */ {
		otx.DeleteFlows("table=101, reg0=%d", vnid)

		for i, rule := range policies[0].Spec.Egress {
			priority := len(policies[0].Spec.Egress) - i

			var action string
			if rule.Type == networkapi.EgressNetworkPolicyRuleAllow {
				action = "output:2"
			} else {
				action = "drop"
			}

			var selectors []string
			if len(rule.To.CIDRSelector) > 0 {
				selectors = append(selectors, rule.To.CIDRSelector)
			} else if len(rule.To.DNSName) > 0 {
				ips := egressDNS.GetIPs(rule.To.DNSName)
				for _, ip := range ips {
					selectors = append(selectors, ip.String())
				}
			}

			for _, selector := range selectors {
				var dst string
				if selector == "0.0.0.0/0" || selector == "::/0" {
					dst = ""
				} else if selector == "0.0.0.0/32" {
					klog.Warningf("Correcting CIDRSelector '0.0.0.0/32' to '0.0.0.0/0' in EgressNetworkPolicy %s:%s", policies[0].Namespace, policies[0].Name)
					dst = ""
				} else {
					dst = fmt.Sprintf(", nw_dst=%s", selector)
				}

				otx.AddFlow("table=101, reg0=%d, priority=%d, ip%s, actions=%s", vnid, priority, dst, action)
			}
		}
	}

	if txErr := otx.Commit(); txErr != nil {
		errs = append(errs, txErr)
	}

	return kerrors.NewAggregate(errs)
}

func hostSubnetCookie(subnet *networkapi.HostSubnet) uint32 {
	hash := sha256.Sum256([]byte(subnet.UID))
	return (uint32(hash[0]) << 24) | (uint32(hash[1]) << 16) | (uint32(hash[2]) << 8) | uint32(hash[3])
}

func (oc *ovsController) AddHostSubnetRules(subnet *networkapi.HostSubnet) error {
	cookie := hostSubnetCookie(subnet)
	otx := oc.ovs.NewTransaction()

	otx.AddFlow("table=10, priority=100, cookie=0x%08x, tun_src=%s, actions=goto_table:30", cookie, subnet.HostIP)
	if vnid, ok := subnet.Annotations[networkapi.FixedVNIDHostAnnotation]; ok {
		otx.AddFlow("table=50, priority=100, cookie=0x%08x, arp, nw_dst=%s, actions=load:%s->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:1", cookie, subnet.Subnet, vnid, subnet.HostIP)
		otx.AddFlow("table=90, priority=100, cookie=0x%08x, ip, nw_dst=%s, actions=load:%s->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:1", cookie, subnet.Subnet, vnid, subnet.HostIP)
	} else {
		otx.AddFlow("table=50, priority=100, cookie=0x%08x, arp, nw_dst=%s, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:1", cookie, subnet.Subnet, subnet.HostIP)
		otx.AddFlow("table=90, priority=100, cookie=0x%08x, ip, nw_dst=%s, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:1", cookie, subnet.Subnet, subnet.HostIP)
	}

	return otx.Commit()
}

func (oc *ovsController) DeleteHostSubnetRules(subnet *networkapi.HostSubnet) error {
	cookie := hostSubnetCookie(subnet)

	otx := oc.ovs.NewTransaction()
	otx.DeleteFlows("table=10, cookie=0x%08x/0xffffffff, tun_src=%s", cookie, subnet.HostIP)
	otx.DeleteFlows("table=50, cookie=0x%08x/0xffffffff, arp, nw_dst=%s", cookie, subnet.Subnet)
	otx.DeleteFlows("table=90, cookie=0x%08x/0xffffffff, ip, nw_dst=%s", cookie, subnet.Subnet)
	return otx.Commit()
}

func (oc *ovsController) UpdateLocalMulticastFlows(vnid uint32, enabled bool, ofports []int) error {
	otx := oc.ovs.NewTransaction()

	if enabled {
		otx.AddFlow("table=110, reg0=%d, actions=goto_table:111", vnid)
	} else {
		otx.DeleteFlows("table=110, reg0=%d", vnid)
	}

	var actions []string
	if enabled && len(ofports) > 0 {
		actions = make([]string, len(ofports))
		for i, ofport := range ofports {
			actions[i] = fmt.Sprintf("output:%d", ofport)
		}
		sort.Strings(actions)
		otx.AddFlow("table=120, priority=100, reg0=%d, actions=%s", vnid, strings.Join(actions, ","))
	} else {
		otx.DeleteFlows("table=120, reg0=%d", vnid)
	}

	return otx.Commit()
}

func (oc *ovsController) UpdateVXLANMulticastFlows(remoteIPs []string) error {
	otx := oc.ovs.NewTransaction()

	if len(remoteIPs) > 0 {
		actions := make([]string, len(remoteIPs))
		for i, ip := range remoteIPs {
			actions[i] = fmt.Sprintf("set_field:%s->tun_dst,output:1", ip)
		}
		sort.Strings(actions)
		otx.AddFlow("table=111, priority=0, actions=move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],%s,goto_table:120", strings.Join(actions, ","))
	} else {
		otx.AddFlow("table=111, priority=0, actions=goto_table:120")
	}

	return otx.Commit()
}

// FindPolicyVNIDs returns the set of VNIDs for which there are currently "policy" rules
// in OVS. (This is used to reinitialize the osdnPolicy after a restart.)
// We also include inUseVNIDs because if a namespace has only a deny all rule
// policyVNIDs won't include that namespace.
func (oc *ovsController) FindPolicyVNIDs() sets.Int {
	inUseVNIDs, policyVNIDs := oc.findInUseAndPolicyVNIDs()
	return inUseVNIDs.Union(policyVNIDs)
}

// FindUnusedVNIDs returns a list of VNIDs for which there are table 80 "policy" rules,
// but no table 70 "load" rules (meaning that there are no longer any pods or services
// on this node with that VNID). There is no locking with respect to other ovsController
// actions, but as long the "add a pod" and "add a service" codepaths add the
// pod/service-specific rules before they call policy.EnsureVNIDRules(), then there is no
// race condition.
func (oc *ovsController) FindUnusedVNIDs() []int {
	inUseVNIDs, policyVNIDs := oc.findInUseAndPolicyVNIDs()
	// VNID 0 is always in use, even if there aren't any flows for it in table 70
	inUseVNIDs.Insert(0)
	return policyVNIDs.Difference(inUseVNIDs).UnsortedList()
}

// findInUseAndPolicyVNIDs returns two sets: the VNIDs that are currently in use by pods
// or services on this node, and the VNIDs that are currently in use by NetworkPolicies
// on this node.
func (oc *ovsController) findInUseAndPolicyVNIDs() (sets.Int, sets.Int) {
	inUseVNIDs := sets.NewInt()
	policyVNIDs := sets.NewInt()

	flows, err := oc.ovs.DumpFlows("")
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("findInUseAndPolicyVNIDs: could not DumpFlows: %v", err))
		return inUseVNIDs, policyVNIDs
	}

	for _, flow := range flows {
		parsed, err := ovs.ParseFlow(ovs.ParseForDump, flow)
		if err != nil {
			klog.Warningf("findInUseAndPolicyVNIDs: could not parse flow %q: %v", flow, err)
			continue
		}

		// A VNID is in use if there is a table 70 (pod) flow that loads that VNID
		// into reg1 for later comparison.
		if parsed.Table == 70 {
			// Can't use FindAction here since there may be multiple "load"s
			for _, action := range parsed.Actions {
				if action.Name != "load" || strings.Index(action.Value, "REG1") == -1 {
					continue
				}
				vnidEnd := strings.Index(action.Value, "->")
				if vnidEnd == -1 {
					continue
				}
				vnid, err := strconv.ParseInt(action.Value[:vnidEnd], 0, 32)
				if err != nil {
					klog.Warningf("findInUseAndPolicyVNIDs: could not parse VNID in 'load:%s': %v", action.Value, err)
					continue
				}
				inUseVNIDs.Insert(int(vnid))
				break
			}
		}

		// A VNID is checked by policy if there is a table 80 rule comparing reg1 to it.
		if parsed.Table == 80 {
			if field, exists := parsed.FindField("reg1"); exists {
				vnid, err := strconv.ParseInt(field.Value, 0, 32)
				if err != nil {
					klog.Warningf("findInUseAndPolicyVNIDs: could not parse VNID in 'reg1=%s': %v", field.Value, err)
					continue
				}
				policyVNIDs.Insert(int(vnid))
			}
		}
	}

	return inUseVNIDs, policyVNIDs
}

func (oc *ovsController) ensureTunMAC() error {
	if oc.tunMAC != "" {
		return nil
	}

	val, err := oc.ovs.Get("Interface", Tun0, "mac_in_use")
	if err != nil {
		return fmt.Errorf("could not get %s MAC address: %v", Tun0, err)
	} else if len(val) != 19 || val[0] != '"' || val[18] != '"' {
		return fmt.Errorf("bad MAC address for %s: %q", Tun0, val)
	}
	oc.tunMAC = val[1:18]
	return nil
}

func (oc *ovsController) SetNamespaceEgressNormal(vnid uint32) error {
	otx := oc.ovs.NewTransaction()
	otx.DeleteFlows("table=100, reg0=%d", vnid)
	otx.DeleteGroup(vnid)
	return otx.Commit()
}

func (oc *ovsController) SetNamespaceEgressDropped(vnid uint32) error {
	otx := oc.ovs.NewTransaction()
	otx.DeleteGroup(vnid)
	otx.DeleteFlows("table=100, reg0=%d", vnid)
	otx.AddFlow("table=100, priority=100, reg0=%d, actions=drop", vnid)
	return otx.Commit()
}

func (oc *ovsController) isLocalNodeIP(ip string) bool {
	for _, localIP := range oc.localIPs {
		if ip == localIP {
			return true
		}
	}
	return false
}

func (oc *ovsController) SetNamespaceEgressViaEgressIPs(vnid uint32, egressIPsMetaData []egressIPMetaData) error {
	otx := oc.ovs.NewTransaction()
	otx.DeleteFlows("table=100, reg0=%d", vnid)
	otx.DeleteGroup(vnid)

	var buildBuckets []string
	for _, egressIPMetaData := range egressIPsMetaData {
		if oc.isLocalNodeIP(egressIPMetaData.nodeIP) {
			if err := oc.ensureTunMAC(); err != nil {
				return err
			}
			buildBuckets = []string{fmt.Sprintf("actions=set_field:%s->eth_dst,set_field:%s->pkt_mark,output:tun0", oc.tunMAC, egressIPMetaData.packetMark)}
			// if one of the egressIPs is the IP of the node always use that egress otherwise it might not actually egress and get sent between nodes
			break
		} else {
			buildBuckets = append(buildBuckets, fmt.Sprintf("actions=ct(commit),move:NXM_NX_REG0[]->NXM_NX_TUN_ID[0..31],set_field:%s->tun_dst,output:vxlan0", egressIPMetaData.nodeIP))
		}

	}

	if len(egressIPsMetaData) == 0 {
		// Namespace wants egressIP, but no node hosts it, so drop
		otx.AddFlow("table=100, priority=100, reg0=%d, actions=drop", vnid)
	} else {
		// there is at least one egressIP hosted by one other node. Use a group
		// to load balance between the egressIPs
		otx.AddGroup(vnid, "select", buildBuckets)
		otx.AddFlow("table=100, priority=100, ip, reg0=%d, actions=group:%d", vnid, vnid)
	}
	return otx.Commit()
}
