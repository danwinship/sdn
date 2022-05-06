package common

import (
	"time"

	kinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	kfake "k8s.io/client-go/kubernetes/fake"

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
}

// Start starts the client's informers
func (clients *SDNClients) Start(stopCh <-chan struct{}) {
	clients.KubeInformers.Start(stopCh)
	clients.OSDNInformers.Start(stopCh)
	if clients.CloudNetworkInformers != nil {
		clients.CloudNetworkInformers.Start(stopCh)
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
