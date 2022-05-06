package common

import (
	kinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	cloudnetworkclient "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
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
