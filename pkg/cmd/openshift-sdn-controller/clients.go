package openshift_sdn_controller

import (
	"time"

	cloudnetworkclient "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformer "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformer "github.com/openshift/client-go/network/informers/externalversions"
	"github.com/openshift/sdn/pkg/network/common"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const defaultInformerResyncPeriod = 10 * time.Minute

func newSDNClients(platformType string, clientConfig *rest.Config) (*common.SDNClients, error) {
	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	osdnClient, err := osdnclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	sdnClients := &common.SDNClients{
		KubeClient:    kubeClient,
		KubeInformers: informers.NewSharedInformerFactory(kubeClient, defaultInformerResyncPeriod),
		OSDNClient:    osdnClient,
		OSDNInformers: osdninformer.NewSharedInformerFactory(osdnClient, defaultInformerResyncPeriod),
	}

	if common.PlatformUsesCloudEgressIP(platformType) {
		cloudNetworkClient, err := cloudnetworkclient.NewForConfig(clientConfig)
		if err != nil {
			return nil, err
		}
		sdnClients.CloudNetworkClient = cloudNetworkClient
		sdnClients.CloudNetworkInformers = cloudnetworkinformer.NewSharedInformerFactory(cloudNetworkClient, defaultInformerResyncPeriod)
	}

	return sdnClients, nil
}
