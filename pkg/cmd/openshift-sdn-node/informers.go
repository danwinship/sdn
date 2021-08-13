package openshift_sdn_node

import (
	"net"
	"net/http"
	"time"

	kinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformers "github.com/openshift/client-go/network/informers/externalversions"
	sdncommon "github.com/openshift/sdn/pkg/network/common"
)

var defaultInformerResyncPeriod = 30 * time.Minute

// buildInformers creates all the informer factories.
func (sdn *openShiftSDN) buildInformers() error {
	kubeConfig, err := getInClusterConfig()
	if err != nil {
		return err
	}

	protoKubeConfig := rest.CopyConfig(kubeConfig)
	protoKubeConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	protoKubeConfig.ContentType = "application/vnd.kubernetes.protobuf"

	kubeClient, err := kubernetes.NewForConfig(protoKubeConfig)
	if err != nil {
		return err
	}
	osdnClient, err := osdnclient.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	kubeInformers := kinformers.NewSharedInformerFactory(kubeClient, defaultInformerResyncPeriod)
	osdnInformers := osdninformers.NewSharedInformerFactory(osdnClient, defaultInformerResyncPeriod)

	sdn.clients = &sdncommon.SDNClients{
		KubeClient: kubeClient,
		OSDNClient: osdnClient,

		KubeInformers: kubeInformers,
		OSDNInformers: osdnInformers,
	}
	return nil
}

// getInClusterConfig loads in-cluster config, then applies default overrides.
func getInClusterConfig() (*rest.Config, error) {
	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	applyClientConnectionOverrides(clientConfig)
	clientConfig.WrapTransport = defaultClientTransport

	return clientConfig, nil
}

// defaultClientTransport sets defaults for a client Transport that are suitable
// for use by infrastructure components.
func defaultClientTransport(rt http.RoundTripper) http.RoundTripper {
	transport, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}

	// TODO: this should be configured by the caller, not in this method.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.Dial = dialer.Dial
	// Hold open more internal idle connections
	// TODO: this should be configured by the caller, not in this method.
	transport.MaxIdleConnsPerHost = 100
	return transport
}

// applyClientConnectionOverrides updates a kubeConfig with default overrides
func applyClientConnectionOverrides(kubeConfig *rest.Config) {
	kubeConfig.QPS = 10.0
	kubeConfig.Burst = 20
}
