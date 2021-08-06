package openshift_sdn_controller

import (
	"context"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	configv1 "github.com/openshift/api/config/v1"
	osdnclient "github.com/openshift/client-go/network/clientset/versioned"
	osdninformer "github.com/openshift/client-go/network/informers/externalversions"
	operclient "github.com/openshift/client-go/operator/clientset/versioned"
	leaderelectionconverter "github.com/openshift/library-go/pkg/config/leaderelection"
	"github.com/openshift/library-go/pkg/serviceability"
	sdncommon "github.com/openshift/sdn/pkg/network/common"
	sdnmaster "github.com/openshift/sdn/pkg/network/master"

	// for metrics
	_ "k8s.io/component-base/metrics/prometheus/restclient"
	_ "k8s.io/component-base/metrics/prometheus/version"
)

func RunOpenShiftNetworkController() error {
	serviceability.InitLogrusFromKlog()

	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return err
	}

	originControllerManager := func(ctx context.Context) {
		sdnClients, err := newSDNClients(clientConfig)
		if err != nil {
			klog.Fatal(err)
		}

		sdnConfig, err := sdncommon.GetSDNConfig(sdnClients)
		if err != nil {
			klog.Fatalf("failed to get SDN config: %v", err)
		}

		if err := sdnmaster.Start(sdnClients, sdnConfig); err != nil {
			klog.Fatalf("Error starting OpenShift Network Controller: %v", err)
		}
		klog.Infof("Started OpenShift Network Controller")
		sdnClients.Start(nil)
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	eventRecorder := eventBroadcaster.NewRecorder(legacyscheme.Scheme, corev1.EventSource{Component: "openshift-network-controller"})
	id, err := os.Hostname()
	if err != nil {
		return err
	}

	leaderConfig := leaderelectionconverter.LeaderElectionDefaulting(configv1.LeaderElection{}, "openshift-sdn", "openshift-network-controller")
	rl, err := resourcelock.New(
		"configmaps",
		leaderConfig.Namespace,
		leaderConfig.Name,
		kubeClient.CoreV1(),
		kubeClient.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity:      id,
			EventRecorder: eventRecorder,
		})
	if err != nil {
		return err
	}
	go leaderelection.RunOrDie(context.Background(),
		leaderelection.LeaderElectionConfig{
			Lock:          rl,
			LeaseDuration: leaderConfig.LeaseDuration.Duration,
			RenewDeadline: leaderConfig.RenewDeadline.Duration,
			RetryPeriod:   leaderConfig.RetryPeriod.Duration,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: originControllerManager,
				OnStoppedLeading: func() {
					klog.Fatalf("leaderelection lost")
				},
			},
		})

	return nil
}

const defaultInformerResyncPeriod = 10 * time.Minute

func newSDNClients(clientConfig *rest.Config) (*sdncommon.SDNClients, error) {
	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	osdnClient, err := osdnclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	operClient, err := operclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	sdnClients := &sdncommon.SDNClients{
		KubeClient:    kubeClient,
		KubeInformers: informers.NewSharedInformerFactory(kubeClient, defaultInformerResyncPeriod),
		OSDNClient:    osdnClient,
		OSDNInformers: osdninformer.NewSharedInformerFactory(osdnClient, defaultInformerResyncPeriod),
		OperClient:    operClient,
	}

	return sdnClients, nil
}
