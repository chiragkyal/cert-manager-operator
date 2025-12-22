package operator

import (
	"context"
	"fmt"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"

	ctrl "sigs.k8s.io/controller-runtime"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/deployment"
	"github.com/openshift/cert-manager-operator/pkg/features"
	certmanoperatorclient "github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned"
	certmanoperatorinformers "github.com/openshift/cert-manager-operator/pkg/operator/informers/externalversions"
	"github.com/openshift/cert-manager-operator/pkg/operator/operatorclient"
	"github.com/openshift/cert-manager-operator/pkg/operator/optionalinformer"
)

const (
	resyncInterval = 10 * time.Minute
)

var (
	// scheme for controller-runtime manager
	scheme = runtime.NewScheme()
)

func init() {
	// Set controller-runtime logger to use klog (same as the rest of the operator)
	// This must be called before any controller-runtime code uses ctrl.Log
	ctrllog.SetLogger(klog.NewKlogr())

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(admissionregistrationv1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

// TrustedCAConfigMapName is the trusted ca configmap name
// provided as a runtime arg.
var TrustedCAConfigMapName string

// CloudSecretName is the name of the cloud secret to be
// used in ambient credentials mode, and is provided as a runtime arg.
var CloudCredentialSecret string

// UnsupportedAddonFeatures is the user-specific list of unsupported addon features
// that the operator optionally enables, and is provided as a runtime arg.
var UnsupportedAddonFeatures string

func RunOperator(ctx context.Context, cc *controllercmd.ControllerContext) error {
	kubeClient, err := kubernetes.NewForConfig(cc.ProtoKubeConfig)
	if err != nil {
		return err
	}

	certManagerOperatorClient, err := certmanoperatorclient.NewForConfig(cc.KubeConfig)
	if err != nil {
		return err
	}

	apiExtensionsClient, err := apiextensionsclient.NewForConfig(cc.KubeConfig)
	if err != nil {
		return err
	}

	certManagerInformers := certmanoperatorinformers.NewSharedInformerFactory(certManagerOperatorClient, resyncInterval)

	operatorClient := &operatorclient.OperatorClient{
		Informers: certManagerInformers,
		Client:    certManagerOperatorClient.OperatorV1alpha1(),
		Clock:     cc.Clock,
	}

	// perform version changes to the version getter prior to tying it up in the status controller
	// via change-notification channel so that it only updates operator version in status once
	// either of the workloads synces
	versionRecorder := status.NewVersionGetter()
	versionRecorder.SetVersion("operator", status.VersionForOperatorFromEnv())

	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(kubeClient,
		"",
		"kube-system",
		operatorclient.TargetNamespace,
	)

	configClient, err := configv1client.NewForConfig(cc.KubeConfig)
	if err != nil {
		return err
	}

	infraGVR := configv1.GroupVersion.WithResource("infrastructures")
	optInfraInformer, err := optionalinformer.NewOptionalInformer(
		ctx, infraGVR, configClient.Discovery(),
		func() configinformers.SharedInformerFactory {
			return configinformers.NewSharedInformerFactory(configClient, resyncInterval)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to discover Infrastructure presence: %w", err)
	}

	certManagerControllerSet := deployment.NewCertManagerControllerSet(
		kubeClient,
		kubeInformersForNamespaces,
		kubeInformersForNamespaces.InformersFor(operatorclient.TargetNamespace),
		*optInfraInformer,
		operatorClient,
		certManagerInformers,
		resourceapply.NewKubeClientHolder(kubeClient).WithAPIExtensionsClient(apiExtensionsClient),
		cc.EventRecorder,
		status.VersionForOperandFromEnv(),
		versionRecorder,
		TrustedCAConfigMapName,
		CloudCredentialSecret,
	)
	controllersToStart := certManagerControllerSet.ToArray()

	defaultCertManagerController := deployment.NewDefaultCertManagerController(
		operatorClient,
		certManagerOperatorClient.OperatorV1alpha1(),
		cc.EventRecorder,
	)

	controllersToStart = append(controllersToStart, defaultCertManagerController)

	for _, informer := range []interface{ Start(<-chan struct{}) }{
		certManagerInformers,
		kubeInformersForNamespaces,
	} {
		informer.Start(ctx.Done())
	}

	// only start the informer if Infrastructure is found applicable
	if optInfraInformer.Applicable() {
		(*optInfraInformer.InformerFactory).Start(ctx.Done())
	}

	for _, controller := range controllersToStart {
		go controller.Run(ctx, 1)
	}

	err = features.SetupWithFlagValue(UnsupportedAddonFeatures)
	if err != nil {
		return fmt.Errorf("failed to parse addon features: %w", err)
	}

	// Enable controller-runtime based operand controllers when their feature gates are on.
	// The controller manager handles both IstioCSR and TrustManager controllers.
	// - IstioCSR: Manages istio-csr deployment for Istio mTLS certificate issuance
	// - TrustManager: Manages trust-manager deployment for CA bundle distribution
	istioCSREnabled := features.DefaultFeatureGate.Enabled(v1alpha1.FeatureIstioCSR)
	trustManagerEnabled := features.DefaultFeatureGate.Enabled(v1alpha1.FeatureTrustManager)

	if istioCSREnabled || trustManagerEnabled {
		// Create the cache builder (following ESO pattern)
		cacheBuilder := NewCacheBuilder(cc.KubeConfig)

		// Create the manager with the cache builder
		mgr, err := ctrl.NewManager(cc.KubeConfig, ctrl.Options{
			Scheme: scheme,
			Logger: ctrl.Log.WithName("operand-manager"),
			// Use dedicated ports that don't conflict with the main operator
			Metrics:                metricsserver.Options{BindAddress: ":8081"},
			HealthProbeBindAddress: ":9081",
			// Don't use leader election - the main operator handles that
			LeaderElection: false,
			// Configure manager's cache with the cache builder
			NewCache: cacheBuilder,
		})
		if err != nil {
			return fmt.Errorf("failed to create operand controller manager: %w", err)
		}

		// Setup controllers with the manager
		if err := StartControllers(ctx, mgr); err != nil {
			return fmt.Errorf("failed to setup operand controllers: %w", err)
		}

		// Start the manager in a goroutine (non-blocking)
		go func() {
			ctrl.Log.WithName("operand-manager").Info("starting operand controller manager")
			if err := mgr.Start(ctx); err != nil {
				ctrl.Log.WithName("operand-manager").Error(err, "operand controller manager failed")
			}
		}()
	}

	<-ctx.Done()
	return nil
}
