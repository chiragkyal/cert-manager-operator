package operator

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"

	ctrl "sigs.k8s.io/controller-runtime"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/istiocsr"
	"github.com/openshift/cert-manager-operator/pkg/controller/trustmanager"
	"github.com/openshift/cert-manager-operator/pkg/features"
	"github.com/openshift/cert-manager-operator/pkg/version"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup-manager")
)

func init() {
	ctrllog.SetLogger(klog.NewKlogr())

	utilruntime.Must(clientscheme.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(networkingv1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// Manager holds the manager resource for operand controllers (IstioCSR, TrustManager).
type Manager struct {
	manager manager.Manager
}

// NewControllerManager creates a new manager and registers enabled controllers.
//
// Controllers are registered based on feature gates:
// - IstioCSR: Enabled by FeatureIstioCSR (default: true)
// - TrustManager: Enabled by FeatureTrustManager (default: true)
//
// The manager uses a shared cache that is configured with label selectors
// to efficiently watch only resources managed by our controllers.
func NewControllerManager() (*Manager, error) {
	setupLog.Info("setting up operator manager", "version", version.Get())

	// Determine which controllers are enabled
	istioCSREnabled := features.DefaultFeatureGate.Enabled(v1alpha1.FeatureIstioCSR)
	trustManagerEnabled := features.DefaultFeatureGate.Enabled(v1alpha1.FeatureTrustManager)

	setupLog.Info("feature gates",
		"IstioCSR", istioCSREnabled,
		"TrustManager", trustManagerEnabled)

	// If no controllers enabled, return early
	if !istioCSREnabled && !trustManagerEnabled {
		setupLog.Info("no operand controllers enabled, skipping manager setup")
		return nil, fmt.Errorf("no operand controllers enabled")
	}

	// Build manager options
	// Note: We need to select the appropriate cache builder based on which
	// controllers are enabled. For now, we use IstioCSR's cache builder
	// when it's enabled, as it's more mature. In the future, we should
	// merge both cache configurations.
	mgrOpts := ctrl.Options{
		Scheme: scheme,
		Logger: ctrl.Log.WithName("operator-manager"),
	}

	// Configure cache builder based on enabled controllers
	// TODO: When both are enabled, merge cache configurations
	if istioCSREnabled {
		mgrOpts.NewCache = istiocsr.NewCacheBuilder
	} else if trustManagerEnabled {
		mgrOpts.NewCache = trustmanager.NewCacheBuilder
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// ==========================================================================
	// Register IstioCSR controller
	// ==========================================================================
	if istioCSREnabled {
		setupLog.Info("registering controller", "name", istiocsr.ControllerName)

		istioCSRReconciler, err := istiocsr.New(mgr)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s reconciler: %w", istiocsr.ControllerName, err)
		}
		if err := istioCSRReconciler.SetupWithManager(mgr); err != nil {
			return nil, fmt.Errorf("failed to setup %s controller: %w", istiocsr.ControllerName, err)
		}
	}

	// ==========================================================================
	// Register TrustManager controller
	// ==========================================================================
	if trustManagerEnabled {
		setupLog.Info("registering controller", "name", trustmanager.ControllerName)

		trustManagerReconciler, err := trustmanager.New(mgr)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s reconciler: %w", trustmanager.ControllerName, err)
		}
		if err := trustManagerReconciler.SetupWithManager(mgr); err != nil {
			return nil, fmt.Errorf("failed to setup %s controller: %w", trustmanager.ControllerName, err)
		}
	}

	// +kubebuilder:scaffold:builder

	return &Manager{
		manager: mgr,
	}, nil
}

// Start starts the operator synchronously until a message is received from ctx.
func (mgr *Manager) Start(ctx context.Context) error {
	mgr.manager.GetEventRecorderFor("cert-manager-istio-csr-controller").Event(&v1alpha1.IstioCSR{}, corev1.EventTypeNormal, "ControllerStarted", "controller is starting")
	return mgr.manager.Start(ctx)
}
