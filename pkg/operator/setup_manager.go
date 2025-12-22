package operator

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/rest"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/istiocsr"
	"github.com/openshift/cert-manager-operator/pkg/controller/trustmanager"
)

var setupLog = ctrl.Log.WithName("setup")

// NewCacheBuilder returns a cache builder function that configures the manager's cache.
// This follows the same pattern as external-secrets-operator.
//
// Note: We don't use label selectors at cache level because:
// - IstioCSR and TrustManager use different label keys
// - K8s label selectors don't support OR logic
// - Predicates in each controller handle the filtering instead
func NewCacheBuilder(config *rest.Config) cache.NewCacheFunc {
	return func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
		// Configure which objects the cache should watch
		opts.ByObject = buildCacheObjectList()
		return cache.New(config, opts)
	}
}

// buildCacheObjectList creates the cache configuration.
// We register all resource types that controllers need to watch.
// Filtering is done via predicates in SetupWithManager, not at cache level.
func buildCacheObjectList() map[client.Object]cache.ByObject {
	objectList := make(map[client.Object]cache.ByObject)

	// CR types - no label filter (controllers always need to read these)
	objectList[&v1alpha1.IstioCSR{}] = cache.ByObject{}
	objectList[&v1alpha1.TrustManager{}] = cache.ByObject{}

	// Resources managed by controllers - no cache-level filtering
	// Predicates in SetupWithManager handle event filtering
	objectList[&appsv1.Deployment{}] = cache.ByObject{}
	objectList[&corev1.ServiceAccount{}] = cache.ByObject{}
	objectList[&corev1.Service{}] = cache.ByObject{}
	objectList[&corev1.ConfigMap{}] = cache.ByObject{}
	objectList[&corev1.Secret{}] = cache.ByObject{}
	objectList[&rbacv1.ClusterRole{}] = cache.ByObject{}
	objectList[&rbacv1.ClusterRoleBinding{}] = cache.ByObject{}
	objectList[&rbacv1.Role{}] = cache.ByObject{}
	objectList[&rbacv1.RoleBinding{}] = cache.ByObject{}
	objectList[&certmanagerv1.Certificate{}] = cache.ByObject{}
	objectList[&certmanagerv1.Issuer{}] = cache.ByObject{}
	objectList[&admissionregistrationv1.ValidatingWebhookConfiguration{}] = cache.ByObject{}

	return objectList
}

// StartControllers sets up and registers all operand controllers with the manager.
// The manager should already be configured with the cache from NewCacheBuilder.
func StartControllers(ctx context.Context, mgr ctrl.Manager) error {
	// ==========================================================================
	// Setup IstioCSR Controller
	// ==========================================================================
	setupLog.Info("setting up controller", "name", istiocsr.ControllerName)

	istioCSRReconciler, err := istiocsr.New(mgr)
	if err != nil {
		return fmt.Errorf("failed to create %s reconciler: %w", istiocsr.ControllerName, err)
	}
	if err := istioCSRReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup %s controller: %w", istiocsr.ControllerName, err)
	}

	// ==========================================================================
	// Setup TrustManager Controller
	// ==========================================================================
	setupLog.Info("setting up controller", "name", trustmanager.ControllerName)

	trustManagerReconciler, err := trustmanager.New(mgr)
	if err != nil {
		return fmt.Errorf("failed to create %s reconciler: %w", trustmanager.ControllerName, err)
	}
	if err := trustManagerReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup %s controller: %w", trustmanager.ControllerName, err)
	}

	return nil
}
