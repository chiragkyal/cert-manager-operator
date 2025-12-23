package trustmanager

import (
	"context"
	"fmt"
	"reflect"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

// =============================================================================
// RECONCILER STRUCTURE
// =============================================================================
// Reconciler is the main controller struct. It holds all dependencies needed
// to perform reconciliation.
//
// Why these fields?
// - ctrlClient: For Kubernetes API operations (embedded for convenience)
// - ctx: Background context for operations
// - eventRecorder: To emit events visible via `kubectl describe`
// - log: Structured logging with controller name
// - scheme: For setting owner references and type conversions
type Reconciler struct {
	ctrlClient // Embedded client interface

	ctx           context.Context
	eventRecorder record.EventRecorder
	log           logr.Logger
	scheme        *runtime.Scheme
}

// =============================================================================
// RBAC MARKERS
// =============================================================================
// These markers generate ClusterRole rules in config/rbac/role.yaml
// They define what permissions the operator needs to manage trust-manager.
//
// Format: +kubebuilder:rbac:groups=<group>,resources=<resources>,verbs=<verbs>

// TrustManager CR permissions
// +kubebuilder:rbac:groups=operator.openshift.io,resources=trustmanagers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=trustmanagers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=trustmanagers/finalizers,verbs=update

// Deployment management
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete

// RBAC management (for trust-manager's permissions)
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete

// ServiceAccount, Service, and ConfigMap management
// +kubebuilder:rbac:groups="",resources=serviceaccounts;services;configmaps,verbs=get;list;watch;create;update;patch;delete

// Namespace management (for creating trust namespace if different from operand namespace)
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create

// Certificate management (for webhook TLS)
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates;issuers,verbs=get;list;watch;create;update;patch;delete

// Webhook configuration
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;create;update;patch;delete

// =============================================================================
// CACHE BUILDER
// =============================================================================
// NewCacheBuilder returns a function that builds a cache with label selectors.
//
// Why use a custom cache?
// - By default, the cache watches ALL resources of each type
// - This can be expensive in large clusters
// - We only care about resources WE create (with our labels)
// - Label selectors reduce memory usage and API load
//
// This function is passed to the manager via cache.Options.NewCache
func NewCacheBuilder(config *rest.Config, opts cache.Options) (cache.Cache, error) {
	// Create a label requirement: requestEnqueueLabelKey == requestEnqueueLabelValue
	// This matches only resources created by this controller
	managedResourceLabelReq, err := labels.NewRequirement(
		requestEnqueueLabelKey,
		selection.Equals,
		[]string{requestEnqueueLabelValue},
	)
	if err != nil {
		return nil, fmt.Errorf("invalid cache label requirement for %q: %w", requestEnqueueLabelKey, err)
	}
	selector := labels.NewSelector().Add(*managedResourceLabelReq)

	// Configure per-type cache settings
	// Types without Label selector will cache ALL instances
	// Types with Label selector will only cache matching instances
	opts.ByObject = map[client.Object]cache.ByObject{
		// TrustManager CR: Cache all (no selector) - it's cluster-scoped singleton
		&v1alpha1.TrustManager{}: {},

		// Managed resources: Only cache those with our label
		&appsv1.Deployment{}:         {Label: selector},
		&corev1.ServiceAccount{}:     {Label: selector},
		&corev1.Service{}:            {Label: selector},
		&corev1.ConfigMap{}:          {Label: selector}, // For DefaultCAPackage ConfigMaps
		&rbacv1.ClusterRole{}:        {Label: selector},
		&rbacv1.ClusterRoleBinding{}: {Label: selector},
		&rbacv1.Role{}:               {Label: selector},
		&rbacv1.RoleBinding{}:        {Label: selector},
		&certmanagerv1.Certificate{}: {Label: selector},
		&certmanagerv1.Issuer{}:      {Label: selector},
		&admissionregistrationv1.ValidatingWebhookConfiguration{}: {Label: selector},
	}

	return cache.New(config, opts)
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================
// New creates a new Reconciler with all its dependencies.
func New(mgr ctrl.Manager) (*Reconciler, error) {
	c, err := NewClient(mgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &Reconciler{
		ctrlClient:    c,
		ctx:           context.Background(),
		eventRecorder: mgr.GetEventRecorderFor(ControllerName),
		log:           ctrl.Log.WithName(ControllerName),
		scheme:        mgr.GetScheme(),
	}, nil
}

// =============================================================================
// CONTROLLER SETUP
// =============================================================================
// SetupWithManager registers the controller with the manager.
//
// This is where we define:
// 1. What resource triggers reconciliation (For)
// 2. What other resources to watch (Watches)
// 3. How to map watched resources back to our CR (handler.EnqueueRequestsFromMapFunc)
// 4. What changes to ignore (predicates)
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	// mapFunc converts events from watched resources into reconcile requests.
	// When a Deployment/Service/etc changes, we need to figure out which
	// TrustManager CR should be reconciled.
	//
	// For trust-manager, this is simple: we only have one singleton named "cluster"
	mapFunc := func(ctx context.Context, obj client.Object) []reconcile.Request {
		r.log.Info("received event for managed resource",
			"type", fmt.Sprintf("%T", obj),
			"name", obj.GetName(),
			"namespace", obj.GetNamespace())

		// Check if this resource was created by us (has our label)
		if obj.GetLabels() != nil && obj.GetLabels()[requestEnqueueLabelKey] == requestEnqueueLabelValue {
			// Always reconcile the singleton "cluster" TrustManager
			// Note: No namespace because TrustManager is cluster-scoped
			return []reconcile.Request{{
				NamespacedName: types.NamespacedName{
					Name: trustManagerObjectName, // "cluster"
				},
			}}
		}

		r.log.V(4).Info("ignoring event - resource not managed by this controller",
			"type", fmt.Sprintf("%T", obj),
			"name", obj.GetName())
		return []reconcile.Request{}
	}

	// Predicates filter which events trigger reconciliation
	//
	// GenerationChangedPredicate: Only trigger on spec changes, not status updates
	// This prevents infinite loops where:
	// 1. Controller updates status
	// 2. Status update triggers reconciliation
	// 3. Controller updates status again
	// 4. ...
	//
	// controllerManagedResources: Only watch resources with our label
	controllerManagedResources := predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetLabels() != nil &&
			object.GetLabels()[requestEnqueueLabelKey] == requestEnqueueLabelValue
	})

	// Different predicate combinations for different resource types
	withIgnoreStatusUpdate := builder.WithPredicates(
		predicate.GenerationChangedPredicate{},
		controllerManagedResources,
	)
	withManagedResourcesOnly := builder.WithPredicates(controllerManagedResources)

	// Build the controller
	return ctrl.NewControllerManagedBy(mgr).
		// Primary resource - changes here always trigger reconciliation
		// GenerationChangedPredicate ignores status-only updates
		For(&v1alpha1.TrustManager{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named(ControllerName).

		// Secondary resources - we create these, so watch for drift
		// If someone modifies our Deployment, we want to fix it
		Watches(&appsv1.Deployment{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withIgnoreStatusUpdate).
		Watches(&corev1.ServiceAccount{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		// ConfigMaps are watched for DefaultCAPackage feature
		// CNO updates the injection ConfigMap, which should trigger reconciliation
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&rbacv1.ClusterRole{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&rbacv1.ClusterRoleBinding{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&rbacv1.Role{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&rbacv1.RoleBinding{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&certmanagerv1.Certificate{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withIgnoreStatusUpdate).
		Watches(&certmanagerv1.Issuer{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Watches(&admissionregistrationv1.ValidatingWebhookConfiguration{},
			handler.EnqueueRequestsFromMapFunc(mapFunc),
			withManagedResourcesOnly).
		Complete(r)
}

// =============================================================================
// MAIN RECONCILIATION LOOP
// =============================================================================
// Reconcile is called whenever:
// 1. A TrustManager CR is created/updated/deleted
// 2. A watched resource (Deployment, etc.) changes
// 3. A requeue timer fires
//
// The reconciler's job is to make the cluster state match the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.log.V(1).Info("reconciling", "request", req)

	// ==========================================================================
	// STEP 1: Singleton validation
	// ==========================================================================
	// TrustManager is a singleton - only "cluster" is valid
	// This is enforced by CRD validation, but we double-check here
	if req.Name != trustManagerObjectName {
		r.log.Info("ignoring TrustManager with invalid name, only 'cluster' is supported",
			"name", req.Name,
			"expected", trustManagerObjectName)
		return ctrl.Result{}, nil
	}

	// ==========================================================================
	// STEP 2: Fetch the TrustManager CR
	// ==========================================================================
	trustManager := &v1alpha1.TrustManager{}
	// Note: No namespace because TrustManager is cluster-scoped
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, trustManager); err != nil {
		if errors.IsNotFound(err) {
			// CR was deleted - nothing to do
			// Cleanup is handled by finalizers before deletion completes
			r.log.V(1).Info("TrustManager not found, skipping reconciliation", "name", req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to fetch TrustManager %q: %w", req.Name, err)
	}

	// ==========================================================================
	// STEP 3: Handle deletion
	// ==========================================================================
	// If DeletionTimestamp is set, the resource is being deleted
	// We need to clean up before removing the finalizer
	if !trustManager.DeletionTimestamp.IsZero() {
		r.log.V(1).Info("TrustManager is marked for deletion", "name", req.Name)

		// Clean up all resources we created
		requeue, err := r.cleanUp(trustManager)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cleanup failed for TrustManager %q: %w", req.Name, err)
		}
		if requeue {
			// Cleanup not complete, requeue to check again
			return ctrl.Result{RequeueAfter: defaultRequeueTime}, nil
		}

		// Cleanup complete, remove finalizer so deletion can proceed
		if err := r.removeFinalizer(ctx, trustManager); err != nil {
			return ctrl.Result{}, err
		}

		r.log.V(1).Info("finalizer removed, cleanup complete", "name", req.Name)
		return ctrl.Result{}, nil
	}

	// ==========================================================================
	// STEP 4: Add finalizer
	// ==========================================================================
	// Finalizers prevent deletion until we clean up our resources
	if err := r.addFinalizer(ctx, trustManager); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to add finalizer to TrustManager %q: %w", req.Name, err)
	}

	// ==========================================================================
	// STEP 5: Process reconciliation
	// ==========================================================================
	return r.processReconcileRequest(trustManager)
}

// =============================================================================
// PROCESS RECONCILE REQUEST
// =============================================================================
// processReconcileRequest contains the main reconciliation logic.
// It's separated from Reconcile() to make error handling cleaner.
func (r *Reconciler) processReconcileRequest(trustManager *v1alpha1.TrustManager) (ctrl.Result, error) {
	// Detect if this is a newly created CR
	// Used to emit "ResourceAlreadyExists" warnings if resources exist
	isNewReconcile := !containsProcessedAnnotation(trustManager) &&
		reflect.DeepEqual(trustManager.Status, v1alpha1.TrustManagerStatus{})

	if isNewReconcile {
		r.log.V(1).Info("starting reconciliation of newly created TrustManager",
			"name", trustManager.GetName())
	}

	// ==========================================================================
	// Reconcile all trust-manager resources
	// ==========================================================================
	requeue, err := r.reconcileTrustManagerDeployment(trustManager, isNewReconcile)
	if err != nil {
		r.log.Error(err, "failed to reconcile trust-manager deployment")

		if IsIrrecoverableError(err) {
			// Permanent failure - don't retry
			// Set Degraded=True, Ready=False
			degradedChanged := trustManager.Status.SetCondition(
				v1alpha1.Degraded, metav1.ConditionTrue,
				v1alpha1.ReasonFailed,
				fmt.Sprintf("reconciliation failed with irrecoverable error: %v", err))
			readyChanged := trustManager.Status.SetCondition(
				v1alpha1.Ready, metav1.ConditionFalse,
				v1alpha1.ReasonReady, "")

			if degradedChanged || readyChanged {
				if updateErr := r.updateCondition(trustManager); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
			}
			return ctrl.Result{}, nil // Don't requeue irrecoverable errors
		}

		// Temporary failure - retry after delay
		// Set Degraded=False, Ready=False with "in progress" message
		degradedChanged := trustManager.Status.SetCondition(
			v1alpha1.Degraded, metav1.ConditionFalse,
			v1alpha1.ReasonReady, "")
		readyChanged := trustManager.Status.SetCondition(
			v1alpha1.Ready, metav1.ConditionFalse,
			v1alpha1.ReasonInProgress,
			fmt.Sprintf("reconciliation in progress, will retry: %v", err))

		if degradedChanged || readyChanged {
			if updateErr := r.updateCondition(trustManager); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
		}
		return ctrl.Result{RequeueAfter: defaultRequeueTime}, nil
	}

	// If requeue is requested (e.g., waiting for CNO to inject CA bundle)
	if requeue {
		r.log.V(1).Info("reconciliation requires requeue")

		// Set status to indicate we're waiting
		degradedChanged := trustManager.Status.SetCondition(
			v1alpha1.Degraded, metav1.ConditionFalse,
			v1alpha1.ReasonReady, "")
		readyChanged := trustManager.Status.SetCondition(
			v1alpha1.Ready, metav1.ConditionFalse,
			v1alpha1.ReasonInProgress,
			"waiting for OpenShift CNO to inject trusted CA bundle")

		if degradedChanged || readyChanged {
			if updateErr := r.updateCondition(trustManager); updateErr != nil {
				return ctrl.Result{}, updateErr
			}
		}
		return ctrl.Result{RequeueAfter: defaultRequeueTime}, nil
	}

	// ==========================================================================
	// Success - update status
	// ==========================================================================
	// Update status fields to reflect actual configuration
	trustManager.Status.TrustNamespace = getTrustNamespace(trustManager.Spec.TrustManagerConfig.TrustNamespace)
	trustManager.Status.SecretTargetsEnabled = trustManager.Spec.TrustManagerConfig.SecretTargets != nil &&
		trustManager.Spec.TrustManagerConfig.SecretTargets.Enabled

	degradedChanged := trustManager.Status.SetCondition(
		v1alpha1.Degraded, metav1.ConditionFalse,
		v1alpha1.ReasonReady, "")
	readyChanged := trustManager.Status.SetCondition(
		v1alpha1.Ready, metav1.ConditionTrue,
		v1alpha1.ReasonReady, "trust-manager deployed successfully in cert-manager namespace")

	if degradedChanged || readyChanged {
		if err := r.updateCondition(trustManager); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// =============================================================================
// RECONCILE TRUST-MANAGER DEPLOYMENT
// =============================================================================
// reconcileTrustManagerDeployment creates/updates all resources needed for trust-manager.
// The order matters: some resources depend on others.
//
// Returns:
// - (true, nil) if reconciliation requires requeue (e.g., waiting for CNO to inject CA bundle)
// - (false, nil) if reconciliation was successful
// - (false, error) if there was an error
func (r *Reconciler) reconcileTrustManagerDeployment(trustManager *v1alpha1.TrustManager, isNewReconcile bool) (bool, error) {
	// Get labels to apply to all resources
	resourceLabels := r.getResourceLabels(trustManager)

	// ==========================================================================
	// 1. ServiceAccount - Pod identity
	// ==========================================================================
	// Must exist before Deployment references it
	if err := r.createOrApplyServiceAccount(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// ==========================================================================
	// 2. RBAC - Permissions for trust-manager
	// ==========================================================================
	// ClusterRole/Binding: Cluster-wide permissions
	// Role/Binding: Namespace-scoped permissions (leader election, etc.)
	if err := r.createOrApplyRBACResources(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// ==========================================================================
	// 3. Services - Network endpoints
	// ==========================================================================
	// Webhook service and metrics service
	if err := r.createOrApplyServices(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// ==========================================================================
	// 4. Certificate infrastructure - Webhook TLS
	// ==========================================================================
	// Issuer (self-signed) and Certificate for webhook server
	if err := r.createOrApplyCertificates(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// ==========================================================================
	// 5. Default CA Package (OpenShift-specific)
	// ==========================================================================
	// If enabled, create ConfigMaps for CNO to inject trusted CA bundle.
	// This must be done BEFORE the Deployment so the ConfigMap can be mounted.
	if isDefaultCAPackageEnabled(trustManager) {
		requeue, err := r.createOrApplyDefaultCAPackage(trustManager, resourceLabels, isNewReconcile)
		if err != nil {
			return false, err
		}
		if requeue {
			// CNO hasn't injected the CA bundle yet, requeue to check later
			r.log.V(1).Info("waiting for CNO to inject CA bundle, will requeue")
			return true, nil
		}
	} else {
		// If DefaultCAPackage is disabled, clean up any existing ConfigMaps
		if err := r.deleteDefaultCAPackageConfigMaps(); err != nil {
			r.log.Error(err, "failed to clean up DefaultCAPackage ConfigMaps")
			// Don't fail reconciliation for cleanup errors
		}
		// Clear status if it was previously enabled
		if trustManager.Status.DefaultCAPackage != nil && trustManager.Status.DefaultCAPackage.Enabled {
			if err := r.updateDefaultCAPackageStatus(trustManager, false); err != nil {
				return false, err
			}
		}
	}

	// ==========================================================================
	// 6. Deployment - The trust-manager pod
	// ==========================================================================
	if err := r.createOrApplyDeployment(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// ==========================================================================
	// 7. ValidatingWebhookConfiguration - Bundle validation
	// ==========================================================================
	if err := r.createOrApplyWebhook(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// ==========================================================================
	// 8. Mark as processed
	// ==========================================================================
	return false, r.addProcessedAnnotation(trustManager)
}

// =============================================================================
// CLEANUP
// =============================================================================
// cleanUp removes all resources created for trust-manager.
// Called when TrustManager CR is being deleted.
//
// Returns (true, nil) if cleanup is in progress and we should requeue.
// Returns (false, nil) if cleanup is complete.
// Returns (false, err) if cleanup failed.
func (r *Reconciler) cleanUp(trustManager *v1alpha1.TrustManager) (bool, error) {
	r.log.Info("cleaning up trust-manager resources",
		"name", trustManager.GetName())

	trustNamespace := getTrustNamespace(trustManager.Spec.TrustManagerConfig.TrustNamespace)
	if trustNamespace != operandNamespace {
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "Cleanup",
			"TrustManager marked for deletion, cleaning up resources in %s and %s namespaces",
			operandNamespace, trustNamespace)
	} else {
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "Cleanup",
			"TrustManager marked for deletion, cleaning up resources in %s namespace",
			operandNamespace)
	}

	// Get labels to identify resources we created
	resourceLabels := r.getResourceLabels(trustManager)

	// List of cluster-scoped resources to delete (no owner references)
	// Order matters - delete dependents first
	clusterScopedResources := []client.Object{
		&admissionregistrationv1.ValidatingWebhookConfiguration{},
		&rbacv1.ClusterRoleBinding{},
		&rbacv1.ClusterRole{},
	}

	// Delete cluster-scoped resources by label
	for _, obj := range clusterScopedResources {
		if err := r.deleteByLabel(obj, resourceLabels); err != nil {
			return false, err
		}
	}

	// Namespace-scoped resources will be garbage collected when namespace resources are deleted
	// But we explicitly delete them for faster cleanup
	namespacedResources := []client.Object{
		&appsv1.Deployment{},
		&corev1.Service{},
		&corev1.ConfigMap{}, // DefaultCAPackage ConfigMaps
		&certmanagerv1.Certificate{},
		&certmanagerv1.Issuer{},
		&rbacv1.RoleBinding{},
		&rbacv1.Role{},
		&corev1.ServiceAccount{},
	}

	// Delete resources in the operand namespace (cert-manager)
	for _, obj := range namespacedResources {
		if err := r.deleteByLabelInNamespace(obj, operandNamespace, resourceLabels); err != nil {
			return false, err
		}
	}

	// Also clean up Role and RoleBinding in the trust namespace if different from operand namespace
	if trustNamespace != operandNamespace {
		r.log.V(2).Info("cleaning up RBAC resources in trust namespace", "namespace", trustNamespace)
		rbacResources := []client.Object{
			&rbacv1.RoleBinding{},
			&rbacv1.Role{},
		}
		for _, obj := range rbacResources {
			if err := r.deleteByLabelInNamespace(obj, trustNamespace, resourceLabels); err != nil {
				return false, err
			}
		}
		// Note: We don't delete the trust namespace itself as it may contain user resources
	}

	r.log.Info("cleanup complete", "name", trustManager.GetName())
	return false, nil
}

// deleteByLabel deletes all cluster-scoped resources matching the given labels.
func (r *Reconciler) deleteByLabel(obj client.Object, resourceLabels map[string]string) error {
	listOpts := []client.ListOption{
		client.MatchingLabels{
			requestEnqueueLabelKey: requestEnqueueLabelValue,
		},
	}

	// Get the list type for this object
	list := getListType(obj)
	if list == nil {
		return nil // Skip if we don't have a list type
	}

	if err := r.List(r.ctx, list, listOpts...); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return FromClientError(err, "failed to list %T for cleanup", obj)
	}

	// Delete each item
	items := getItemsFromList(list)
	for _, item := range items {
		r.log.V(2).Info("deleting resource", "type", fmt.Sprintf("%T", item), "name", item.GetName())
		if err := r.Delete(r.ctx, item); err != nil && !errors.IsNotFound(err) {
			return FromClientError(err, "failed to delete %T %s", item, item.GetName())
		}
	}

	return nil
}

// deleteByLabelInNamespace deletes all namespace-scoped resources matching the given labels.
func (r *Reconciler) deleteByLabelInNamespace(obj client.Object, namespace string, resourceLabels map[string]string) error {
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels{
			requestEnqueueLabelKey: requestEnqueueLabelValue,
		},
	}

	list := getListType(obj)
	if list == nil {
		return nil
	}

	if err := r.List(r.ctx, list, listOpts...); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return FromClientError(err, "failed to list %T in namespace %s for cleanup", obj, namespace)
	}

	items := getItemsFromList(list)
	for _, item := range items {
		r.log.V(2).Info("deleting resource", "type", fmt.Sprintf("%T", item),
			"name", item.GetName(), "namespace", item.GetNamespace())
		if err := r.Delete(r.ctx, item); err != nil && !errors.IsNotFound(err) {
			return FromClientError(err, "failed to delete %T %s/%s", item, item.GetNamespace(), item.GetName())
		}
	}

	return nil
}

// getListType returns the appropriate list type for a given object.
func getListType(obj client.Object) client.ObjectList {
	switch obj.(type) {
	case *appsv1.Deployment:
		return &appsv1.DeploymentList{}
	case *corev1.ServiceAccount:
		return &corev1.ServiceAccountList{}
	case *corev1.Service:
		return &corev1.ServiceList{}
	case *corev1.ConfigMap:
		return &corev1.ConfigMapList{}
	case *rbacv1.ClusterRole:
		return &rbacv1.ClusterRoleList{}
	case *rbacv1.ClusterRoleBinding:
		return &rbacv1.ClusterRoleBindingList{}
	case *rbacv1.Role:
		return &rbacv1.RoleList{}
	case *rbacv1.RoleBinding:
		return &rbacv1.RoleBindingList{}
	case *certmanagerv1.Certificate:
		return &certmanagerv1.CertificateList{}
	case *certmanagerv1.Issuer:
		return &certmanagerv1.IssuerList{}
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		return &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	default:
		return nil
	}
}

// getItemsFromList extracts items from a list object as client.Objects.
func getItemsFromList(list client.ObjectList) []client.Object {
	var items []client.Object

	switch l := list.(type) {
	case *appsv1.DeploymentList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *corev1.ServiceAccountList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *corev1.ServiceList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *corev1.ConfigMapList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *rbacv1.ClusterRoleList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *rbacv1.ClusterRoleBindingList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *rbacv1.RoleList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *rbacv1.RoleBindingList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *certmanagerv1.CertificateList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *certmanagerv1.IssuerList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *admissionregistrationv1.ValidatingWebhookConfigurationList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	}

	return items
}

// =============================================================================
// HELPER METHODS
// =============================================================================

// getResourceLabels returns labels to apply to all created resources.
// Includes default labels plus any user-specified labels.
func (r *Reconciler) getResourceLabels(trustManager *v1alpha1.TrustManager) map[string]string {
	labels := make(map[string]string)

	// Start with controller defaults
	for k, v := range controllerDefaultResourceLabels {
		labels[k] = v
	}

	// Add user-specified labels
	if trustManager.Spec.ControllerConfig != nil {
		for k, v := range trustManager.Spec.ControllerConfig.Labels {
			labels[k] = v
		}
	}

	return labels
}

// containsProcessedAnnotation checks if the CR has been successfully reconciled before.
func containsProcessedAnnotation(trustManager *v1alpha1.TrustManager) bool {
	annotations := trustManager.GetAnnotations()
	if annotations == nil {
		return false
	}
	_, exists := annotations[controllerProcessedAnnotation]
	return exists
}

// addProcessedAnnotation marks the CR as successfully reconciled.
func (r *Reconciler) addProcessedAnnotation(trustManager *v1alpha1.TrustManager) error {
	if containsProcessedAnnotation(trustManager) {
		return nil
	}

	annotations := trustManager.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[controllerProcessedAnnotation] = "true"
	trustManager.SetAnnotations(annotations)

	if err := r.UpdateWithRetry(r.ctx, trustManager); err != nil {
		return FromClientError(err, "failed to add processed annotation")
	}

	return nil
}

// updateCondition updates the TrustManager status conditions.
func (r *Reconciler) updateCondition(trustManager *v1alpha1.TrustManager) error {
	if err := r.StatusUpdate(r.ctx, trustManager); err != nil {
		return FromClientError(err, "failed to update TrustManager status")
	}
	return nil
}

// addFinalizer adds the controller finalizer if not present.
func (r *Reconciler) addFinalizer(ctx context.Context, trustManager *v1alpha1.TrustManager) error {
	if controllerutil.ContainsFinalizer(trustManager, finalizer) {
		return nil
	}

	if !controllerutil.AddFinalizer(trustManager, finalizer) {
		return fmt.Errorf("failed to add finalizer to TrustManager %q", trustManager.GetName())
	}

	if err := r.UpdateWithRetry(ctx, trustManager); err != nil {
		return fmt.Errorf("failed to update TrustManager %q with finalizer: %w", trustManager.GetName(), err)
	}

	r.log.V(2).Info("added finalizer", "name", trustManager.GetName())
	return nil
}

// removeFinalizer removes the controller finalizer.
func (r *Reconciler) removeFinalizer(ctx context.Context, trustManager *v1alpha1.TrustManager) error {
	if !controllerutil.ContainsFinalizer(trustManager, finalizer) {
		return nil
	}

	if !controllerutil.RemoveFinalizer(trustManager, finalizer) {
		return fmt.Errorf("failed to remove finalizer from TrustManager %q", trustManager.GetName())
	}

	if err := r.UpdateWithRetry(ctx, trustManager); err != nil {
		return fmt.Errorf("failed to update TrustManager %q after removing finalizer: %w", trustManager.GetName(), err)
	}

	r.log.V(2).Info("removed finalizer", "name", trustManager.GetName())
	return nil
}

// Note: The actual implementation of these methods is in separate files:
// - serviceaccounts.go: createOrApplyServiceAccount()
// - rbacs.go: createOrApplyRBACResources()
// - services.go: createOrApplyServices()
// - certificates.go: createOrApplyCertificates()
// - deployments.go: createOrApplyDeployment()
// - webhooks.go: createOrApplyWebhook()
