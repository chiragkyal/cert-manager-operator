package approverpolicy

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
)

// RequestEnqueueLabelValue is the label value used for filtering reconcile
// events to include only the resources created by the ApproverPolicy controller.
// The label key is common.ManagedResourceLabelKey.
const RequestEnqueueLabelValue = approverPolicyCommonName

// Reconciler reconciles an ApproverPolicyManager object.
type Reconciler struct {
	common.CtrlClient

	ctx           context.Context
	eventRecorder record.EventRecorder
	log           logr.Logger
	scheme        *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.openshift.io,resources=approverpolicymanagers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=approverpolicymanagers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=approverpolicymanagers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy.cert-manager.io,resources=certificaterequestpolicies,verbs=get;list;watch

// New returns a new Reconciler instance.
func New(mgr ctrl.Manager) (*Reconciler, error) {
	c, err := common.NewClient(mgr)
	if err != nil {
		return nil, err
	}
	return &Reconciler{
		CtrlClient:    c,
		ctx:           context.Background(),
		eventRecorder: mgr.GetEventRecorderFor(ControllerName),
		log:           ctrl.Log.WithName(ControllerName),
		scheme:        mgr.GetScheme(),
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	// mapFunc unconditionally enqueues the singleton ApproverPolicyManager CR.
	// Filtering is handled by predicates attached to each Watch.
	mapFunc := func(ctx context.Context, obj client.Object) []reconcile.Request {
		r.log.V(4).Info("received reconcile event", "object", fmt.Sprintf("%T", obj), "name", obj.GetName(), "namespace", obj.GetNamespace())
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: approverPolicyManagerObjectName}}}
	}

	isManagedResource := func(object client.Object) bool {
		labels := object.GetLabels()
		matches := labels != nil && labels[common.ManagedResourceLabelKey] == RequestEnqueueLabelValue
		r.log.V(4).Info("predicate evaluation", "object", fmt.Sprintf("%T", object), "name", object.GetName(), "namespace", object.GetNamespace(), "labels", labels, "matches", matches)
		return matches
	}

	// Predicate to filter events for resources managed by this controller.
	// On updates, checks both old and new objects so that events where the
	// managed label is removed still trigger reconciliation.
	controllerManagedResources := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isManagedResource(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isManagedResource(e.ObjectOld) || isManagedResource(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isManagedResource(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return isManagedResource(e.Object)
		},
	}

	controllerManagedResourcePredicates := builder.WithPredicates(controllerManagedResources)

	// withIgnoreStatusUpdatePredicates filters out status-only updates while still
	// detecting spec changes (generation bump) and metadata drift (label/annotation edits).
	withIgnoreStatusUpdatePredicates := builder.WithPredicates(
		predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
		),
		controllerManagedResources,
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ApproverPolicyManager{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named(ControllerName).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestsFromMapFunc(mapFunc), withIgnoreStatusUpdatePredicates).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.Role{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&rbacv1.RoleBinding{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Watches(&admissionregistrationv1.ValidatingWebhookConfiguration{}, handler.EnqueueRequestsFromMapFunc(mapFunc), controllerManagedResourcePredicates).
		Complete(r)
}

// Reconcile function to compare the state specified by the ApproverPolicyManager object against the actual
// cluster state, and to make the cluster state reflect the state specified by the user.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.log.V(1).Info("reconciling", "request", req)

	// Fetch the approverpolicymanagers.openshift.operator.io CR.
	apm := &v1alpha1.ApproverPolicyManager{}
	// Note: No namespace because ApproverPolicyManager is cluster-scoped.
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, apm); err != nil {
		if errors.IsNotFound(err) {
			// NotFound errors, since they can't be fixed by an immediate
			// requeue (have to wait for a new notification), and can be processed
			// on deleted requests.
			r.log.V(1).Info("approverpolicymanager.openshift.operator.io object not found, skipping reconciliation", "request", req)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to fetch approverpolicymanager.openshift.operator.io %q during reconciliation: %w", req.NamespacedName, err)
	}

	// Only the singleton named "cluster" is reconciled; the XValidation rule on the CRD
	// already rejects any other name at admission time, so this is a defense-in-depth check.
	if apm.GetName() != approverPolicyManagerObjectName {
		r.log.V(1).Info("ignoring approverpolicymanager.openshift.operator.io CR with unsupported name", "name", apm.GetName())
		return ctrl.Result{}, nil
	}

	if !apm.DeletionTimestamp.IsZero() {
		r.log.V(1).Info("approverpolicymanager.openshift.operator.io is marked for deletion", "name", req.NamespacedName)

		if err := r.cleanUp(apm); err != nil {
			return ctrl.Result{}, fmt.Errorf("clean up failed for %q approverpolicymanager.openshift.operator.io instance deletion: %w", req.NamespacedName, err)
		}

		if err := r.removeFinalizer(ctx, apm, finalizer); err != nil {
			return ctrl.Result{}, err
		}

		r.log.V(1).Info("removed finalizer, cleanup complete", "request", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Set finalizers on the approverpolicymanagers.openshift.operator.io resource.
	if err := r.addFinalizer(ctx, apm); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update %q approverpolicymanager.openshift.operator.io with finalizers: %w", req.NamespacedName, err)
	}

	return r.processReconcileRequest(apm, req.NamespacedName)
}

func (r *Reconciler) processReconcileRequest(apm *v1alpha1.ApproverPolicyManager, req types.NamespacedName) (ctrl.Result, error) {
	reconcileErr := r.reconcileApproverPolicyDeployment(apm)
	if reconcileErr != nil {
		r.log.Error(reconcileErr, "failed to reconcile ApproverPolicyManager deployment", "request", req)
	}

	return common.HandleReconcileResult(
		&apm.Status.ConditionalStatus,
		reconcileErr,
		r.log.WithValues("name", apm.GetName()),
		func(prependErr error) error {
			return r.updateCondition(apm, prependErr)
		},
		defaultRequeueTime,
	)
}

// cleanUp handles deletion of approverpolicymanagers.openshift.operator.io gracefully.
//
// Per the enhancement's design, ALL operator-created resources must be deleted before the
// finalizer is removed, so that the cert-manager controller only observes ApproverPolicyManager
// as `NotFound` (and re-enables the built-in auto-approver) after cleanup fully completes.
// Only resources created by the operator are removed; user-created CertificateRequestPolicy
// resources are explicitly out of scope (Non-Goal) and are left untouched.
func (r *Reconciler) cleanUp(apm *v1alpha1.ApproverPolicyManager) error {
	r.log.V(1).Info("cleaning up approver-policy operand resources", "name", apm.GetName())

	if err := r.deleteApproverPolicyResources(); err != nil {
		r.eventRecorder.Eventf(apm, corev1.EventTypeWarning, "CleanupFailed", "failed to clean up approver-policy resources, will retry: %v", err)
		return err
	}

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "CleanupComplete", "all approver-policy operand resources removed")
	return nil
}
