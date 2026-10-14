package approverpolicy

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
)

const (
	// ControllerName identifies this operand controller.
	ControllerName = "cert-manager-approver-policy-controller"
	// RequestEnqueueLabelValue identifies managed resources in the shared cache.
	RequestEnqueueLabelValue = "cert-manager-approver-policy"
	operandName              = "cert-manager-approver-policy"
	operandNamespace         = "cert-manager"
	managerName              = "cluster"
	fieldOwner               = "approver-policy-controller"
	cleanupFinalizer         = "operator.openshift.io/approver-policy-cleanup"
	requeueInterval          = 30 * time.Second
)

// Reconciler installs the optional approver-policy operand. Default-approver
// coordination belongs to the active CertManager controller, not this reconciler.
type Reconciler struct {
	common.CtrlClient
	log logr.Logger
}

// +kubebuilder:rbac:groups=operator.openshift.io,resources=approverpolicymanagers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=approverpolicymanagers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=approverpolicymanagers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets;services;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings;clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// The operator must hold the signer permission it grants to the operand; no RBAC escalation exemption is needed.
// +kubebuilder:rbac:groups=cert-manager.io,resources=signers,verbs=approve
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy.cert-manager.io,resources=certificaterequestpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy.cert-manager.io,resources=certificaterequestpolicies/status,verbs=patch
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// New constructs the reconciler using the shared manager client.
func New(mgr ctrl.Manager) (*Reconciler, error) {
	c, err := common.NewClient(mgr)
	if err != nil {
		return nil, err
	}
	return &Reconciler{CtrlClient: c, log: ctrl.Log.WithName(ControllerName)}, nil
}

// operandResourcePredicate includes status-only events, including Deployment
// readiness loss and cainjector updates, and does not rely on a mutable label.
func operandResourcePredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return (obj.GetNamespace() == "" || obj.GetNamespace() == operandNamespace) &&
			(obj.GetName() == operandName || obj.GetName() == operandName+"-metrics" || obj.GetName() == operandName+"-tls")
	})
}

func managerResourcePredicate() predicate.Predicate {
	return predicate.Or(predicate.GenerationChangedPredicate{}, predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld != nil && e.ObjectNew != nil &&
				!e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp())
		},
	})
}

// SetupWithManager registers watches only when the operator enables this controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: managerName}}}
	})
	b := ctrl.NewControllerManagedBy(mgr).Named(ControllerName).
		For(&v1alpha1.ApproverPolicyManager{}, builder.WithPredicates(managerResourcePredicate()))
	for _, obj := range []client.Object{&corev1.ServiceAccount{}, &corev1.Secret{}, &corev1.Service{},
		&appsv1.Deployment{}, &rbacv1.Role{}, &rbacv1.RoleBinding{}, &rbacv1.ClusterRole{},
		&rbacv1.ClusterRoleBinding{}, &admissionv1.ValidatingWebhookConfiguration{}} {
		b = b.Watches(obj, enqueue, builder.WithPredicates(operandResourcePredicate()))
	}
	b = b.Watches(&corev1.Namespace{}, enqueue, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == operandNamespace
	})))
	return b.Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != managerName || req.Namespace != "" {
		return ctrl.Result{}, nil
	}
	manager := &v1alpha1.ApproverPolicyManager{}
	if err := r.Get(ctx, req.NamespacedName, manager); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	original := manager.Status.DeepCopy()
	var reconcileErr error
	lifecycle := !manager.DeletionTimestamp.IsZero() || !slices.Contains(manager.Finalizers, cleanupFinalizer)
	switch {
	case !manager.DeletionTimestamp.IsZero():
		if !slices.Contains(manager.Finalizers, cleanupFinalizer) {
			return ctrl.Result{}, nil
		}
		reconcileErr = r.removeOperand(ctx, manager)
		if reconcileErr == nil {
			reconcileErr = r.updateFinalizer(ctx, manager, false)
			if reconcileErr == nil {
				// Removing the last finalizer can delete the manager immediately.
				return ctrl.Result{}, nil
			}
		}
	case !slices.Contains(manager.Finalizers, cleanupFinalizer):
		reconcileErr = r.updateFinalizer(ctx, manager, true)
		if reconcileErr == nil {
			// Observe the persisted finalizer before installing any resource.
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
	default:
		reconcileErr = r.reconcileOperand(ctx, manager)
	}
	// Accumulate conditions and image identity, then persist one coherent status.
	// The shared helper may skip its callback when only the image changed.
	result, _ := common.HandleReconcileResult(&manager.Status.ConditionalStatus, reconcileErr, r.log,
		func(error) error { return nil }, requeueInterval)
	if lifecycle && reconcileErr != nil {
		// Permission corrections do not necessarily enqueue this manager.
		result.RequeueAfter = requeueInterval
	}
	for i := range manager.Status.Conditions {
		manager.Status.Conditions[i].ObservedGeneration = manager.Generation
	}
	if reconcileErr != nil {
		condition := manager.Status.GetCondition(v1alpha1.Ready)
		if common.IsIrrecoverableError(reconcileErr) {
			condition = manager.Status.GetCondition(v1alpha1.Degraded)
		}
		// SetCondition intentionally ignores message-only changes. Persist the
		// current diagnostic without changing its transition timestamp.
		condition.Message = reconcileErr.Error()
	}
	if !equality.Semantic.DeepEqual(original, &manager.Status) {
		if err := r.updateStatus(ctx, manager); err != nil {
			return ctrl.Result{}, utilerrors.NewAggregate([]error{reconcileErr, err})
		}
	}
	return result, nil
}

func (r *Reconciler) updateFinalizer(ctx context.Context, manager *v1alpha1.ApproverPolicyManager, add bool) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &v1alpha1.ApproverPolicyManager{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(manager), current); err != nil {
			return err
		}
		if current.UID != manager.UID || (add && !current.DeletionTimestamp.IsZero()) || (!add && current.DeletionTimestamp.IsZero()) {
			return fmt.Errorf("ApproverPolicyManager changed during finalization; retry")
		}
		if slices.Contains(current.Finalizers, cleanupFinalizer) == add {
			return nil
		}
		if add {
			current.Finalizers = append(current.Finalizers, cleanupFinalizer)
		} else {
			current.Finalizers = slices.DeleteFunc(current.Finalizers, func(f string) bool { return f == cleanupFinalizer })
		}
		return r.Update(ctx, current)
	})
	if err != nil {
		return common.FromClientError(err, "persist approver-policy cleanup finalizer")
	}
	return nil
}

func (r *Reconciler) removeOperand(ctx context.Context, manager *v1alpha1.ApproverPolicyManager) error {
	objects, err := importedResources()
	if err != nil {
		return common.NewIrrecoverableError(err, "read approver-policy removal inventory")
	}
	// Stop the policy controller first. Foreground deletion keeps the Deployment
	// present until its blocking ReplicaSet/Pod dependents have been removed.
	for _, obj := range objects {
		if obj.GetKind() == "Deployment" {
			pending, err := r.removeOwnedResource(ctx, manager, obj, metav1.DeletePropagationForeground)
			if err != nil {
				return err
			}
			if pending {
				return common.NewRetryRequiredError(fmt.Errorf("deployment or its dependents are still being removed"), "waiting for approver-policy shutdown")
			}
		}
	}
	pending := false
	for _, obj := range slices.Backward(objects) {
		if obj.GetKind() == "Deployment" {
			continue
		}
		remaining, err := r.removeOwnedResource(ctx, manager, obj, metav1.DeletePropagationBackground)
		if err != nil {
			return err
		}
		pending = pending || remaining
	}
	if pending {
		return common.NewRetryRequiredError(fmt.Errorf("owned resources are still being removed"), "waiting for approver-policy cleanup")
	}
	return nil
}

func (r *Reconciler) removeOwnedResource(ctx context.Context, manager *v1alpha1.ApproverPolicyManager, obj *unstructured.Unstructured, propagation metav1.DeletionPropagation) (bool, error) {
	if err := r.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, common.FromClientError(err, "observe %s %s for removal", obj.GetKind(), obj.GetName())
	}
	owner := metav1.GetControllerOf(obj)
	if manager.UID == "" || owner == nil || owner.UID != manager.UID || owner.Name != manager.Name ||
		owner.Kind != "ApproverPolicyManager" || owner.APIVersion != v1alpha1.SchemeGroupVersion.String() {
		return false, nil // Never delete a foreign resource that reused an inventory name.
	}
	if obj.GetDeletionTimestamp().IsZero() {
		uid, version := obj.GetUID(), obj.GetResourceVersion()
		if uid == "" || version == "" {
			return true, common.NewRetryRequiredError(fmt.Errorf("missing resource identity"), "cannot safely remove %s %s", obj.GetKind(), obj.GetName())
		}
		err := r.Delete(ctx, obj, client.PropagationPolicy(propagation), client.Preconditions{UID: &uid, ResourceVersion: &version})
		if err != nil && !apierrors.IsNotFound(err) {
			return true, common.FromClientError(err, "remove %s %s", obj.GetKind(), obj.GetName())
		}
	}
	return true, nil // Confirm absence in a subsequent reconcile, including after Delete/NotFound.
}

func (r *Reconciler) updateStatus(ctx context.Context, desired *v1alpha1.ApproverPolicyManager) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &v1alpha1.ApproverPolicyManager{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(desired), current); err != nil {
			return err
		}
		if current.UID != desired.UID || current.Generation != desired.Generation {
			return fmt.Errorf("ApproverPolicyManager changed during reconciliation; retry with current configuration")
		}
		desired.Status.DeepCopyInto(&current.Status)
		return r.StatusUpdate(ctx, current)
	})
}

func (r *Reconciler) reconcileOperand(ctx context.Context, manager *v1alpha1.ApproverPolicyManager) error {
	if err := r.Get(ctx, client.ObjectKey{Name: operandNamespace}, &corev1.Namespace{}); err != nil {
		return common.FromClientError(err, "required namespace %s is unavailable; install cert-manager first", operandNamespace)
	}
	objects, err := desiredResources(manager)
	if err != nil {
		return common.NewIrrecoverableError(err, "cannot construct approver-policy resources")
	}
	var deployment *unstructured.Unstructured
	for _, obj := range objects {
		if err := r.applyResource(ctx, obj); err != nil {
			return err
		}
		if obj.GetKind() == "Deployment" {
			deployment = obj
		}
	}
	observed := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: operandNamespace, Name: operandName}, observed); err != nil {
		return common.FromClientError(err, "observe approver-policy Deployment")
	}
	for _, container := range observed.Spec.Template.Spec.Containers {
		if container.Name == operandName {
			manager.Status.ApproverPolicyImage = container.Image
		}
	}
	observed.SetGroupVersionKind(deployment.GroupVersionKind())
	observedFields, err := runtime.DefaultUnstructuredConverter.ToUnstructured(observed)
	if err != nil {
		return common.NewIrrecoverableError(err, "decode observed Deployment")
	}
	if !managedFieldsEqual(deployment.Object, observedFields) || !deploymentReady(observed) {
		return common.NewRetryRequiredError(fmt.Errorf("desired Deployment rollout has not converged"), "waiting for approver-policy readiness")
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: operandNamespace, Name: operandName + "-tls"}, secret); err != nil {
		return common.FromClientError(err, "observe webhook TLS Secret")
	}
	if len(secret.Data) == 0 {
		return common.NewRetryRequiredError(fmt.Errorf("webhook TLS Secret is not populated"), "waiting for approver-policy TLS")
	}
	webhook := &admissionv1.ValidatingWebhookConfiguration{}
	if err := r.Get(ctx, client.ObjectKey{Name: operandName}, webhook); err != nil {
		return common.FromClientError(err, "observe webhook CA injection")
	}
	if len(webhook.Webhooks) != 1 || len(webhook.Webhooks[0].ClientConfig.CABundle) == 0 {
		return common.NewRetryRequiredError(fmt.Errorf("webhook CA bundle is not injected"), "waiting for approver-policy TLS")
	}
	return nil
}

func deploymentReady(d *appsv1.Deployment) bool {
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	return d.DeletionTimestamp.IsZero() && replicas > 0 && d.Generation > 0 &&
		d.Status.ObservedGeneration >= d.Generation && d.Status.UpdatedReplicas == replicas &&
		d.Status.AvailableReplicas == replicas && d.Status.ReadyReplicas == replicas &&
		d.Status.Replicas == replicas && d.Status.UnavailableReplicas == 0
}
