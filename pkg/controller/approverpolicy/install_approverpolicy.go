package approverpolicy

import (
	"errors"
	"fmt"
	"os"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
)

// errDeploymentNotAvailable is a sentinel, recoverable error used to signal that the
// approver-policy Deployment has not yet reached Available with the expected replica
// count. This is intentionally treated as a retryable (not irrecoverable) condition by
// common.HandleReconcileResult, which sets Ready=False/Progressing and requeues.
//
// This gating matters: the cert-manager controller watches ApproverPolicyManager's
// Ready=True condition to decide when it is safe to disable the built-in
// CertificateRequest auto-approver. Reporting Ready=True before the operand pod is
// actually running and serving would create a certificate-approval gap.
var errDeploymentNotAvailable = errors.New("approver-policy deployment is not yet available with the expected replica count")

func (r *Reconciler) reconcileApproverPolicyDeployment(apm *v1alpha1.ApproverPolicyManager) error {
	if err := validateApproverPolicyConfig(apm); err != nil {
		return common.NewIrrecoverableError(err, "%s configuration validation failed", apm.GetName())
	}

	if err := r.validateOperandNamespace(); err != nil {
		return common.NewIrrecoverableError(err, "operand namespace %q validation failed", operandNamespace)
	}

	resourceLabels := getResourceLabels(apm)
	resourceAnnotations := getResourceAnnotations(apm)

	if err := r.createOrApplyServiceAccount(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile serviceaccount resource")
		return err
	}

	if err := r.createOrApplyRBACResources(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile RBAC resources")
		return err
	}

	if err := r.createOrApplyServices(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile service resources")
		return err
	}

	if err := r.createOrApplyWebhookTLSSecret(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile webhook TLS secret resource")
		return err
	}

	if err := r.createOrApplyDeployment(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile deployment resource")
		return err
	}

	if err := r.createOrApplyValidatingWebhookConfiguration(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile validatingwebhookconfiguration resource")
		return err
	}

	if err := r.updateStatusObservedState(apm); err != nil {
		return common.FromClientError(err, "failed to update status observed state")
	}

	available, err := r.isDeploymentAvailable()
	if err != nil {
		return err
	}
	if !available {
		r.log.V(2).Info("waiting for approver-policy deployment to become available", "name", apm.GetName())
		return common.NewRetryRequiredError(errDeploymentNotAvailable, "approver-policy deployment %q is not yet available", approverPolicyDeploymentName)
	}

	r.log.V(4).Info("finished reconciliation of approverpolicymanager", "name", apm.GetName())
	return nil
}

// validateOperandNamespace validates that the operand namespace exists.
func (r *Reconciler) validateOperandNamespace() error {
	exists, err := r.namespaceExists(operandNamespace)
	if err != nil {
		return fmt.Errorf("failed to check if namespace %q exists: %w", operandNamespace, err)
	}
	if !exists {
		return fmt.Errorf("operand namespace %q does not exist, create the namespace before creating ApproverPolicyManager CR", operandNamespace)
	}
	return nil
}

// isDeploymentAvailable reports whether the approver-policy Deployment has an
// AvailableReplicas count that matches (or exceeds) the desired replica count, and that
// the Deployment status reflects the latest observed generation.
func (r *Reconciler) isDeploymentAvailable() (bool, error) {
	deployment := &appsv1.Deployment{}
	key := client.ObjectKey{Name: approverPolicyDeploymentName, Namespace: operandNamespace}
	exists, err := r.Exists(r.ctx, key, deployment)
	if err != nil {
		return false, common.FromClientError(err, "failed to check if deployment %q exists", key)
	}
	if !exists {
		return false, nil
	}

	desiredReplicas := int32(1)
	if deployment.Spec.Replicas != nil {
		desiredReplicas = *deployment.Spec.Replicas
	}

	if deployment.Status.ObservedGeneration < deployment.Generation {
		return false, nil
	}

	return deployment.Status.AvailableReplicas >= desiredReplicas, nil
}

// updateStatusObservedState populates and persists the ApproverPolicyManager status with the observed state.
// Returns nil if no changes were needed, otherwise returns an error if the update fails.
func (r *Reconciler) updateStatusObservedState(apm *v1alpha1.ApproverPolicyManager) error {
	changed := false

	if image := os.Getenv(approverPolicyImageNameEnvVarName); apm.Status.ApproverPolicyImage != image {
		apm.Status.ApproverPolicyImage = image
		changed = true
	}

	if !changed {
		return nil
	}

	return r.updateStatus(r.ctx, apm)
}

// deleteApproverPolicyResources deletes all operator-created resources for the
// approver-policy operand. It is only called when the ApproverPolicyManager CR is being
// deleted (Story 9 -- finalizer-gated cleanup). Deletions are best-effort idempotent:
// NotFound errors are ignored so that repeated cleanup attempts (e.g. after a partial
// failure) converge safely. User-created CertificateRequestPolicy resources are
// intentionally NOT deleted (Non-Goal in the enhancement).
func (r *Reconciler) deleteApproverPolicyResources() error {
	var errs []error

	deleters := []func() error{
		func() error {
			return r.deleteObject(&appsv1.Deployment{}, client.ObjectKey{Name: approverPolicyDeploymentName, Namespace: operandNamespace})
		},
		func() error {
			return r.deleteObject(&admissionregistrationv1.ValidatingWebhookConfiguration{}, client.ObjectKey{Name: approverPolicyWebhookConfigName})
		},
		func() error {
			return r.deleteObject(&corev1.Service{}, client.ObjectKey{Name: approverPolicyServiceName, Namespace: operandNamespace})
		},
		func() error {
			return r.deleteObject(&corev1.Service{}, client.ObjectKey{Name: approverPolicyMetricsServiceName, Namespace: operandNamespace})
		},
		func() error {
			return r.deleteObject(&corev1.Secret{}, client.ObjectKey{Name: webhookTLSSecretName, Namespace: operandNamespace})
		},
		func() error {
			return r.deleteObject(&rbacv1.RoleBinding{}, client.ObjectKey{Name: approverPolicyRoleBindingName, Namespace: operandNamespace})
		},
		func() error {
			return r.deleteObject(&rbacv1.Role{}, client.ObjectKey{Name: approverPolicyRoleName, Namespace: operandNamespace})
		},
		func() error {
			return r.deleteObject(&rbacv1.ClusterRoleBinding{}, client.ObjectKey{Name: approverPolicyClusterRoleBindingName})
		},
		func() error {
			return r.deleteObject(&rbacv1.ClusterRole{}, client.ObjectKey{Name: approverPolicyClusterRoleName})
		},
		func() error {
			return r.deleteObject(&corev1.ServiceAccount{}, client.ObjectKey{Name: approverPolicyServiceAccountName, Namespace: operandNamespace})
		},
	}

	for _, del := range deleters {
		if err := del(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return common.NewRetryRequiredError(joinErrors(errs), "failed to delete one or more approver-policy resources")
	}
	return nil
}

func (r *Reconciler) deleteObject(obj client.Object, key client.ObjectKey) error {
	obj.SetName(key.Name)
	obj.SetNamespace(key.Namespace)
	if err := r.Delete(r.ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete %T %q: %w", obj, key, err)
	}
	return nil
}

func joinErrors(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	msg := "multiple errors occurred:"
	for _, e := range errs {
		msg += " [" + e.Error() + "]"
	}
	return errors.New(msg)
}
