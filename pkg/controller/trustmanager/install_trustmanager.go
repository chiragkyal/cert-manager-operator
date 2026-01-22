package trustmanager

import (
	"fmt"
	"os"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
)

func (r *Reconciler) reconcileTrustManagerDeployment(trustManager *v1alpha1.TrustManager, trustManagerCreateRecon bool) error {
	if err := validateTrustManagerConfig(trustManager); err != nil {
		return common.NewIrrecoverableError(err, "%s configuration validation failed", trustManager.GetName())
	}

	resourceLabels := getResourceLabels(trustManager)

	// Validate trust namespace exists
	trustNamespace := getTrustNamespace(trustManager)
	if err := r.validateTrustNamespace(trustNamespace); err != nil {
		return common.NewIrrecoverableError(err, "trust namespace %q validation failed", trustNamespace)
	}

	// TODO: Reconcile all trust-manager resources
	// For now, just reconcile ServiceAccount to verify controller is working
	if err := r.createOrApplyServiceAccounts(trustManager, resourceLabels, trustManagerCreateRecon); err != nil {
		r.log.Error(err, "failed to reconcile serviceaccount resource")
		return err
	}

	// Set status observed state fields (not persisted until updateCondition is called)
	r.setStatusObservedState(trustManager)

	if addProcessedAnnotation(trustManager) {
		if err := r.UpdateWithRetry(r.ctx, trustManager); err != nil {
			return fmt.Errorf("failed to update processed annotation to %s: %w", trustManager.GetName(), err)
		}
	}

	r.log.V(4).Info("finished reconciliation of trustmanager", "name", trustManager.GetName())
	return nil
}

// validateTrustNamespace validates that the trust namespace exists.
func (r *Reconciler) validateTrustNamespace(namespace string) error {
	exists, err := r.namespaceExists(namespace)
	if err != nil {
		return fmt.Errorf("failed to check if namespace %q exists: %w", namespace, err)
	}
	if !exists {
		return fmt.Errorf("trust namespace %q does not exist, create the namespace before creating TrustManager CR", namespace)
	}
	return nil
}

// setStatusObservedState populates the TrustManager status with the observed state.
// This only sets the in-memory fields; actual persistence happens via updateCondition().
// TODO: As the implementation extends, move status field updates inline within each
// resource reconciler
func (r *Reconciler) setStatusObservedState(trustManager *v1alpha1.TrustManager) {
	trustManager.Status.TrustManagerImage = os.Getenv(trustManagerImageNameEnvVarName)
	trustManager.Status.TrustNamespace = getTrustNamespace(trustManager)
	trustManager.Status.SecretTargetsPolicy = trustManager.Spec.TrustManagerConfig.SecretTargets.Policy
	trustManager.Status.DefaultCAPackagePolicy = trustManager.Spec.TrustManagerConfig.DefaultCAPackage.Policy
}
