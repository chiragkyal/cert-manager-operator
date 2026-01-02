package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// =============================================================================
// SERVICE ACCOUNT RECONCILIATION
// =============================================================================
// The ServiceAccount provides the identity for the trust-manager pod.
// It's referenced by:
// - The Deployment (pod runs as this SA)
// - ClusterRoleBinding/RoleBinding (grants permissions to this SA)

// createOrApplyServiceAccount ensures the trust-manager ServiceAccount exists
// with the correct configuration.
func (r *Reconciler) createOrApplyServiceAccount(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	// Get the desired ServiceAccount state
	desired := r.getServiceAccountObject(trustManager, resourceLabels)
	saName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling ServiceAccount", "name", saName)

	// Check if it already exists
	fetched := &corev1.ServiceAccount{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if ServiceAccount %s exists", saName)
	}

	if exists {
		if isNewReconcile {
			// Warn on first reconcile if SA already exists (might be from previous install)
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"ServiceAccount %s already exists, may be from previous installation", saName)
		}

		// Check if update needed
		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("ServiceAccount has changed, updating", "name", saName)
			// Copy resourceVersion for update
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update ServiceAccount %s", saName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"ServiceAccount %s updated", saName)
		} else {
			r.log.V(4).Info("ServiceAccount is in expected state", "name", saName)
		}
	} else {
		// Create the ServiceAccount
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create ServiceAccount %s", saName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"ServiceAccount %s created", saName)
	}

	return nil
}

// getServiceAccountObject loads the ServiceAccount from bindata and customizes it.
func (r *Reconciler) getServiceAccountObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *corev1.ServiceAccount {
	// Load from bindata
	sa := decodeServiceAccountObjBytes(assets.MustAsset(serviceAccountAssetName))

	// Set namespace to cert-manager (hardcoded per design)
	updateNamespace(sa, operandNamespace)

	// Apply labels (includes controller tracking labels)
	updateResourceLabels(sa, resourceLabels)

	// Apply user-specified annotations if any
	if len(trustManager.Spec.ControllerConfig.Annotations) > 0 {
		updateResourceAnnotations(sa, trustManager.Spec.ControllerConfig.Annotations)
	}

	return sa
}
