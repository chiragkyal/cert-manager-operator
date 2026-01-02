package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// =============================================================================
// SERVICE RECONCILIATION
// =============================================================================
// trust-manager requires two Services:
//
// 1. trust-manager (webhook): Exposes the validating webhook for Bundle CRs
//    - Port 443 -> 6443 (webhook server in container)
//
// 2. trust-manager-metrics: Exposes Prometheus metrics
//    - Port 9402 -> 9402

// createOrApplyServices reconciles both trust-manager Services.
func (r *Reconciler) createOrApplyServices(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	// Webhook service
	if err := r.createOrApplyService(trustManager, resourceLabels, isNewReconcile, serviceAssetName); err != nil {
		return err
	}

	// Metrics service
	if err := r.createOrApplyService(trustManager, resourceLabels, isNewReconcile, metricsServiceAssetName); err != nil {
		return err
	}

	return nil
}

// createOrApplyService reconciles a single Service.
func (r *Reconciler) createOrApplyService(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
	assetName string,
) error {
	desired := r.getServiceObject(trustManager, resourceLabels, assetName)
	svcName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling Service", "name", svcName)

	fetched := &corev1.Service{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if Service %s exists", svcName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Service %s already exists", svcName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("Service has changed, updating", "name", svcName)
			// Preserve ClusterIP - it's assigned by Kubernetes and can't be changed
			desired.Spec.ClusterIP = fetched.Spec.ClusterIP
			desired.Spec.ClusterIPs = fetched.Spec.ClusterIPs
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update Service %s", svcName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Service %s updated", svcName)
		} else {
			r.log.V(4).Info("Service is in expected state", "name", svcName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create Service %s", svcName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Service %s created", svcName)
	}

	return nil
}

// getServiceObject loads a Service from bindata and customizes it.
func (r *Reconciler) getServiceObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	assetName string,
) *corev1.Service {
	svc := decodeServiceObjBytes(assets.MustAsset(assetName))

	// Set namespace to cert-manager
	updateNamespace(svc, operandNamespace)

	// Apply labels to metadata
	updateResourceLabels(svc, resourceLabels)

	// Update selector to match our pod labels
	// The selector should use the base "app" label
	svc.Spec.Selector = map[string]string{
		"app": trustManagerCommonName,
	}

	// Apply user-specified annotations if any
	if len(trustManager.Spec.ControllerConfig.Annotations) > 0 {
		updateResourceAnnotations(svc, trustManager.Spec.ControllerConfig.Annotations)
	}

	return svc
}
