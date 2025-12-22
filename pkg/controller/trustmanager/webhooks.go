package trustmanager

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// =============================================================================
// WEBHOOK CONFIGURATION RECONCILIATION
// =============================================================================
// trust-manager uses a ValidatingWebhookConfiguration to validate Bundle CRs.
// The webhook ensures that:
// - Bundle specs are valid
// - Target configurations are correct
// - Source references exist
//
// The webhook's CA bundle is injected by cert-manager via the annotation:
//   cert-manager.io/inject-ca-from: "cert-manager/trust-manager"
//
// This annotation tells cert-manager to copy the CA from the Certificate's
// secret into the webhook's clientConfig.caBundle field.

// createOrApplyWebhook reconciles the ValidatingWebhookConfiguration.
func (r *Reconciler) createOrApplyWebhook(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	desired := r.getValidatingWebhookObject(trustManager, resourceLabels)
	webhookName := desired.GetName()

	r.log.V(4).Info("reconciling ValidatingWebhookConfiguration", "name", webhookName)

	fetched := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if ValidatingWebhookConfiguration %s exists", webhookName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"ValidatingWebhookConfiguration %s already exists", webhookName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("ValidatingWebhookConfiguration has changed, updating", "name", webhookName)
			// Preserve the CA bundle - it's injected by cert-manager
			for i := range desired.Webhooks {
				if i < len(fetched.Webhooks) {
					desired.Webhooks[i].ClientConfig.CABundle = fetched.Webhooks[i].ClientConfig.CABundle
				}
			}
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update ValidatingWebhookConfiguration %s", webhookName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"ValidatingWebhookConfiguration %s updated", webhookName)
		} else {
			r.log.V(4).Info("ValidatingWebhookConfiguration is in expected state", "name", webhookName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create ValidatingWebhookConfiguration %s", webhookName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"ValidatingWebhookConfiguration %s created", webhookName)
	}

	return nil
}

// getValidatingWebhookObject builds the ValidatingWebhookConfiguration.
func (r *Reconciler) getValidatingWebhookObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *admissionregistrationv1.ValidatingWebhookConfiguration {
	webhook := decodeValidatingWebhookConfigurationObjBytes(assets.MustAsset(validatingWebhookAssetName))

	// Apply labels
	updateResourceLabels(webhook, resourceLabels)

	// Update annotations for CA injection
	// cert-manager will inject the CA from the Certificate secret
	annotations := webhook.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	// Format: <namespace>/<certificate-name>
	annotations["cert-manager.io/inject-ca-from"] = fmt.Sprintf("%s/%s", operandNamespace, trustManagerCommonName)
	webhook.SetAnnotations(annotations)

	// Apply user-specified annotations (but don't override inject-ca-from)
	if trustManager.Spec.ControllerConfig != nil && trustManager.Spec.ControllerConfig.Annotations != nil {
		currentAnnotations := webhook.GetAnnotations()
		for k, v := range trustManager.Spec.ControllerConfig.Annotations {
			// Don't override the CA injection annotation
			if k != "cert-manager.io/inject-ca-from" {
				currentAnnotations[k] = v
			}
		}
		webhook.SetAnnotations(currentAnnotations)
	}

	// Update webhook service references to use cert-manager namespace
	for i := range webhook.Webhooks {
		if webhook.Webhooks[i].ClientConfig.Service != nil {
			webhook.Webhooks[i].ClientConfig.Service.Namespace = operandNamespace
		}
	}

	return webhook
}
