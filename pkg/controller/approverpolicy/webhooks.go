package approverpolicy

import (
	"reflect"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// createOrApplyValidatingWebhookConfiguration reconciles the ValidatingWebhookConfiguration
// that approver-policy registers for CertificateRequestPolicy admission review. Per the
// enhancement's "Webhook TLS Management" design, the webhook's `caBundle` is populated by
// cert-manager's CA-injector controller (via the `cert-manager.io/inject-ca-from-secret`
// annotation already present on the bindata manifest) sourced from the operator-managed
// bootstrap Secret, NOT set directly by this controller.
func (r *Reconciler) createOrApplyValidatingWebhookConfiguration(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getValidatingWebhookConfigurationObject(resourceLabels, resourceAnnotations)
	resourceName := desired.GetName()
	r.log.V(4).Info("reconciling validatingwebhookconfiguration resource", "name", resourceName)

	existing := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if validatingwebhookconfiguration %q exists", resourceName)
	}
	if exists && !validatingWebhookConfigurationModified(desired, existing) {
		r.log.V(4).Info("validatingwebhookconfiguration resource exists and is in desired state", "name", resourceName)
		return nil
	}

	r.log.V(2).Info("validatingwebhookconfiguration resource has been modified, updating to desired state", "name", resourceName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply validatingwebhookconfiguration %q", resourceName)
	}

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "validatingwebhookconfiguration resource %s applied", resourceName)
	return nil
}

func getValidatingWebhookConfigurationObject(resourceLabels, resourceAnnotations map[string]string) *admissionregistrationv1.ValidatingWebhookConfiguration {
	webhookConfig := common.DecodeObjBytes[*admissionregistrationv1.ValidatingWebhookConfiguration](codecs, admissionregistrationv1.SchemeGroupVersion, assets.MustAsset(validatingWebhookConfigAssetName))
	common.UpdateName(webhookConfig, approverPolicyWebhookConfigName)
	common.UpdateResourceLabels(webhookConfig, resourceLabels)
	updateResourceAnnotations(webhookConfig, resourceAnnotations)
	return webhookConfig
}

// validatingWebhookConfigurationModified compares only the fields we manage via SSA.
// The `caBundle` field (owned/set by cert-manager's CA-injector controller via annotation)
// is intentionally excluded from the comparison, since this controller never sets it and
// forcibly re-applying with an empty caBundle would cause a "fight" between field managers.
func validatingWebhookConfigurationModified(desired, existing *admissionregistrationv1.ValidatingWebhookConfiguration) bool {
	if managedMetadataModified(desired, existing) {
		return true
	}

	if len(desired.Webhooks) != len(existing.Webhooks) {
		return true
	}

	for i := range desired.Webhooks {
		if webhookModified(&desired.Webhooks[i], &existing.Webhooks[i]) {
			return true
		}
	}

	return false
}

func webhookModified(desired, existing *admissionregistrationv1.ValidatingWebhook) bool {
	if desired.Name != existing.Name ||
		!reflect.DeepEqual(desired.Rules, existing.Rules) ||
		!reflect.DeepEqual(desired.AdmissionReviewVersions, existing.AdmissionReviewVersions) ||
		!reflect.DeepEqual(desired.SideEffects, existing.SideEffects) ||
		!reflect.DeepEqual(desired.FailurePolicy, existing.FailurePolicy) ||
		!reflect.DeepEqual(desired.TimeoutSeconds, existing.TimeoutSeconds) {
		return true
	}

	if desired.ClientConfig.Service == nil || existing.ClientConfig.Service == nil {
		return desired.ClientConfig.Service != existing.ClientConfig.Service
	}

	return desired.ClientConfig.Service.Name != existing.ClientConfig.Service.Name ||
		desired.ClientConfig.Service.Namespace != existing.ClientConfig.Service.Namespace ||
		!reflect.DeepEqual(desired.ClientConfig.Service.Path, existing.ClientConfig.Service.Path)
}
