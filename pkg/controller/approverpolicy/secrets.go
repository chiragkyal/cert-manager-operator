package approverpolicy

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// createOrApplyWebhookTLSSecret reconciles the bootstrap Secret used by approver-policy to
// store its self-managed webhook CA/leaf certificates (see "Webhook TLS Management" in the
// enhancement). approver-policy uses cert-manager's DynamicSource CA provider to generate and
// rotate this Secret's data at runtime; the operator only ensures the Secret exists with the
// correct metadata (including the `cert-manager.io/allow-direct-injection` annotation) and never
// sets/overwrites the `data` field, so approver-policy's runtime-managed certificate content
// (owned by a different field manager) is never clobbered by this controller's Server-Side Apply.
func (r *Reconciler) createOrApplyWebhookTLSSecret(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getWebhookTLSSecretObject(resourceLabels, resourceAnnotations)
	secretName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())
	r.log.V(4).Info("reconciling webhook tls secret resource", "name", secretName)

	existing := &corev1.Secret{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if secret %q exists", secretName)
	}
	if exists && !secretModified(desired, existing) {
		r.log.V(4).Info("webhook tls secret resource exists and is in desired state", "name", secretName)
		return nil
	}

	r.log.V(2).Info("webhook tls secret resource has been modified, updating to desired state", "name", secretName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply secret %q", secretName)
	}

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "webhook tls secret resource %s applied", secretName)
	return nil
}

// secretModified compares only the metadata fields we manage via SSA. The `data` field is
// intentionally never compared/set: it is owned and populated at runtime by approver-policy.
func secretModified(desired, existing *corev1.Secret) bool {
	return managedMetadataModified(desired, existing)
}

func getWebhookTLSSecretObject(resourceLabels, resourceAnnotations map[string]string) *corev1.Secret {
	secret := common.DecodeObjBytes[*corev1.Secret](codecs, corev1.SchemeGroupVersion, assets.MustAsset(secretAssetName))
	common.UpdateName(secret, webhookTLSSecretName)
	common.UpdateNamespace(secret, operandNamespace)
	common.UpdateResourceLabels(secret, resourceLabels)
	updateResourceAnnotations(secret, resourceAnnotations)
	return secret
}
