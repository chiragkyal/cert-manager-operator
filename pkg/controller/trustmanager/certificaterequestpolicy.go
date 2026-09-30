package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// reconcileApproverPolicyIntegration reconciles the CertificateRequestPolicy, ClusterRole,
// and ClusterRoleBinding that allow approver-policy to approve trust-manager's webhook TLS
// certificate (Story 12). Per the enhancement's design, these resources are created or
// removed **solely** based on the value of spec.trustManagerConfig.approverPolicy.enabled --
// there is no dependency on ApproverPolicyManager CR status, approver-policy Deployment
// availability, or approveSignerNames configuration.
func (r *Reconciler) reconcileApproverPolicyIntegration(trustManager *v1alpha1.TrustManager, resourceLabels, resourceAnnotations map[string]string) error {
	if trustManager.Spec.TrustManagerConfig.ApproverPolicy.Enabled != v1alpha1.ApproverPolicyWebhookEnabled {
		return r.deleteApproverPolicyIntegrationResources()
	}

	if err := r.createOrApplyCertificateRequestPolicy(trustManager, resourceLabels, resourceAnnotations); err != nil {
		return err
	}
	if err := r.createOrApplyPolicyClusterRole(trustManager, resourceLabels, resourceAnnotations); err != nil {
		return err
	}
	if err := r.createOrApplyPolicyClusterRoleBinding(trustManager, resourceLabels, resourceAnnotations); err != nil {
		return err
	}
	return nil
}

// CertificateRequestPolicy

func (r *Reconciler) createOrApplyCertificateRequestPolicy(trustManager *v1alpha1.TrustManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getCertificateRequestPolicyObject(resourceLabels, resourceAnnotations)
	resourceName := desired.GetName()
	r.log.V(4).Info("reconciling certificaterequestpolicy resource", "name", resourceName)

	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(certificateRequestPolicyGVK)
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if certificaterequestpolicy %q exists", resourceName)
	}
	if exists && !certificateRequestPolicyModified(desired, existing) {
		r.log.V(4).Info("certificaterequestpolicy resource exists and is in desired state", "name", resourceName)
		return nil
	}

	r.log.V(2).Info("certificaterequestpolicy resource has been modified, updating to desired state", "name", resourceName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply certificaterequestpolicy %q", resourceName)
	}

	r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled", "certificaterequestpolicy resource %s applied", resourceName)
	return nil
}

// getCertificateRequestPolicyObject decodes the CertificateRequestPolicy bindata manifest
// into an *unstructured.Unstructured. The upstream approver-policy CertificateRequestPolicy
// type (policy.cert-manager.io/v1alpha1) is not vendored as a Go type in this repository;
// its CRD is installed by the operator's OLM bundle at runtime.
func getCertificateRequestPolicyObject(resourceLabels, resourceAnnotations map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(assets.MustAsset(certificateRequestPolicyAssetName), &obj.Object); err != nil {
		panic(fmt.Sprintf("failed to decode certificaterequestpolicy asset: %v", err))
	}
	obj.SetGroupVersionKind(certificateRequestPolicyGVK)
	obj.SetName(trustManagerPolicyName)
	common.UpdateResourceLabels(obj, resourceLabels)
	updateResourceAnnotations(obj, resourceAnnotations)
	return obj
}

// certificateRequestPolicyModified compares only the fields we manage via SSA: the
// managed metadata and the .spec content decoded from bindata (allowed/selector rules,
// which this controller never customizes at runtime).
func certificateRequestPolicyModified(desired, existing *unstructured.Unstructured) bool {
	if managedMetadataModified(desired, existing) {
		return true
	}
	desiredSpec, _, _ := unstructured.NestedMap(desired.Object, "spec")
	existingSpec, _, _ := unstructured.NestedMap(existing.Object, "spec")
	return !unstructuredSpecsEqual(desiredSpec, existingSpec)
}

// ClusterRole

func (r *Reconciler) createOrApplyPolicyClusterRole(trustManager *v1alpha1.TrustManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getPolicyClusterRoleObject(resourceLabels, resourceAnnotations)
	resourceName := desired.GetName()
	r.log.V(4).Info("reconciling clusterrole resource for approver-policy integration", "name", resourceName)

	existing := &rbacv1.ClusterRole{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if clusterrole %q exists", resourceName)
	}
	if exists && !clusterRoleModified(desired, existing) {
		r.log.V(4).Info("clusterrole resource exists and is in desired state", "name", resourceName)
		return nil
	}

	r.log.V(2).Info("clusterrole resource has been modified, updating to desired state", "name", resourceName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply clusterrole %q", resourceName)
	}

	r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled", "clusterrole resource %s applied", resourceName)
	return nil
}

func getPolicyClusterRoleObject(resourceLabels, resourceAnnotations map[string]string) *rbacv1.ClusterRole {
	clusterRole := common.DecodeObjBytes[*rbacv1.ClusterRole](codecs, rbacv1.SchemeGroupVersion, assets.MustAsset(policyClusterRoleAssetName))
	common.UpdateName(clusterRole, trustManagerPolicyRoleName)
	common.UpdateResourceLabels(clusterRole, resourceLabels)
	updateResourceAnnotations(clusterRole, resourceAnnotations)
	return clusterRole
}

// ClusterRoleBinding

func (r *Reconciler) createOrApplyPolicyClusterRoleBinding(trustManager *v1alpha1.TrustManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getPolicyClusterRoleBindingObject(resourceLabels, resourceAnnotations)
	resourceName := desired.GetName()
	r.log.V(4).Info("reconciling clusterrolebinding resource for approver-policy integration", "name", resourceName)

	existing := &rbacv1.ClusterRoleBinding{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if clusterrolebinding %q exists", resourceName)
	}
	if exists && !clusterRoleBindingModified(desired, existing) {
		r.log.V(4).Info("clusterrolebinding resource exists and is in desired state", "name", resourceName)
		return nil
	}

	r.log.V(2).Info("clusterrolebinding resource has been modified, updating to desired state", "name", resourceName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply clusterrolebinding %q", resourceName)
	}

	r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled", "clusterrolebinding resource %s applied", resourceName)
	return nil
}

func getPolicyClusterRoleBindingObject(resourceLabels, resourceAnnotations map[string]string) *rbacv1.ClusterRoleBinding {
	clusterRoleBinding := common.DecodeObjBytes[*rbacv1.ClusterRoleBinding](codecs, rbacv1.SchemeGroupVersion, assets.MustAsset(policyClusterRoleBindingAssetName))
	common.UpdateName(clusterRoleBinding, trustManagerPolicyBindingName)
	common.UpdateResourceLabels(clusterRoleBinding, resourceLabels)
	updateResourceAnnotations(clusterRoleBinding, resourceAnnotations)
	clusterRoleBinding.RoleRef.Name = trustManagerPolicyRoleName
	// The subject is always the hardcoded cert-manager ServiceAccount/namespace (see
	// constants.go), never trust-manager's own ServiceAccount: it is cert-manager's
	// controller that creates the CertificateRequest needing approver-policy's approval.
	updateBindingSubjects(clusterRoleBinding.Subjects, certManagerServiceAccountName, certManagerOperandNamespace)
	return clusterRoleBinding
}

// deleteApproverPolicyIntegrationResources deletes the CertificateRequestPolicy, ClusterRole,
// and ClusterRoleBinding created for the approver-policy integration. Called whenever
// spec.trustManagerConfig.approverPolicy.enabled is (or becomes) Disabled -- including the
// default state, so that flipping Enabled -> Disabled converges the cluster to having none
// of these resources. Deletions are best-effort idempotent: NotFound errors are ignored.
func (r *Reconciler) deleteApproverPolicyIntegrationResources() error {
	var errs []error

	if err := r.deletePolicyObject(); err != nil {
		errs = append(errs, err)
	}
	if err := r.deleteObject(&rbacv1.ClusterRoleBinding{}, client.ObjectKey{Name: trustManagerPolicyBindingName}); err != nil {
		errs = append(errs, err)
	}
	if err := r.deleteObject(&rbacv1.ClusterRole{}, client.ObjectKey{Name: trustManagerPolicyRoleName}); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return common.NewRetryRequiredError(joinErrors(errs), "failed to delete one or more approver-policy integration resources")
	}
	return nil
}

func (r *Reconciler) deletePolicyObject() error {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(certificateRequestPolicyGVK)
	obj.SetName(trustManagerPolicyName)
	if err := r.Delete(r.ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete certificaterequestpolicy %q: %w", trustManagerPolicyName, err)
	}
	return nil
}

// deleteObject deletes a typed object by name (cluster-scoped), ignoring NotFound errors.
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
	return fmt.Errorf("%s", msg)
}

// unstructuredSpecsEqual compares two decoded .spec maps for equality using a simple
// deep-equal semantic appropriate for the fixed, operator-managed CertificateRequestPolicy
// content (no runtime-managed subfields exist within .spec for this resource).
func unstructuredSpecsEqual(a, b map[string]interface{}) bool {
	aBytes, errA := yaml.Marshal(a)
	bBytes, errB := yaml.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(aBytes) == string(bBytes)
}
