package approverpolicy

import (
	"fmt"
	"reflect"
	"slices"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// signersAPIGroup and signersResource identify the RBAC rule in the ClusterRole that grants
// the "approve" verb on cert-manager's "signers" resource. This is the rule that Story 7
// dynamically restricts to a specific set of signer names via approveSignerNames.
const (
	signersAPIGroup = "cert-manager.io"
	signersResource = "signers"
	signersVerb     = "approve"
)

func (r *Reconciler) createOrApplyRBACResources(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	if err := r.createOrApplyClusterRole(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile clusterrole resource")
		return err
	}

	if err := r.createOrApplyClusterRoleBinding(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile clusterrolebinding resource")
		return err
	}

	if err := r.createOrApplyRole(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile role resource")
		return err
	}

	if err := r.createOrApplyRoleBinding(apm, resourceLabels, resourceAnnotations); err != nil {
		r.log.Error(err, "failed to reconcile rolebinding resource")
		return err
	}

	return nil
}

// ClusterRole

func (r *Reconciler) createOrApplyClusterRole(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getClusterRoleObject(apm.Spec.ApproverPolicyConfig.ApproveSignerNames, resourceLabels, resourceAnnotations)
	resourceName := desired.GetName()
	r.log.V(4).Info("reconciling clusterrole resource", "name", resourceName)

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

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "clusterrole resource %s applied", resourceName)
	return nil
}

func getClusterRoleObject(approveSignerNames []string, resourceLabels, resourceAnnotations map[string]string) *rbacv1.ClusterRole {
	clusterRole := common.DecodeObjBytes[*rbacv1.ClusterRole](codecs, rbacv1.SchemeGroupVersion, assets.MustAsset(clusterRoleAssetName))
	common.UpdateName(clusterRole, approverPolicyClusterRoleName)
	common.UpdateResourceLabels(clusterRole, resourceLabels)
	updateResourceAnnotations(clusterRole, resourceAnnotations)
	applySignerNamesRule(clusterRole, approveSignerNames)
	return clusterRole
}

// applySignerNamesRule dynamically configures the ClusterRole's "approve" on "signers" rule
// based on approveSignerNames (Story 7 -- RBAC Configuration):
//   - Default (approveSignerNames empty): no resourceNames restriction -- approve all signers.
//   - approveSignerNames specified: resourceNames restricted to exactly the listed entries.
//
// The signer names are sorted to produce a deterministic rule for stable diffing against the
// existing cluster state.
func applySignerNamesRule(clusterRole *rbacv1.ClusterRole, approveSignerNames []string) {
	for i := range clusterRole.Rules {
		rule := &clusterRole.Rules[i]
		if !isSignersApproveRule(rule) {
			continue
		}

		if len(approveSignerNames) == 0 {
			rule.ResourceNames = nil
			return
		}

		sortedNames := slices.Clone(approveSignerNames)
		slices.Sort(sortedNames)
		rule.ResourceNames = sortedNames
		return
	}
}

// isSignersApproveRule identifies the PolicyRule granting "approve" on the "signers" resource
// in the "cert-manager.io" API group -- the rule that Story 7 dynamically scopes.
func isSignersApproveRule(rule *rbacv1.PolicyRule) bool {
	return slices.Contains(rule.APIGroups, signersAPIGroup) &&
		slices.Contains(rule.Resources, signersResource) &&
		slices.Contains(rule.Verbs, signersVerb)
}

// ClusterRoleBinding

func (r *Reconciler) createOrApplyClusterRoleBinding(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getClusterRoleBindingObject(resourceLabels, resourceAnnotations)
	resourceName := desired.GetName()
	r.log.V(4).Info("reconciling clusterrolebinding resource", "name", resourceName)

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

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "clusterrolebinding resource %s applied", resourceName)
	return nil
}

func getClusterRoleBindingObject(resourceLabels, resourceAnnotations map[string]string) *rbacv1.ClusterRoleBinding {
	clusterRoleBinding := common.DecodeObjBytes[*rbacv1.ClusterRoleBinding](codecs, rbacv1.SchemeGroupVersion, assets.MustAsset(clusterRoleBindingAssetName))
	common.UpdateName(clusterRoleBinding, approverPolicyClusterRoleBindingName)
	common.UpdateResourceLabels(clusterRoleBinding, resourceLabels)
	updateResourceAnnotations(clusterRoleBinding, resourceAnnotations)
	clusterRoleBinding.RoleRef.Name = approverPolicyClusterRoleName
	updateBindingSubjects(clusterRoleBinding.Subjects, approverPolicyServiceAccountName, operandNamespace)
	return clusterRoleBinding
}

// Role (leader election + webhook TLS secret access, in the operand namespace)

func (r *Reconciler) createOrApplyRole(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getRoleObject(resourceLabels, resourceAnnotations)
	resourceName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())
	r.log.V(4).Info("reconciling role resource", "name", resourceName)

	existing := &rbacv1.Role{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if role %q exists", resourceName)
	}
	if exists && !roleModified(desired, existing) {
		r.log.V(4).Info("role resource exists and is in desired state", "name", resourceName)
		return nil
	}

	r.log.V(2).Info("role resource has been modified, updating to desired state", "name", resourceName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply role %q", resourceName)
	}

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "role resource %s applied", resourceName)
	return nil
}

func getRoleObject(resourceLabels, resourceAnnotations map[string]string) *rbacv1.Role {
	role := common.DecodeObjBytes[*rbacv1.Role](codecs, rbacv1.SchemeGroupVersion, assets.MustAsset(roleAssetName))
	common.UpdateName(role, approverPolicyRoleName)
	common.UpdateNamespace(role, operandNamespace)
	common.UpdateResourceLabels(role, resourceLabels)
	updateResourceAnnotations(role, resourceAnnotations)
	return role
}

// RoleBinding (in the operand namespace)

func (r *Reconciler) createOrApplyRoleBinding(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired := getRoleBindingObject(resourceLabels, resourceAnnotations)
	resourceName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())
	r.log.V(4).Info("reconciling rolebinding resource", "name", resourceName)

	existing := &rbacv1.RoleBinding{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if rolebinding %q exists", resourceName)
	}
	if exists && !roleBindingModified(desired, existing) {
		r.log.V(4).Info("rolebinding resource exists and is in desired state", "name", resourceName)
		return nil
	}

	r.log.V(2).Info("rolebinding resource has been modified, updating to desired state", "name", resourceName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply rolebinding %q", resourceName)
	}

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "rolebinding resource %s applied", resourceName)
	return nil
}

func getRoleBindingObject(resourceLabels, resourceAnnotations map[string]string) *rbacv1.RoleBinding {
	roleBinding := common.DecodeObjBytes[*rbacv1.RoleBinding](codecs, rbacv1.SchemeGroupVersion, assets.MustAsset(roleBindingAssetName))
	common.UpdateName(roleBinding, approverPolicyRoleBindingName)
	common.UpdateNamespace(roleBinding, operandNamespace)
	common.UpdateResourceLabels(roleBinding, resourceLabels)
	updateResourceAnnotations(roleBinding, resourceAnnotations)
	roleBinding.RoleRef.Name = approverPolicyRoleName
	updateBindingSubjects(roleBinding.Subjects, approverPolicyServiceAccountName, operandNamespace)
	return roleBinding
}

// updateBindingSubjects sets the ServiceAccount name and namespace on RBAC binding subjects.
func updateBindingSubjects(subjects []rbacv1.Subject, serviceAccountName, namespace string) {
	for i := range subjects {
		if subjects[i].Kind == roleBindingSubjectKind {
			subjects[i].Name = serviceAccountName
			subjects[i].Namespace = namespace
		}
	}
}

// clusterRoleModified compares only the fields we manage via SSA.
func clusterRoleModified(desired, existing *rbacv1.ClusterRole) bool {
	return managedMetadataModified(desired, existing) ||
		!reflect.DeepEqual(desired.Rules, existing.Rules)
}

// clusterRoleBindingModified compares only the fields we manage via SSA.
func clusterRoleBindingModified(desired, existing *rbacv1.ClusterRoleBinding) bool {
	return managedMetadataModified(desired, existing) ||
		!reflect.DeepEqual(desired.RoleRef, existing.RoleRef) ||
		!reflect.DeepEqual(desired.Subjects, existing.Subjects)
}

// roleModified compares only the fields we manage via SSA.
func roleModified(desired, existing *rbacv1.Role) bool {
	return managedMetadataModified(desired, existing) ||
		!reflect.DeepEqual(desired.Rules, existing.Rules)
}

// roleBindingModified compares only the fields we manage via SSA.
func roleBindingModified(desired, existing *rbacv1.RoleBinding) bool {
	return managedMetadataModified(desired, existing) ||
		!reflect.DeepEqual(desired.RoleRef, existing.RoleRef) ||
		!reflect.DeepEqual(desired.Subjects, existing.Subjects)
}
