package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// =============================================================================
// RBAC RECONCILIATION
// =============================================================================
// trust-manager requires several RBAC resources:
//
// Cluster-scoped:
// - ClusterRole: Permissions to manage Bundles, ConfigMaps, Secrets across cluster
// - ClusterRoleBinding: Binds ClusterRole to ServiceAccount
//
// Namespace-scoped (in cert-manager namespace):
// - Role (trust-manager): Read secrets in trust namespace
// - Role (trust-manager:leaderelection): Leader election
// - RoleBinding for each Role
//
// The ClusterRole rules are DYNAMIC based on secretTargets configuration:
// - If secretTargets.enabled=false: No secret write permissions
// - If secretTargets.authorizedSecretsAll=true: Full secret access
// - If secretTargets.authorizedSecrets=[list]: Write only to named secrets

// createOrApplyRBACResources reconciles all RBAC resources for trust-manager.
func (r *Reconciler) createOrApplyRBACResources(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	// 1. ClusterRole (with dynamic rules based on secretTargets)
	if err := r.createOrApplyClusterRole(trustManager, resourceLabels, isNewReconcile); err != nil {
		return err
	}

	// 2. ClusterRoleBinding
	if err := r.createOrApplyClusterRoleBinding(trustManager, resourceLabels, isNewReconcile); err != nil {
		return err
	}

	// 3. Role (trust-manager) - for reading secrets in trust namespace
	if err := r.createOrApplyRole(trustManager, resourceLabels, isNewReconcile, roleAssetName); err != nil {
		return err
	}

	// 4. Role (trust-manager:leaderelection) - for leader election
	if err := r.createOrApplyRole(trustManager, resourceLabels, isNewReconcile, roleLeaderElectionAssetName); err != nil {
		return err
	}

	// 5. RoleBinding (trust-manager)
	if err := r.createOrApplyRoleBinding(trustManager, resourceLabels, isNewReconcile, roleBindingAssetName); err != nil {
		return err
	}

	// 6. RoleBinding (trust-manager:leaderelection)
	if err := r.createOrApplyRoleBinding(trustManager, resourceLabels, isNewReconcile, roleBindingLeaderElectionAssetName); err != nil {
		return err
	}

	return nil
}

// =============================================================================
// CLUSTER ROLE
// =============================================================================

func (r *Reconciler) createOrApplyClusterRole(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	desired := r.getClusterRoleObject(trustManager, resourceLabels)
	crName := desired.GetName()

	r.log.V(4).Info("reconciling ClusterRole", "name", crName)

	fetched := &rbacv1.ClusterRole{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if ClusterRole %s exists", crName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"ClusterRole %s already exists", crName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("ClusterRole has changed, updating", "name", crName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update ClusterRole %s", crName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"ClusterRole %s updated", crName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create ClusterRole %s", crName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"ClusterRole %s created", crName)
	}

	// Update status
	if trustManager.Status.ClusterRole != crName {
		trustManager.Status.ClusterRole = crName
		if err := r.updateStatus(r.ctx, trustManager); err != nil {
			return FromClientError(err, "failed to update status with ClusterRole name")
		}
	}

	return nil
}

// getClusterRoleObject builds the ClusterRole with dynamic rules based on secretTargets.
func (r *Reconciler) getClusterRoleObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *rbacv1.ClusterRole {
	// Load base ClusterRole from bindata
	cr := decodeClusterRoleObjBytes(assets.MustAsset(clusterRoleAssetName))

	// Apply labels
	updateResourceLabels(cr, resourceLabels)

	// Build rules dynamically based on secretTargets configuration
	cr.Rules = r.buildClusterRoleRules(trustManager)

	return cr
}

// buildClusterRoleRules creates the ClusterRole rules based on secretTargets config.
func (r *Reconciler) buildClusterRoleRules(trustManager *v1alpha1.TrustManager) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		// Bundle management (always required)
		{
			APIGroups: []string{"trust.cert-manager.io"},
			Resources: []string{"bundles"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"trust.cert-manager.io"},
			Resources: []string{"bundles/finalizers"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"trust.cert-manager.io"},
			Resources: []string{"bundles/status"},
			Verbs:     []string{"patch"},
		},
		// Namespace access (to filter by namespace labels)
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// ConfigMap management (always required - primary target type)
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "create", "patch", "watch", "delete"},
		},
		// Events (for status reporting)
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
	}

	// Add secret rules based on secretTargets configuration
	secretRules := r.buildSecretRules(trustManager)
	rules = append(rules, secretRules...)

	return rules
}

// buildSecretRules creates the secret access rules based on secretTargets config.
func (r *Reconciler) buildSecretRules(trustManager *v1alpha1.TrustManager) []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule

	secretTargets := trustManager.Spec.TrustManagerConfig.SecretTargets
	if secretTargets == nil || !secretTargets.Enabled {
		// Secret targets disabled - no secret rules needed
		r.log.V(4).Info("secretTargets disabled, no secret rules added")
		return rules
	}

	// Secret targets enabled
	if secretTargets.AuthorizedSecretsAll {
		// Full access to ALL secrets (dangerous but sometimes needed)
		r.log.V(2).Info("secretTargets.authorizedSecretsAll=true, granting full secret access")
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch", "create", "patch", "delete"},
		})
	} else if len(secretTargets.AuthorizedSecrets) > 0 {
		// Restricted access - read all, write only to specific secrets
		r.log.V(2).Info("secretTargets with specific secrets", "count", len(secretTargets.AuthorizedSecrets))

		// Read access to all secrets (needed to check if secret exists)
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		})

		// Write access only to specified secrets
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"create", "patch", "delete"},
			ResourceNames: secretTargets.AuthorizedSecrets,
		})
	} else {
		// Enabled but no secrets specified - read-only access
		r.log.V(4).Info("secretTargets enabled but no secrets specified, read-only access")
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		})
	}

	return rules
}

// =============================================================================
// CLUSTER ROLE BINDING
// =============================================================================

func (r *Reconciler) createOrApplyClusterRoleBinding(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	desired := r.getClusterRoleBindingObject(trustManager, resourceLabels)
	crbName := desired.GetName()

	r.log.V(4).Info("reconciling ClusterRoleBinding", "name", crbName)

	fetched := &rbacv1.ClusterRoleBinding{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if ClusterRoleBinding %s exists", crbName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"ClusterRoleBinding %s already exists", crbName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("ClusterRoleBinding has changed, updating", "name", crbName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update ClusterRoleBinding %s", crbName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"ClusterRoleBinding %s updated", crbName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create ClusterRoleBinding %s", crbName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"ClusterRoleBinding %s created", crbName)
	}

	// Update status
	if trustManager.Status.ClusterRoleBinding != crbName {
		trustManager.Status.ClusterRoleBinding = crbName
		if err := r.updateStatus(r.ctx, trustManager); err != nil {
			return FromClientError(err, "failed to update status with ClusterRoleBinding name")
		}
	}

	return nil
}

func (r *Reconciler) getClusterRoleBindingObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *rbacv1.ClusterRoleBinding {
	crb := decodeClusterRoleBindingObjBytes(assets.MustAsset(clusterRoleBindingAssetName))

	// Apply labels
	updateResourceLabels(crb, resourceLabels)

	// Fix the subject namespace to cert-manager (where SA lives)
	for i := range crb.Subjects {
		if crb.Subjects[i].Kind == "ServiceAccount" {
			crb.Subjects[i].Namespace = operandNamespace
		}
	}

	return crb
}

// =============================================================================
// ROLE
// =============================================================================

func (r *Reconciler) createOrApplyRole(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
	assetName string,
) error {
	desired := r.getRoleObject(trustManager, resourceLabels, assetName)
	roleName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling Role", "name", roleName)

	fetched := &rbacv1.Role{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if Role %s exists", roleName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Role %s already exists", roleName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("Role has changed, updating", "name", roleName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update Role %s", roleName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Role %s updated", roleName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create Role %s", roleName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Role %s created", roleName)
	}

	return nil
}

func (r *Reconciler) getRoleObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	assetName string,
) *rbacv1.Role {
	role := decodeRoleObjBytes(assets.MustAsset(assetName))

	// Set namespace to cert-manager
	updateNamespace(role, operandNamespace)

	// Apply labels
	updateResourceLabels(role, resourceLabels)

	return role
}

// =============================================================================
// ROLE BINDING
// =============================================================================

func (r *Reconciler) createOrApplyRoleBinding(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
	assetName string,
) error {
	desired := r.getRoleBindingObject(trustManager, resourceLabels, assetName)
	rbName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling RoleBinding", "name", rbName)

	fetched := &rbacv1.RoleBinding{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if RoleBinding %s exists", rbName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"RoleBinding %s already exists", rbName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("RoleBinding has changed, updating", "name", rbName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update RoleBinding %s", rbName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"RoleBinding %s updated", rbName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create RoleBinding %s", rbName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"RoleBinding %s created", rbName)
	}

	return nil
}

func (r *Reconciler) getRoleBindingObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	assetName string,
) *rbacv1.RoleBinding {
	rb := decodeRoleBindingObjBytes(assets.MustAsset(assetName))

	// Set namespace to cert-manager
	updateNamespace(rb, operandNamespace)

	// Apply labels
	updateResourceLabels(rb, resourceLabels)

	// Fix the subject namespace to cert-manager (where SA lives)
	for i := range rb.Subjects {
		if rb.Subjects[i].Kind == "ServiceAccount" {
			rb.Subjects[i].Namespace = operandNamespace
		}
	}

	return rb
}

