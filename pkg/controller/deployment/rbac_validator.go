package deployment

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// RBACValidator validates that operator permissions are sufficient for resources it creates
type RBACValidator struct {
	operatorRules []rbacv1.PolicyRule
	createdRoles  []rbacv1.Role
}

// NewRBACValidator creates a new RBAC validator
func NewRBACValidator(operatorRules []rbacv1.PolicyRule) *RBACValidator {
	return &RBACValidator{
		operatorRules: operatorRules,
	}
}

// ValidateRoleCreation checks if operator can create the given role without privilege escalation
func (v *RBACValidator) ValidateRoleCreation(role rbacv1.Role) error {
	for _, rule := range role.Rules {
		if !v.operatorCanGrant(rule) {
			return fmt.Errorf("operator cannot create role %s: missing permissions for %v",
				role.Name, formatPolicyRule(rule))
		}
	}
	return nil
}

// operatorCanGrant checks if operator has sufficient permissions to grant a policy rule
func (v *RBACValidator) operatorCanGrant(rule rbacv1.PolicyRule) bool {
	for _, opRule := range v.operatorRules {
		if v.ruleCovers(opRule, rule) {
			return true
		}
	}
	return false
}

// ruleCovers checks if the operator rule covers the required rule
func (v *RBACValidator) ruleCovers(opRule, reqRule rbacv1.PolicyRule) bool {
	// Check API groups
	if !v.sliceContains(opRule.APIGroups, reqRule.APIGroups) {
		return false
	}

	// Check resources
	if !v.sliceContains(opRule.Resources, reqRule.Resources) {
		return false
	}

	// Check verbs
	if !v.sliceContains(opRule.Verbs, reqRule.Verbs) {
		return false
	}

	// Check resource names if specified
	if len(reqRule.ResourceNames) > 0 && len(opRule.ResourceNames) > 0 {
		if !v.sliceContains(opRule.ResourceNames, reqRule.ResourceNames) {
			return false
		}
	}

	return true
}

// sliceContains checks if all items in required are present in available
func (v *RBACValidator) sliceContains(available, required []string) bool {
	for _, req := range required {
		found := false
		for _, avail := range available {
			if avail == "*" || avail == req {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// formatPolicyRule formats a policy rule for error messages
func formatPolicyRule(rule rbacv1.PolicyRule) string {
	return fmt.Sprintf("APIGroups:%v Resources:%v Verbs:%v",
		rule.APIGroups, rule.Resources, rule.Verbs)
}

// ValidateAllRoles validates all roles that the operator will create
func (v *RBACValidator) ValidateAllRoles(roles []rbacv1.Role) []error {
	var errors []error
	for _, role := range roles {
		if err := v.ValidateRoleCreation(role); err != nil {
			errors = append(errors, err)
		}
	}
	return errors
}

// GetMissingPermissions returns the permissions the operator needs to create a role
func (v *RBACValidator) GetMissingPermissions(role rbacv1.Role) []rbacv1.PolicyRule {
	var missing []rbacv1.PolicyRule

	for _, rule := range role.Rules {
		if !v.operatorCanGrant(rule) {
			missing = append(missing, rule)
		}
	}

	return missing
}

// SuggestKubebuilderAnnotation suggests the kubebuilder annotation needed for missing permissions
func (v *RBACValidator) SuggestKubebuilderAnnotation(missingRules []rbacv1.PolicyRule) []string {
	var suggestions []string

	for _, rule := range missingRules {
		apiGroups := strings.Join(rule.APIGroups, ";")
		if apiGroups == "" {
			apiGroups = `""`
		}

		resources := strings.Join(rule.Resources, ";")
		verbs := strings.Join(rule.Verbs, ";")

		suggestion := fmt.Sprintf("//+kubebuilder:rbac:groups=%s,resources=%s,verbs=%s",
			apiGroups, resources, verbs)

		if len(rule.ResourceNames) > 0 {
			resourceNames := strings.Join(rule.ResourceNames, ";")
			suggestion += fmt.Sprintf(",resourceNames=%s", resourceNames)
		}

		suggestions = append(suggestions, suggestion)
	}

	return suggestions
}
