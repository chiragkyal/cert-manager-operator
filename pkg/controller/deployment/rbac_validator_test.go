package deployment

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRBACValidator_ValidateRoleCreation(t *testing.T) {
	tests := []struct {
		name          string
		operatorRules []rbacv1.PolicyRule
		roleToCreate  rbacv1.Role
		expectError   bool
		errorContains string
	}{
		{
			name: "should fail when operator lacks serviceaccounts/token permissions",
			operatorRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts", "configmaps"},
					Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
				},
			},
			roleToCreate: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"serviceaccounts/token"},
						ResourceNames: []string{"cert-manager"},
						Verbs:         []string{"create"},
					},
				},
			},
			expectError:   true,
			errorContains: "missing permissions for",
		},
		{
			name: "should pass when operator has serviceaccounts/token permissions",
			operatorRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts", "serviceaccounts/token", "configmaps"},
					Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
				},
			},
			roleToCreate: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups:     []string{""},
						Resources:     []string{"serviceaccounts/token"},
						ResourceNames: []string{"cert-manager"},
						Verbs:         []string{"create"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "should pass with minimal required permissions",
			operatorRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts/token"},
					Verbs:     []string{"create"},
				},
			},
			roleToCreate: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"serviceaccounts/token"},
						Verbs:     []string{"create"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "should fail when operator has wrong verb permissions",
			operatorRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts/token"},
					Verbs:     []string{"get", "list"}, // Missing "create"
				},
			},
			roleToCreate: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"serviceaccounts/token"},
						Verbs:     []string{"create"},
					},
				},
			},
			expectError:   true,
			errorContains: "missing permissions for",
		},
		{
			name: "should pass with wildcard permissions",
			operatorRules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			roleToCreate: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"serviceaccounts/token"},
						Verbs:     []string{"create"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRBACValidator(tt.operatorRules)
			err := validator.ValidateRoleCreation(tt.roleToCreate)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorContains != "" && !containsString(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestRBACValidator_WithActualManifests(t *testing.T) {
	// This test would catch the actual bug we fixed
	t.Run("cert-manager-tokenrequest role validation", func(t *testing.T) {
		// Simulate the operator ClusterRole BEFORE our fix
		operatorRulesBeforeFix := []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "events", "namespaces", "pods", "secrets", "serviceaccounts", "services"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
			// Note: missing serviceaccounts/token permission
		}

		// The actual cert-manager tokenrequest role
		certManagerTokenRequestRole := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts/token"},
					ResourceNames: []string{"cert-manager"},
					Verbs:         []string{"create"},
				},
			},
		}

		validator := NewRBACValidator(operatorRulesBeforeFix)
		err := validator.ValidateRoleCreation(certManagerTokenRequestRole)

		if err == nil {
			t.Error("Expected validation to fail for cert-manager-tokenrequest role without serviceaccounts/token permissions")
		} else {
			t.Logf("Correctly caught RBAC issue: %v", err)
		}
	})

	t.Run("cert-manager-tokenrequest role validation after fix", func(t *testing.T) {
		// Simulate the operator ClusterRole AFTER our fix
		operatorRulesAfterFix := []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "events", "namespaces", "pods", "secrets", "serviceaccounts", "services"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			},
		}

		// The actual cert-manager tokenrequest role
		certManagerTokenRequestRole := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-tokenrequest"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts/token"},
					ResourceNames: []string{"cert-manager"},
					Verbs:         []string{"create"},
				},
			},
		}

		validator := NewRBACValidator(operatorRulesAfterFix)
		err := validator.ValidateRoleCreation(certManagerTokenRequestRole)

		if err != nil {
			t.Errorf("Expected validation to pass after fix, but got: %v", err)
		}
	})
}

func TestRBACValidator_GetMissingPermissions(t *testing.T) {
	operatorRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list"},
		},
	}

	roleToCreate := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			},
		},
	}

	validator := NewRBACValidator(operatorRules)
	missing := validator.GetMissingPermissions(roleToCreate)

	if len(missing) != 1 {
		t.Errorf("expected 1 missing permission, got %d", len(missing))
	}

	if len(missing) > 0 {
		rule := missing[0]
		if len(rule.Resources) != 1 || rule.Resources[0] != "serviceaccounts/token" {
			t.Errorf("expected missing serviceaccounts/token permission, got %v", rule.Resources)
		}
	}
}

func TestRBACValidator_SuggestKubebuilderAnnotation(t *testing.T) {
	missingRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		},
	}

	validator := NewRBACValidator(nil)
	suggestions := validator.SuggestKubebuilderAnnotation(missingRules)

	if len(suggestions) != 1 {
		t.Errorf("expected 1 suggestion, got %d", len(suggestions))
	}

	expected := `//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create`
	if len(suggestions) > 0 && suggestions[0] != expected {
		t.Errorf("expected suggestion %q, got %q", expected, suggestions[0])
	}
}

func TestRBACValidator_Integration(t *testing.T) {
	// This test demonstrates the complete workflow
	t.Run("complete RBAC validation workflow", func(t *testing.T) {
		// 1. Load operator's current permissions
		operatorRules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "secrets"},
				Verbs:     []string{"get", "list", "create"},
			},
		}

		// 2. Define role that operator wants to create
		roleToCreate := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "example-role"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts/token"},
					Verbs:     []string{"create"},
				},
			},
		}

		validator := NewRBACValidator(operatorRules)

		// 3. Validate permissions
		err := validator.ValidateRoleCreation(roleToCreate)
		if err == nil {
			t.Error("Expected validation to fail")
			return
		}

		// 4. Get missing permissions
		missing := validator.GetMissingPermissions(roleToCreate)
		if len(missing) == 0 {
			t.Error("Expected missing permissions")
			return
		}

		// 5. Get suggestions for kubebuilder annotations
		suggestions := validator.SuggestKubebuilderAnnotation(missing)
		if len(suggestions) == 0 {
			t.Error("Expected kubebuilder annotation suggestions")
			return
		}

		t.Logf("Validation failed as expected: %v", err)
		t.Logf("Missing permissions: %v", missing)
		t.Logf("Suggested kubebuilder annotation: %v", suggestions)

		// This demonstrates what a developer would need to do:
		// 1. Add the suggested annotation to their controller
		// 2. Run `make manifests` to regenerate ClusterRole
		// 3. Re-run validation - should pass
	})
}

// Helper function for string containment check
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(findInString(s, substr) >= 0))
}

func findInString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
