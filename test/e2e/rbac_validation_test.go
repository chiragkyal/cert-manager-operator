package e2e

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/openshift/cert-manager-operator/pkg/controller/deployment"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

func TestRBACValidation(t *testing.T) {
	ctx := context.Background()

	// Get the operator's current ClusterRole
	operatorRole, err := getOperatorClusterRole(ctx, t)
	if err != nil {
		t.Fatalf("failed to get operator ClusterRole: %v", err)
	}

	// Get all roles that the operator will create
	rolesToCreate, err := getAllRolesToCreate(t)
	if err != nil {
		t.Fatalf("failed to get roles to create: %v", err)
	}

	// Validate RBAC permissions
	validator := deployment.NewRBACValidator(operatorRole.Rules)
	errors := validator.ValidateAllRoles(rolesToCreate)

	if len(errors) > 0 {
		t.Errorf("RBAC validation failed with %d errors:", len(errors))
		for _, err := range errors {
			t.Errorf("  - %v", err)
		}
		t.Log("The operator lacks permissions to create required roles")
		t.Log("Add missing permissions to the operator's ClusterRole in config/rbac/role.yaml")

		// Provide actionable feedback
		for _, role := range rolesToCreate {
			missing := validator.GetMissingPermissions(role)
			if len(missing) > 0 {
				t.Logf("Missing permissions for role %s:", role.Name)
				suggestions := validator.SuggestKubebuilderAnnotation(missing)
				for _, suggestion := range suggestions {
					t.Logf("  Add: %s", suggestion)
				}
			}
		}
	}
}

func TestRBACValidationWithCluster(t *testing.T) {
	// This test runs against a real cluster with the operator deployed
	ctx := context.Background()

	// Skip if not running in cluster (check for KUBECONFIG or in-cluster config)
	if os.Getenv("KUBECONFIG") == "" && !fileExists("/var/run/secrets/kubernetes.io/serviceaccount/token") {
		t.Skip("Skipping cluster-based RBAC test - not running in cluster")
	}

	// Get Kubernetes client
	k8sClient, err := getKubernetesClient()
	if err != nil {
		t.Fatalf("failed to get Kubernetes client: %v", err)
	}

	// Get the actual operator ClusterRole from the cluster
	operatorRole, err := k8sClient.RbacV1().ClusterRoles().Get(ctx, "cert-manager-operator-manager-role", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get operator ClusterRole from cluster: %v", err)
	}

	// Load roles from manifests
	rolesToCreate, err := getAllRolesToCreate(t)
	if err != nil {
		t.Fatalf("failed to load roles: %v", err)
	}

	// Validate
	validator := deployment.NewRBACValidator(operatorRole.Rules)

	for _, role := range rolesToCreate {
		t.Run("validate_"+role.Name, func(t *testing.T) {
			err := validator.ValidateRoleCreation(role)
			if err != nil {
				t.Errorf("RBAC validation failed for role %s: %v", role.Name, err)

				// Provide helpful suggestions
				missing := validator.GetMissingPermissions(role)
				if len(missing) > 0 {
					suggestions := validator.SuggestKubebuilderAnnotation(missing)
					t.Log("Add these kubebuilder annotations to fix the issue:")
					for _, suggestion := range suggestions {
						t.Logf("  %s", suggestion)
					}
				}
			}
		})
	}
}

func TestRBACSecurityBestPractices(t *testing.T) {
	ctx := context.Background()

	// Get the operator's ClusterRole
	operatorRole, err := getOperatorClusterRole(ctx, t)
	if err != nil {
		t.Fatalf("failed to get operator ClusterRole: %v", err)
	}

	// Check for security anti-patterns
	t.Run("check_for_wildcard_permissions", func(t *testing.T) {
		for i, rule := range operatorRole.Rules {
			// Check for wildcard API groups
			for _, apiGroup := range rule.APIGroups {
				if apiGroup == "*" {
					t.Errorf("Rule %d has wildcard API group '*' - consider being more specific", i)
				}
			}

			// Check for wildcard resources
			for _, resource := range rule.Resources {
				if resource == "*" {
					t.Errorf("Rule %d has wildcard resource '*' - consider being more specific", i)
				}
			}

			// Check for wildcard verbs
			for _, verb := range rule.Verbs {
				if verb == "*" {
					t.Errorf("Rule %d has wildcard verb '*' - consider principle of least privilege", i)
				}
			}
		}
	})

	t.Run("check_for_excessive_permissions", func(t *testing.T) {
		dangerousPermissions := []string{
			"delete",
			"deletecollection",
			"escalate",
			"impersonate",
		}

		for i, rule := range operatorRole.Rules {
			for _, verb := range rule.Verbs {
				for _, dangerous := range dangerousPermissions {
					if verb == dangerous {
						t.Logf("Rule %d has potentially dangerous permission '%s' - verify this is needed", i, dangerous)
					}
				}
			}
		}
	})
}

func getOperatorClusterRole(ctx context.Context, t *testing.T) (*rbacv1.ClusterRole, error) {
	// Try to get from cluster first
	if isRunningInCluster() {
		k8sClient, err := getKubernetesClient()
		if err == nil {
			role, err := k8sClient.RbacV1().ClusterRoles().Get(ctx, "cert-manager-operator-manager-role", metav1.GetOptions{})
			if err == nil {
				return role, nil
			}
		}
	}

	// Fallback to loading from file
	return loadClusterRoleFromFile("../../config/rbac/role.yaml")
}

// Helper functions
func isRunningInCluster() bool {
	return os.Getenv("KUBECONFIG") != "" || fileExists("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func getKubernetesClient() (kubernetes.Interface, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}

	return kubernetes.NewForConfig(config)
}

func getAllRolesToCreate(t *testing.T) ([]rbacv1.Role, error) {
	var roles []rbacv1.Role

	// Load all role manifests from bindata
	roleFiles := []string{
		"cert-manager-deployment/controller/cert-manager-tokenrequest-role.yaml",
		"cert-manager-deployment/controller/cert-manager-leaderelection-role.yaml",
		"cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-role.yaml",
		"cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-role.yaml",
		"istio-csr/cert-manager-istio-csr-role.yaml",
		"istio-csr/cert-manager-istio-csr-leases-role.yaml",
	}

	for _, roleFile := range roleFiles {
		roleData, err := assets.Asset(roleFile)
		if err != nil {
			// Skip if file doesn't exist - not all roles may be present
			t.Logf("Skipping %s: %v", roleFile, err)
			continue
		}

		// Parse YAML to Role object
		role, err := parseRoleFromYAML(roleData)
		if err != nil {
			return nil, err
		}

		roles = append(roles, *role)
	}

	return roles, nil
}

func parseRoleFromYAML(data []byte) (*rbacv1.Role, error) {
	role := &rbacv1.Role{}
	err := yaml.Unmarshal(data, role)
	return role, err
}

func loadClusterRoleFromFile(path string) (*rbacv1.ClusterRole, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	clusterRole := &rbacv1.ClusterRole{}
	err = yaml.Unmarshal(data, clusterRole)
	return clusterRole, err
}

// Test that simulates the exact bug we encountered
func TestTokenRequestRoleBug(t *testing.T) {
	t.Run("simulate_original_bug", func(t *testing.T) {
		// This simulates the operator's permissions BEFORE the fix
		operatorRulesWithoutTokenPermission := []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "events", "namespaces", "pods", "secrets", "serviceaccounts", "services"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
		}

		// The problematic role that caused the bug
		tokenRequestRole := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cert-manager-tokenrequest",
				Namespace: "cert-manager",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts/token"},
					ResourceNames: []string{"cert-manager"},
					Verbs:         []string{"create"},
				},
			},
		}

		validator := deployment.NewRBACValidator(operatorRulesWithoutTokenPermission)

		// This should fail - demonstrating the bug
		err := validator.ValidateRoleCreation(tokenRequestRole)
		if err == nil {
			t.Error("Expected validation to fail for serviceaccounts/token permission bug")
		} else {
			t.Logf("Correctly detected RBAC bug: %v", err)
		}

		// Show what the fix should be
		missing := validator.GetMissingPermissions(tokenRequestRole)
		suggestions := validator.SuggestKubebuilderAnnotation(missing)

		t.Log("To fix this bug, add the following kubebuilder annotation:")
		for _, suggestion := range suggestions {
			t.Logf("  %s", suggestion)
		}
	})

	t.Run("verify_fix_works", func(t *testing.T) {
		// This simulates the operator's permissions AFTER the fix
		operatorRulesWithTokenPermission := []rbacv1.PolicyRule{
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
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
		}

		tokenRequestRole := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cert-manager-tokenrequest",
				Namespace: "cert-manager",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts/token"},
					ResourceNames: []string{"cert-manager"},
					Verbs:         []string{"create"},
				},
			},
		}

		validator := deployment.NewRBACValidator(operatorRulesWithTokenPermission)

		// This should pass now - demonstrating the fix
		err := validator.ValidateRoleCreation(tokenRequestRole)
		if err != nil {
			t.Errorf("Expected validation to pass after fix, but got: %v", err)
		} else {
			t.Log("Validation passed - fix is working correctly")
		}
	})
}
