package trustmanager

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestBuildClusterRoleRules_NoSecretTargets(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManager()

	// SecretTargets is nil
	rules := r.buildClusterRoleRules(trustManager)

	// Verify basic rules are present
	assertRuleExists(t, rules, "trust.cert-manager.io", "bundles", "get")
	assertRuleExists(t, rules, "", "configmaps", "create")
	assertRuleExists(t, rules, "", "namespaces", "get")
	assertRuleExists(t, rules, "", "events", "create")

	// Verify NO secret write rules (secrets not enabled)
	assertNoSecretWriteRule(t, rules)
}

func TestBuildClusterRoleRules_SecretTargetsEnabled(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManagerWithSecretTargets()

	rules := r.buildClusterRoleRules(trustManager)

	// Verify basic rules are present
	assertRuleExists(t, rules, "trust.cert-manager.io", "bundles", "get")

	// Verify secret read rule
	assertRuleExists(t, rules, "", "secrets", "get")

	// Verify secret write rule with resourceNames
	found := false
	for _, rule := range rules {
		if containsString(rule.Resources, "secrets") && containsString(rule.Verbs, "create") {
			if len(rule.ResourceNames) > 0 {
				found = true
				// Verify specific secrets
				if !containsString(rule.ResourceNames, "my-secret-1") {
					t.Error("expected my-secret-1 in ResourceNames")
				}
				if !containsString(rule.ResourceNames, "my-secret-2") {
					t.Error("expected my-secret-2 in ResourceNames")
				}
			}
		}
	}
	if !found {
		t.Error("expected secret write rule with specific ResourceNames")
	}
}

func TestBuildClusterRoleRules_SecretTargetsAll(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManagerWithSecretTargetsAll()

	rules := r.buildClusterRoleRules(trustManager)

	// Verify full secret access
	found := false
	for _, rule := range rules {
		if containsString(rule.Resources, "secrets") &&
			containsString(rule.Verbs, "create") &&
			containsString(rule.Verbs, "delete") &&
			len(rule.ResourceNames) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected full secret access rule (no ResourceNames restriction)")
	}
}

func TestBuildSecretRules_Disabled(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManager()

	rules := r.buildSecretRules(trustManager)

	// Should return no rules when disabled
	if len(rules) != 0 {
		t.Errorf("expected no secret rules when disabled, got %d", len(rules))
	}
}

func TestBuildSecretRules_EnabledWithList(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManagerWithSecretTargets()

	rules := r.buildSecretRules(trustManager)

	// Should have 2 rules: read all, write specific
	if len(rules) != 2 {
		t.Errorf("expected 2 secret rules, got %d", len(rules))
	}

	// First rule should be read access
	if !containsString(rules[0].Verbs, "get") || !containsString(rules[0].Verbs, "list") {
		t.Error("expected first rule to have read access")
	}
	if len(rules[0].ResourceNames) != 0 {
		t.Error("expected first rule to have no ResourceNames (read all)")
	}

	// Second rule should be write access with specific names
	if !containsString(rules[1].Verbs, "create") {
		t.Error("expected second rule to have write access")
	}
	if len(rules[1].ResourceNames) == 0 {
		t.Error("expected second rule to have ResourceNames")
	}
}

func TestBuildSecretRules_EnabledAll(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManagerWithSecretTargetsAll()

	rules := r.buildSecretRules(trustManager)

	// Should have 1 rule with full access
	if len(rules) != 1 {
		t.Errorf("expected 1 secret rule, got %d", len(rules))
	}

	// Should have full access verbs
	if !containsString(rules[0].Verbs, "get") ||
		!containsString(rules[0].Verbs, "create") ||
		!containsString(rules[0].Verbs, "delete") {
		t.Error("expected full access verbs")
	}

	// Should have no ResourceNames (access to all)
	if len(rules[0].ResourceNames) != 0 {
		t.Error("expected no ResourceNames for full access")
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func assertRuleExists(t *testing.T, rules []rbacv1.PolicyRule, apiGroup, resource, verb string) {
	t.Helper()
	for _, rule := range rules {
		if containsString(rule.APIGroups, apiGroup) &&
			containsString(rule.Resources, resource) &&
			containsString(rule.Verbs, verb) {
			return
		}
	}
	t.Errorf("rule not found: apiGroup=%q, resource=%q, verb=%q", apiGroup, resource, verb)
}

func assertNoSecretWriteRule(t *testing.T, rules []rbacv1.PolicyRule) {
	t.Helper()
	for _, rule := range rules {
		if containsString(rule.Resources, "secrets") &&
			(containsString(rule.Verbs, "create") || containsString(rule.Verbs, "patch") || containsString(rule.Verbs, "delete")) {
			t.Error("unexpected secret write rule found")
			return
		}
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
