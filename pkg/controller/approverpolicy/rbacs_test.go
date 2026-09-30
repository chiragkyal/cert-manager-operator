package approverpolicy

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestApplySignerNamesRule(t *testing.T) {
	tests := []struct {
		name               string
		approveSignerNames []string
		wantResourceNames  []string
	}{
		{
			name:               "empty signer names removes resourceNames restriction",
			approveSignerNames: nil,
			wantResourceNames:  nil,
		},
		{
			name:               "single signer name",
			approveSignerNames: []string{"issuers.cert-manager.io/*"},
			wantResourceNames:  []string{"issuers.cert-manager.io/*"},
		},
		{
			name:               "multiple signer names are sorted",
			approveSignerNames: []string{"zzz.example.com/*", "aaa.example.com/*"},
			wantResourceNames:  []string{"aaa.example.com/*", "zzz.example.com/*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clusterRole := getClusterRoleObject(tt.approveSignerNames, testResourceLabels(), testResourceAnnotations())

			var rule *rbacv1.PolicyRule
			for i := range clusterRole.Rules {
				if isSignersApproveRule(&clusterRole.Rules[i]) {
					rule = &clusterRole.Rules[i]
					break
				}
			}
			if rule == nil {
				t.Fatalf("expected to find a signers approve rule in the ClusterRole manifest")
			}
			if len(rule.ResourceNames) != len(tt.wantResourceNames) {
				t.Fatalf("expected resourceNames %v, got %v", tt.wantResourceNames, rule.ResourceNames)
			}
			for i, want := range tt.wantResourceNames {
				if rule.ResourceNames[i] != want {
					t.Errorf("expected resourceNames[%d]=%q, got %q", i, want, rule.ResourceNames[i])
				}
			}
		})
	}
}

func TestIsSignersApproveRule(t *testing.T) {
	tests := []struct {
		name string
		rule rbacv1.PolicyRule
		want bool
	}{
		{
			name: "matches",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"signers"},
				Verbs:     []string{"approve"},
			},
			want: true,
		},
		{
			name: "wrong verb",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"signers"},
				Verbs:     []string{"get"},
			},
			want: false,
		},
		{
			name: "wrong resource",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
				Verbs:     []string{"approve"},
			},
			want: false,
		},
		{
			name: "wrong group",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"policy.cert-manager.io"},
				Resources: []string{"signers"},
				Verbs:     []string{"approve"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSignersApproveRule(&tt.rule); got != tt.want {
				t.Errorf("isSignersApproveRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClusterRoleReconciliation(t *testing.T) {
	tests := []struct {
		name            string
		apm             *approverPolicyManagerBuilder
		preReq          func(*fakes.FakeCtrlClient)
		wantErr         string
		wantExistsCount int
		wantPatchCount  int
	}{
		{
			name: "creates when not found",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
			},
			wantExistsCount: 1,
			wantPatchCount:  1,
		},
		{
			name: "no-op when rules match desired state",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					cr := getClusterRoleObject(nil, testResourceLabels(), testResourceAnnotations())
					cr.DeepCopyInto(obj.(*rbacv1.ClusterRole))
					return true, nil
				})
			},
			wantExistsCount: 1,
			wantPatchCount:  0,
		},
		{
			name: "applies when approveSignerNames changed",
			apm:  testApproverPolicyManager().WithApproveSignerNames([]string{"my-issuer.example.com/*"}),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					cr := getClusterRoleObject(nil, testResourceLabels(), testResourceAnnotations())
					cr.DeepCopyInto(obj.(*rbacv1.ClusterRole))
					return true, nil
				})
			},
			wantExistsCount: 1,
			wantPatchCount:  1,
		},
		{
			name: "exists error propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, errTestClient
				})
			},
			wantErr:         "failed to check if clusterrole",
			wantExistsCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testReconciler(t)
			mock := &fakes.FakeCtrlClient{}
			if tt.preReq != nil {
				tt.preReq(mock)
			}
			r.CtrlClient = mock

			apmBuilder := tt.apm
			if apmBuilder == nil {
				apmBuilder = testApproverPolicyManager()
			}
			apm := apmBuilder.Build()

			err := r.createOrApplyClusterRole(apm, getResourceLabels(apm), getResourceAnnotations(apm))
			assertError(t, err, tt.wantErr)

			if got := mock.ExistsCallCount(); got != tt.wantExistsCount {
				t.Errorf("expected %d Exists calls, got %d", tt.wantExistsCount, got)
			}
			if got := mock.PatchCallCount(); got != tt.wantPatchCount {
				t.Errorf("expected %d Patch calls, got %d", tt.wantPatchCount, got)
			}
		})
	}
}

func TestClusterRoleBindingObject(t *testing.T) {
	crb := getClusterRoleBindingObject(testResourceLabels(), testResourceAnnotations())

	if crb.RoleRef.Name != approverPolicyClusterRoleName {
		t.Errorf("expected roleRef name %q, got %q", approverPolicyClusterRoleName, crb.RoleRef.Name)
	}

	found := false
	for _, s := range crb.Subjects {
		if s.Kind == roleBindingSubjectKind && s.Name == approverPolicyServiceAccountName && s.Namespace == operandNamespace {
			found = true
		}
	}
	if !found {
		t.Errorf("expected subject referencing %s/%s, got %v", operandNamespace, approverPolicyServiceAccountName, crb.Subjects)
	}
}

func TestRoleBindingObject(t *testing.T) {
	rb := getRoleBindingObject(testResourceLabels(), testResourceAnnotations())

	if rb.RoleRef.Name != approverPolicyRoleName {
		t.Errorf("expected roleRef name %q, got %q", approverPolicyRoleName, rb.RoleRef.Name)
	}
	if rb.Namespace != operandNamespace {
		t.Errorf("expected namespace %q, got %q", operandNamespace, rb.Namespace)
	}
}

func TestUpdateBindingSubjects(t *testing.T) {
	subjects := []rbacv1.Subject{
		{Kind: roleBindingSubjectKind, Name: "placeholder", Namespace: "placeholder"},
		{Kind: "Group", Name: "should-not-change"},
	}
	updateBindingSubjects(subjects, "my-sa", "my-ns")

	if subjects[0].Name != "my-sa" || subjects[0].Namespace != "my-ns" {
		t.Errorf("expected ServiceAccount subject to be updated, got %+v", subjects[0])
	}
	if subjects[1].Name != "should-not-change" {
		t.Errorf("expected non-ServiceAccount subject to be left untouched, got %+v", subjects[1])
	}
}
