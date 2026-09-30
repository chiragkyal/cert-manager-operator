package trustmanager

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestGetCertificateRequestPolicyObject(t *testing.T) {
	tests := []struct {
		name            string
		tm              *trustManagerBuilder
		wantName        string
		wantLabels      map[string]string
		wantAnnotations map[string]string
	}{
		{
			name:     "sets correct name",
			tm:       testTrustManager(),
			wantName: trustManagerPolicyName,
		},
		{
			name: "default labels take precedence over user labels",
			tm:   testTrustManager().WithLabels(map[string]string{"app": "should-be-overridden"}),
			wantLabels: map[string]string{
				"app": trustManagerCommonName,
			},
		},
		{
			name: "merges custom labels and annotations",
			tm: testTrustManager().
				WithLabels(map[string]string{"user-label": "test-value"}).
				WithAnnotations(map[string]string{"user-annotation": "test-value"}),
			wantLabels:      map[string]string{"user-label": "test-value"},
			wantAnnotations: map[string]string{"user-annotation": "test-value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := tt.tm.Build()
			obj := getCertificateRequestPolicyObject(getResourceLabels(tm), getResourceAnnotations(tm))

			if obj.GroupVersionKind() != certificateRequestPolicyGVK {
				t.Errorf("expected GVK %v, got %v", certificateRequestPolicyGVK, obj.GroupVersionKind())
			}
			if tt.wantName != "" && obj.GetName() != tt.wantName {
				t.Errorf("expected name %q, got %q", tt.wantName, obj.GetName())
			}
			for key, val := range tt.wantLabels {
				if obj.GetLabels()[key] != val {
					t.Errorf("expected label %s=%q, got %q", key, val, obj.GetLabels()[key])
				}
			}
			for key, val := range tt.wantAnnotations {
				if obj.GetAnnotations()[key] != val {
					t.Errorf("expected annotation %s=%q, got %q", key, val, obj.GetAnnotations()[key])
				}
			}

			// spec content decoded from bindata must be present and untouched.
			selector, found, err := unstructured.NestedString(obj.Object, "spec", "selector", "issuerRef", "name")
			if err != nil || !found {
				t.Fatalf("expected spec.selector.issuerRef.name to be set, err=%v found=%v", err, found)
			}
			if selector != trustManagerIssuerName {
				t.Errorf("expected spec.selector.issuerRef.name=%q, got %q", trustManagerIssuerName, selector)
			}
		})
	}
}

func TestCertificateRequestPolicyModified(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*unstructured.Unstructured)
		want   bool
	}{
		{
			name: "no changes",
			want: false,
		},
		{
			name: "label drift",
			mutate: func(u *unstructured.Unstructured) {
				labels := u.GetLabels()
				labels["app"] = "modified-value"
				u.SetLabels(labels)
			},
			want: true,
		},
		{
			name: "spec drift",
			mutate: func(u *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(u.Object, "tampered-common-name", "spec", "allowed", "commonName", "value")
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := getCertificateRequestPolicyObject(testResourceLabels(), testResourceAnnotations())
			existing := getCertificateRequestPolicyObject(testResourceLabels(), testResourceAnnotations())
			if tt.mutate != nil {
				tt.mutate(existing)
			}

			if got := certificateRequestPolicyModified(desired, existing); got != tt.want {
				t.Errorf("certificateRequestPolicyModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPolicyClusterRoleObject(t *testing.T) {
	clusterRole := getPolicyClusterRoleObject(testResourceLabels(), testResourceAnnotations())

	if clusterRole.Name != trustManagerPolicyRoleName {
		t.Errorf("expected name %q, got %q", trustManagerPolicyRoleName, clusterRole.Name)
	}
	if len(clusterRole.Rules) != 1 {
		t.Fatalf("expected exactly 1 rule, got %d", len(clusterRole.Rules))
	}
	rule := clusterRole.Rules[0]
	if rule.Verbs[0] != "use" {
		t.Errorf("expected verb %q, got %v", "use", rule.Verbs)
	}
	if len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != trustManagerPolicyName {
		t.Errorf("expected resourceNames [%q], got %v", trustManagerPolicyName, rule.ResourceNames)
	}
}

func TestGetPolicyClusterRoleBindingObject(t *testing.T) {
	binding := getPolicyClusterRoleBindingObject(testResourceLabels(), testResourceAnnotations())

	if binding.Name != trustManagerPolicyBindingName {
		t.Errorf("expected name %q, got %q", trustManagerPolicyBindingName, binding.Name)
	}
	if binding.RoleRef.Name != trustManagerPolicyRoleName {
		t.Errorf("expected roleRef name %q, got %q", trustManagerPolicyRoleName, binding.RoleRef.Name)
	}
	if len(binding.Subjects) != 1 {
		t.Fatalf("expected exactly 1 subject, got %d", len(binding.Subjects))
	}
	subject := binding.Subjects[0]
	// The subject must always be the hardcoded cert-manager SA, never trust-manager's own SA.
	if subject.Name != certManagerServiceAccountName {
		t.Errorf("expected subject name %q, got %q", certManagerServiceAccountName, subject.Name)
	}
	if subject.Namespace != certManagerOperandNamespace {
		t.Errorf("expected subject namespace %q, got %q", certManagerOperandNamespace, subject.Namespace)
	}
}

func TestReconcileApproverPolicyIntegration(t *testing.T) {
	tests := []struct {
		name            string
		tmBuilder       *trustManagerBuilder
		preReq          func(*fakes.FakeCtrlClient)
		wantErr         string
		wantExistsCount int
		wantPatchCount  int
		wantDeleteCount int
	}{
		{
			name:      "disabled is a no-op delete when nothing exists",
			tmBuilder: testTrustManager().WithApproverPolicy(v1alpha1.ApproverPolicyWebhookDisabled),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.DeleteReturns(apierrors.NewNotFound(schema.GroupResource{}, "test"))
			},
			wantExistsCount: 0,
			wantPatchCount:  0,
			wantDeleteCount: 3,
		},
		{
			name:      "default (empty) is treated as disabled",
			tmBuilder: testTrustManager(),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.DeleteReturns(apierrors.NewNotFound(schema.GroupResource{}, "test"))
			},
			wantExistsCount: 0,
			wantPatchCount:  0,
			wantDeleteCount: 3,
		},
		{
			name:      "enabled creates all three resources when not found",
			tmBuilder: testTrustManager().WithApproverPolicy(v1alpha1.ApproverPolicyWebhookEnabled),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
			},
			wantExistsCount: 3,
			wantPatchCount:  3,
			wantDeleteCount: 0,
		},
		{
			name:      "enabled skips apply when everything matches desired",
			tmBuilder: testTrustManager().WithApproverPolicy(v1alpha1.ApproverPolicyWebhookEnabled),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					switch o := obj.(type) {
					case *unstructured.Unstructured:
						getCertificateRequestPolicyObject(testResourceLabels(), testResourceAnnotations()).DeepCopyInto(o)
					case *rbacv1.ClusterRole:
						getPolicyClusterRoleObject(testResourceLabels(), testResourceAnnotations()).DeepCopyInto(o)
					case *rbacv1.ClusterRoleBinding:
						getPolicyClusterRoleBindingObject(testResourceLabels(), testResourceAnnotations()).DeepCopyInto(o)
					}
					return true, nil
				})
			},
			wantExistsCount: 3,
			wantPatchCount:  0,
			wantDeleteCount: 0,
		},
		{
			name:      "enabled propagates certificaterequestpolicy exists error",
			tmBuilder: testTrustManager().WithApproverPolicy(v1alpha1.ApproverPolicyWebhookEnabled),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, errTestClient
				})
			},
			wantErr:         "failed to check if certificaterequestpolicy",
			wantExistsCount: 1,
			wantPatchCount:  0,
			wantDeleteCount: 0,
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

			tm := tt.tmBuilder.Build()
			err := r.reconcileApproverPolicyIntegration(tm, getResourceLabels(tm), getResourceAnnotations(tm))
			assertError(t, err, tt.wantErr)

			if got := mock.ExistsCallCount(); got != tt.wantExistsCount {
				t.Errorf("expected %d Exists calls, got %d", tt.wantExistsCount, got)
			}
			if got := mock.PatchCallCount(); got != tt.wantPatchCount {
				t.Errorf("expected %d Patch calls, got %d", tt.wantPatchCount, got)
			}
			if got := mock.DeleteCallCount(); got != tt.wantDeleteCount {
				t.Errorf("expected %d Delete calls, got %d", tt.wantDeleteCount, got)
			}
		})
	}
}
