package approverpolicy

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestGetWebhookTLSSecretObject(t *testing.T) {
	tests := []struct {
		name            string
		apm             *approverPolicyManagerBuilder
		wantName        string
		wantNamespace   string
		wantLabels      map[string]string
		wantAnnotations map[string]string
	}{
		{
			name:          "sets correct name and namespace",
			apm:           testApproverPolicyManager(),
			wantName:      webhookTLSSecretName,
			wantNamespace: operandNamespace,
		},
		{
			name: "default labels take precedence over user labels",
			apm:  testApproverPolicyManager().WithLabels(map[string]string{"app": "should-be-overridden"}),
			wantLabels: map[string]string{
				"app": approverPolicyCommonName,
			},
		},
		{
			name: "merges custom labels and annotations",
			apm: testApproverPolicyManager().
				WithLabels(map[string]string{"user-label": "test-value"}).
				WithAnnotations(map[string]string{"user-annotation": "test-value"}),
			wantLabels:      map[string]string{"user-label": "test-value"},
			wantAnnotations: map[string]string{"user-annotation": "test-value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apm := tt.apm.Build()
			secret := getWebhookTLSSecretObject(getResourceLabels(apm), getResourceAnnotations(apm))

			if tt.wantName != "" && secret.Name != tt.wantName {
				t.Errorf("expected name %q, got %q", tt.wantName, secret.Name)
			}
			if tt.wantNamespace != "" && secret.Namespace != tt.wantNamespace {
				t.Errorf("expected namespace %q, got %q", tt.wantNamespace, secret.Namespace)
			}
			for key, val := range tt.wantLabels {
				if secret.Labels[key] != val {
					t.Errorf("expected label %s=%q, got %q", key, val, secret.Labels[key])
				}
			}
			for key, val := range tt.wantAnnotations {
				if secret.Annotations[key] != val {
					t.Errorf("expected annotation %s=%q, got %q", key, val, secret.Annotations[key])
				}
			}
		})
	}
}

func TestSecretModified(t *testing.T) {
	tests := []struct {
		name       string
		annotedApm bool
		mutate     func(*corev1.Secret)
		want       bool
	}{
		{
			name: "no changes",
			want: false,
		},
		{
			name: "label drift",
			mutate: func(s *corev1.Secret) {
				s.Labels["app"] = "modified-value"
			},
			want: true,
		},
		{
			name:       "annotation drift",
			annotedApm: true,
			mutate: func(s *corev1.Secret) {
				s.Annotations["user-annotation"] = "tampered"
			},
			want: true,
		},
		{
			name: "data drift is ignored since approver-policy owns it at runtime",
			mutate: func(s *corev1.Secret) {
				s.Data = map[string][]byte{"tls.crt": []byte("some-runtime-managed-cert")}
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apmBuilder := testApproverPolicyManager()
			if tt.annotedApm {
				apmBuilder = apmBuilder.WithAnnotations(map[string]string{"user-annotation": "original"})
			}

			// Call getResourceLabels/getResourceAnnotations separately for desired and
			// existing so each getWebhookTLSSecretObject call receives its own map instance,
			// since SetLabels/SetAnnotations store the passed map by reference.
			desired := getWebhookTLSSecretObject(getResourceLabels(apmBuilder.Build()), getResourceAnnotations(apmBuilder.Build()))
			existing := getWebhookTLSSecretObject(getResourceLabels(apmBuilder.Build()), getResourceAnnotations(apmBuilder.Build()))
			if tt.mutate != nil {
				tt.mutate(existing)
			}

			if got := secretModified(desired, existing); got != tt.want {
				t.Errorf("secretModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateOrApplyWebhookTLSSecret(t *testing.T) {
	tests := []struct {
		name            string
		preReq          func(*fakes.FakeCtrlClient)
		wantErr         string
		wantExistsCount int
		wantPatchCount  int
	}{
		{
			name: "successful apply when not found",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
			},
			wantExistsCount: 1,
			wantPatchCount:  1,
		},
		{
			name: "skip apply when existing matches desired even with different runtime-managed data",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					secret := getWebhookTLSSecretObject(testResourceLabels(), testResourceAnnotations())
					secret.Data = map[string][]byte{"tls.crt": []byte("runtime-managed")}
					secret.DeepCopyInto(obj.(*corev1.Secret))
					return true, nil
				})
			},
			wantExistsCount: 1,
			wantPatchCount:  0,
		},
		{
			name: "apply when existing has label drift",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					secret := getWebhookTLSSecretObject(testResourceLabels(), testResourceAnnotations())
					secret.Labels["app.kubernetes.io/instance"] = "modified-value"
					secret.DeepCopyInto(obj.(*corev1.Secret))
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
			wantErr:         "failed to check if secret",
			wantExistsCount: 1,
			wantPatchCount:  0,
		},
		{
			name: "patch error propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
				m.PatchCalls(func(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					return errTestClient
				})
			},
			wantErr:         "failed to apply secret",
			wantExistsCount: 1,
			wantPatchCount:  1,
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

			apm := testApproverPolicyManager().Build()
			err := r.createOrApplyWebhookTLSSecret(apm, getResourceLabels(apm), getResourceAnnotations(apm))
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
