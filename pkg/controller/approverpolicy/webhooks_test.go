package approverpolicy

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestGetValidatingWebhookConfigurationObject(t *testing.T) {
	tests := []struct {
		name            string
		apm             *approverPolicyManagerBuilder
		wantName        string
		wantLabels      map[string]string
		wantAnnotations map[string]string
		wantServiceName string
		wantServiceNS   string
	}{
		{
			name:     "sets correct name and labels",
			apm:      testApproverPolicyManager(),
			wantName: approverPolicyWebhookConfigName,
			wantLabels: map[string]string{
				"app": approverPolicyCommonName,
			},
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
		{
			name:            "configures correct service reference",
			apm:             testApproverPolicyManager(),
			wantServiceName: approverPolicyServiceName,
			wantServiceNS:   operandNamespace,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apm := tt.apm.Build()
			vwc := getValidatingWebhookConfigurationObject(getResourceLabels(apm), getResourceAnnotations(apm))

			if tt.wantName != "" && vwc.Name != tt.wantName {
				t.Errorf("expected name %q, got %q", tt.wantName, vwc.Name)
			}
			for key, val := range tt.wantLabels {
				if vwc.Labels[key] != val {
					t.Errorf("expected label %s=%q, got %q", key, val, vwc.Labels[key])
				}
			}
			for key, val := range tt.wantAnnotations {
				if vwc.Annotations[key] != val {
					t.Errorf("expected annotation %s=%q, got %q", key, val, vwc.Annotations[key])
				}
			}
			if tt.wantServiceName != "" {
				for i, wh := range vwc.Webhooks {
					if wh.ClientConfig.Service == nil {
						t.Errorf("webhook[%d]: expected service reference", i)
						continue
					}
					if wh.ClientConfig.Service.Name != tt.wantServiceName {
						t.Errorf("webhook[%d]: expected service name %q, got %q", i, tt.wantServiceName, wh.ClientConfig.Service.Name)
					}
					if wh.ClientConfig.Service.Namespace != tt.wantServiceNS {
						t.Errorf("webhook[%d]: expected service namespace %q, got %q", i, tt.wantServiceNS, wh.ClientConfig.Service.Namespace)
					}
				}
			}
		})
	}
}

func TestValidatingWebhookConfigurationModified(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*admissionregistrationv1.ValidatingWebhookConfiguration)
		want   bool
	}{
		{
			name: "no changes",
			want: false,
		},
		{
			name: "label drift",
			mutate: func(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				vwc.Labels["app"] = "modified-value"
			},
			want: true,
		},
		{
			name: "annotation drift",
			mutate: func(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				vwc.Annotations["extra"] = "modified-value"
				vwc.Annotations["cert-manager.io/inject-ca-from-secret"] = "tampered"
			},
			want: true,
		},
		{
			name: "service reference drift",
			mutate: func(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				vwc.Webhooks[0].ClientConfig.Service.Name = "wrong-service"
			},
			want: true,
		},
		{
			name: "failure policy drift",
			mutate: func(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				vwc.Webhooks[0].FailurePolicy = ptr.To(admissionregistrationv1.Ignore)
			},
			want: true,
		},
		{
			name: "caBundle drift is ignored",
			mutate: func(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				vwc.Webhooks[0].ClientConfig.CABundle = []byte("some-ca-bundle")
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := getValidatingWebhookConfigurationObject(testResourceLabels(), testResourceAnnotations())
			existing := getValidatingWebhookConfigurationObject(testResourceLabels(), testResourceAnnotations())
			if tt.mutate != nil {
				tt.mutate(existing)
			}

			if got := validatingWebhookConfigurationModified(desired, existing); got != tt.want {
				t.Errorf("validatingWebhookConfigurationModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateOrApplyValidatingWebhookConfiguration(t *testing.T) {
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
			name: "skip apply when existing matches desired",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					vwc := getValidatingWebhookConfigurationObject(testResourceLabels(), testResourceAnnotations())
					vwc.DeepCopyInto(obj.(*admissionregistrationv1.ValidatingWebhookConfiguration))
					return true, nil
				})
			},
			wantExistsCount: 1,
			wantPatchCount:  0,
		},
		{
			name: "apply when existing has drift",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					vwc := getValidatingWebhookConfigurationObject(testResourceLabels(), testResourceAnnotations())
					vwc.Webhooks[0].ClientConfig.Service.Name = "wrong-service"
					vwc.DeepCopyInto(obj.(*admissionregistrationv1.ValidatingWebhookConfiguration))
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
			wantErr:         "failed to check if validatingwebhookconfiguration",
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
			wantErr:         "failed to apply validatingwebhookconfiguration",
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
			err := r.createOrApplyValidatingWebhookConfiguration(apm, getResourceLabels(apm), getResourceAnnotations(apm))
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
