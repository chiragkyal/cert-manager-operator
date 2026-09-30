package approverpolicy

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestGetServiceObjects(t *testing.T) {
	tests := []struct {
		name            string
		apm             *approverPolicyManagerBuilder
		getService      func(map[string]string, map[string]string) *corev1.Service
		wantName        string
		wantNamespace   string
		wantLabels      map[string]string
		wantAnnotations map[string]string
	}{
		{
			name:          "webhook service sets correct name and namespace",
			apm:           testApproverPolicyManager(),
			getService:    getWebhookServiceObject,
			wantName:      approverPolicyServiceName,
			wantNamespace: operandNamespace,
		},
		{
			name:          "metrics service sets correct name and namespace",
			apm:           testApproverPolicyManager(),
			getService:    getMetricsServiceObject,
			wantName:      approverPolicyMetricsServiceName,
			wantNamespace: operandNamespace,
		},
		{
			name:       "default labels take precedence over user labels",
			apm:        testApproverPolicyManager().WithLabels(map[string]string{"app": "should-be-overridden"}),
			getService: getWebhookServiceObject,
			wantLabels: map[string]string{
				"app": approverPolicyCommonName,
			},
		},
		{
			name: "merges custom labels and annotations",
			apm: testApproverPolicyManager().
				WithLabels(map[string]string{"user-label": "test-value"}).
				WithAnnotations(map[string]string{"user-annotation": "test-value"}),
			getService:      getWebhookServiceObject,
			wantLabels:      map[string]string{"user-label": "test-value"},
			wantAnnotations: map[string]string{"user-annotation": "test-value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apm := tt.apm.Build()
			svc := tt.getService(getResourceLabels(apm), getResourceAnnotations(apm))

			if tt.wantName != "" && svc.Name != tt.wantName {
				t.Errorf("expected name %q, got %q", tt.wantName, svc.Name)
			}
			if tt.wantNamespace != "" && svc.Namespace != tt.wantNamespace {
				t.Errorf("expected namespace %q, got %q", tt.wantNamespace, svc.Namespace)
			}
			for key, val := range tt.wantLabels {
				if svc.Labels[key] != val {
					t.Errorf("expected label %s=%q, got %q", key, val, svc.Labels[key])
				}
			}
			for key, val := range tt.wantAnnotations {
				if svc.Annotations[key] != val {
					t.Errorf("expected annotation %s=%q, got %q", key, val, svc.Annotations[key])
				}
			}
		})
	}
}

func TestServiceModified(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corev1.Service)
		want   bool
	}{
		{
			name: "no changes",
			want: false,
		},
		{
			name: "label drift",
			mutate: func(s *corev1.Service) {
				s.Labels["app"] = "modified-value"
			},
			want: true,
		},
		{
			name: "type drift",
			mutate: func(s *corev1.Service) {
				s.Spec.Type = corev1.ServiceTypeNodePort
			},
			want: true,
		},
		{
			name: "selector drift",
			mutate: func(s *corev1.Service) {
				s.Spec.Selector["app"] = "wrong-selector"
			},
			want: true,
		},
		{
			name: "port drift",
			mutate: func(s *corev1.Service) {
				s.Spec.Ports[0].TargetPort = intstr.FromInt32(9999)
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := getWebhookServiceObject(testResourceLabels(), testResourceAnnotations())
			existing := getWebhookServiceObject(testResourceLabels(), testResourceAnnotations())
			if tt.mutate != nil {
				tt.mutate(existing)
			}

			if got := serviceModified(desired, existing); got != tt.want {
				t.Errorf("serviceModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateOrApplyServices(t *testing.T) {
	tests := []struct {
		name            string
		preReq          func(*fakes.FakeCtrlClient)
		wantErr         string
		wantExistsCount int
		wantPatchCount  int
	}{
		{
			name: "successful apply of both services",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
			},
			wantExistsCount: 2,
			wantPatchCount:  2,
		},
		{
			name: "skip apply when both services match desired",
			preReq: func(m *fakes.FakeCtrlClient) {
				existsCall := 0
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					existsCall++
					var svc *corev1.Service
					if existsCall == 1 {
						svc = getWebhookServiceObject(testResourceLabels(), testResourceAnnotations())
					} else {
						svc = getMetricsServiceObject(testResourceLabels(), testResourceAnnotations())
					}
					svc.DeepCopyInto(obj.(*corev1.Service))
					return true, nil
				})
			},
			wantExistsCount: 2,
			wantPatchCount:  0,
		},
		{
			name: "apply when existing has label drift",
			preReq: func(m *fakes.FakeCtrlClient) {
				existsCall := 0
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					existsCall++
					if existsCall == 1 {
						svc := getWebhookServiceObject(testResourceLabels(), testResourceAnnotations())
						svc.Labels["app.kubernetes.io/instance"] = "modified-value"
						svc.DeepCopyInto(obj.(*corev1.Service))
					} else {
						svc := getMetricsServiceObject(testResourceLabels(), testResourceAnnotations())
						svc.DeepCopyInto(obj.(*corev1.Service))
					}
					return true, nil
				})
			},
			wantExistsCount: 2,
			wantPatchCount:  1,
		},
		{
			name: "exists error propagates on first service",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, errTestClient
				})
			},
			wantErr:         "failed to check if service",
			wantExistsCount: 1,
			wantPatchCount:  0,
		},
		{
			name: "webhook service patch error propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
				m.PatchCalls(func(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					return errTestClient
				})
			},
			wantErr:         "failed to apply service",
			wantExistsCount: 1,
			wantPatchCount:  1,
		},
		{
			name: "metrics service patch error propagates on second call",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					return false, nil
				})
				callCount := 0
				m.PatchCalls(func(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					callCount++
					if callCount == 2 {
						return errTestClient
					}
					return nil
				})
			},
			wantErr:         "failed to apply service",
			wantExistsCount: 2,
			wantPatchCount:  2,
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
			err := r.createOrApplyServices(apm, getResourceLabels(apm), getResourceAnnotations(apm))
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
