package approverpolicy

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestIsDeploymentAvailable(t *testing.T) {
	tests := []struct {
		name    string
		preReq  func(*fakes.FakeCtrlClient)
		want    bool
		wantErr string
	}{
		{
			name: "not found returns false",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsReturns(false, nil)
			},
			want: false,
		},
		{
			name: "exists error propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsReturns(false, errTestClient)
			},
			wantErr: "failed to check if deployment",
		},
		{
			name: "available replicas meets desired replicas",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					d := obj.(*appsv1.Deployment)
					d.Generation = 1
					d.Spec.Replicas = ptr.To(int32(1))
					d.Status.ObservedGeneration = 1
					d.Status.AvailableReplicas = 1
					return true, nil
				})
			},
			want: true,
		},
		{
			name: "available replicas below desired replicas",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					d := obj.(*appsv1.Deployment)
					d.Generation = 1
					d.Spec.Replicas = ptr.To(int32(1))
					d.Status.ObservedGeneration = 1
					d.Status.AvailableReplicas = 0
					return true, nil
				})
			},
			want: false,
		},
		{
			name: "stale observedGeneration is not available",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					d := obj.(*appsv1.Deployment)
					d.Generation = 2
					d.Spec.Replicas = ptr.To(int32(1))
					d.Status.ObservedGeneration = 1
					d.Status.AvailableReplicas = 1
					return true, nil
				})
			},
			want: false,
		},
		{
			name: "nil replicas defaults desired to 1",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					d := obj.(*appsv1.Deployment)
					d.Generation = 1
					d.Spec.Replicas = nil
					d.Status.ObservedGeneration = 1
					d.Status.AvailableReplicas = 1
					return true, nil
				})
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testReconciler(t)
			mock := &fakes.FakeCtrlClient{}
			tt.preReq(mock)
			r.CtrlClient = mock

			got, err := r.isDeploymentAvailable()
			assertError(t, err, tt.wantErr)
			if err == nil && got != tt.want {
				t.Errorf("isDeploymentAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateOperandNamespace(t *testing.T) {
	tests := []struct {
		name    string
		preReq  func(*fakes.FakeCtrlClient)
		wantErr string
	}{
		{
			name: "namespace exists",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsReturns(true, nil)
			},
		},
		{
			name: "namespace missing",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsReturns(false, nil)
			},
			wantErr: "does not exist",
		},
		{
			name: "exists error propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsReturns(false, errTestClient)
			},
			wantErr: "failed to check if namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testReconciler(t)
			mock := &fakes.FakeCtrlClient{}
			tt.preReq(mock)
			r.CtrlClient = mock

			err := r.validateOperandNamespace()
			assertError(t, err, tt.wantErr)
		})
	}
}

func TestDeleteApproverPolicyResources(t *testing.T) {
	t.Run("deletes all resources without error", func(t *testing.T) {
		r := testReconciler(t)
		mock := &fakes.FakeCtrlClient{}
		mock.DeleteReturns(nil)
		r.CtrlClient = mock

		if err := r.deleteApproverPolicyResources(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := mock.DeleteCallCount(); got == 0 {
			t.Errorf("expected at least one Delete call, got %d", got)
		}
	})

	t.Run("NotFound errors are ignored", func(t *testing.T) {
		r := testReconciler(t)
		mock := &fakes.FakeCtrlClient{}
		mock.DeleteCalls(func(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
			return apierrors.NewNotFound(schema.GroupResource{}, obj.GetName())
		})
		r.CtrlClient = mock

		if err := r.deleteApproverPolicyResources(); err != nil {
			t.Fatalf("expected NotFound errors to be ignored, got: %v", err)
		}
	})

	t.Run("non-NotFound errors are aggregated and returned", func(t *testing.T) {
		r := testReconciler(t)
		mock := &fakes.FakeCtrlClient{}
		mock.DeleteReturns(errTestClient)
		r.CtrlClient = mock

		err := r.deleteApproverPolicyResources()
		assertError(t, err, "failed to delete")
	})
}

func TestUpdateStatusObservedState(t *testing.T) {
	t.Run("updates when image differs", func(t *testing.T) {
		t.Setenv(approverPolicyImageNameEnvVarName, "quay.io/example/approver-policy:v1")
		r := testReconciler(t)
		mock := &fakes.FakeCtrlClient{}
		mock.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
			testApproverPolicyManager().Build().DeepCopyInto(obj.(*v1alpha1.ApproverPolicyManager))
			return nil
		})
		r.CtrlClient = mock

		apm := testApproverPolicyManager().Build()
		if err := r.updateStatusObservedState(apm); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if apm.Status.ApproverPolicyImage != "quay.io/example/approver-policy:v1" {
			t.Errorf("expected status image to be set, got %q", apm.Status.ApproverPolicyImage)
		}
		if got := mock.StatusUpdateCallCount(); got != 1 {
			t.Errorf("expected 1 StatusUpdate call, got %d", got)
		}
	})

	t.Run("no-op when image unchanged", func(t *testing.T) {
		t.Setenv(approverPolicyImageNameEnvVarName, "")
		r := testReconciler(t)
		mock := &fakes.FakeCtrlClient{}
		r.CtrlClient = mock

		apm := testApproverPolicyManager().Build()
		if err := r.updateStatusObservedState(apm); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := mock.StatusUpdateCallCount(); got != 0 {
			t.Errorf("expected no StatusUpdate call when nothing changed, got %d", got)
		}
	})
}
