package approverpolicy

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func TestReconcile(t *testing.T) {
	tests := []struct {
		name    string
		preReq  func(*fakes.FakeCtrlClient)
		wantErr string
	}{
		{
			name: "resource not found returns no error",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					return apierrors.NewNotFound(v1alpha1.Resource("approverpolicymanager"), approverPolicyManagerObjectName)
				})
			},
		},
		{
			name: "failed to fetch resource propagates error",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					return apierrors.NewBadRequest("test error")
				})
			},
			wantErr: "failed to fetch approverpolicymanager.openshift.operator.io",
		},
		{
			name: "resource marked for deletion without finalizer",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					apm := testApproverPolicyManager().Build()
					apm.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					apm.DeepCopyInto(obj.(*v1alpha1.ApproverPolicyManager))
					return nil
				})
				m.DeleteReturns(nil)
			},
		},
		{
			name: "remove finalizer fails on deletion",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					apm := testApproverPolicyManager().Build()
					apm.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					apm.Finalizers = []string{finalizer}
					apm.DeepCopyInto(obj.(*v1alpha1.ApproverPolicyManager))
					return nil
				})
				m.DeleteReturns(nil)
				m.UpdateWithRetryCalls(func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
					return errTestClient
				})
			},
			wantErr: "failed to remove finalizers",
		},
		{
			name: "cleanup failure on deletion propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					apm := testApproverPolicyManager().Build()
					apm.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					apm.Finalizers = []string{finalizer}
					apm.DeepCopyInto(obj.(*v1alpha1.ApproverPolicyManager))
					return nil
				})
				m.DeleteReturns(errTestClient)
			},
			wantErr: "clean up failed",
		},
		{
			name: "adding finalizer fails",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					testApproverPolicyManager().Build().DeepCopyInto(obj.(*v1alpha1.ApproverPolicyManager))
					return nil
				})
				m.UpdateWithRetryCalls(func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
					return errTestClient
				})
			},
			wantErr: "failed to update",
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

			_, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{Name: approverPolicyManagerObjectName},
			})
			assertError(t, err, tt.wantErr)
		})
	}
}

func TestProcessReconcileRequest(t *testing.T) {
	t.Setenv(approverPolicyImageNameEnvVarName, "quay.io/example/approver-policy:v1")

	tests := []struct {
		name           string
		apm            *approverPolicyManagerBuilder
		preReq         func(*fakes.FakeCtrlClient)
		wantConditions []metav1.Condition
		wantErr        string
	}{
		{
			name: "namespace missing sets degraded true",
			apm:  testApproverPolicyManager(),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					switch obj.(type) {
					case *corev1.Namespace:
						return false, nil
					}
					return false, nil
				})
			},
			wantConditions: []metav1.Condition{
				{Type: v1alpha1.Degraded, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonFailed},
				{Type: v1alpha1.Ready, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonFailed},
			},
		},
		{
			name: "recoverable error sets in progress when deployment not available",
			apm:  testApproverPolicyManager(),
			preReq: func(m *fakes.FakeCtrlClient) {
				m.ExistsCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
					switch obj.(type) {
					case *corev1.Namespace:
						return true, nil
					}
					// Deployment (and every other resource) reports NotFound so it is
					// applied via SSA Patch, but its own subsequent isDeploymentAvailable
					// check will report unavailable since Exists returns false again.
					return false, nil
				})
			},
			wantConditions: []metav1.Condition{
				{Type: v1alpha1.Degraded, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonReady},
				{Type: v1alpha1.Ready, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonInProgress},
			},
			wantErr: "is not yet available",
		},
		{
			name: "invalid config sets degraded true",
			apm: func() *approverPolicyManagerBuilder {
				b := testApproverPolicyManager()
				b.Spec.ApproverPolicyConfig = v1alpha1.ApproverPolicyConfig{}
				return b
			}(),
			wantConditions: []metav1.Condition{
				{Type: v1alpha1.Degraded, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonFailed},
				{Type: v1alpha1.Ready, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonFailed},
			},
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

			apm := tt.apm.Build()
			_, err := r.processReconcileRequest(apm, types.NamespacedName{Name: apm.GetName()})
			assertError(t, err, tt.wantErr)

			for _, want := range tt.wantConditions {
				cond := apm.Status.GetCondition(want.Type)
				if cond == nil {
					t.Errorf("expected condition %s not found in status conditions %v", want.Type, apm.Status.Conditions)
					continue
				}
				if cond.Status != want.Status {
					t.Errorf("condition %s: expected status %s, got %s", want.Type, want.Status, cond.Status)
				}
				if cond.Reason != want.Reason {
					t.Errorf("condition %s: expected reason %s, got %s", want.Type, want.Reason, cond.Reason)
				}
			}
		})
	}
}

func TestCleanUp(t *testing.T) {
	tests := []struct {
		name    string
		preReq  func(*fakes.FakeCtrlClient)
		wantErr string
	}{
		{
			name: "successful cleanup",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.DeleteReturns(nil)
			},
		},
		{
			name: "cleanup failure propagates",
			preReq: func(m *fakes.FakeCtrlClient) {
				m.DeleteReturns(errTestClient)
			},
			wantErr: "failed to delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testReconciler(t)
			mock := &fakes.FakeCtrlClient{}
			tt.preReq(mock)
			r.CtrlClient = mock

			err := r.cleanUp(testApproverPolicyManager().Build())
			assertError(t, err, tt.wantErr)
		})
	}
}
