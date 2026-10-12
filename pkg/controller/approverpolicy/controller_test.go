package approverpolicy

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func readyReconciler(t *testing.T) (*Reconciler, *fakes.FakeCtrlClient, *v1alpha1.ApproverPolicyManager, *appsv1.Deployment) {
	t.Helper()
	objects := testResources(t)
	manager := testManager()
	deployment := &appsv1.Deployment{}
	webhook := &admissionv1.ValidatingWebhookConfiguration{}
	for _, obj := range objects {
		switch obj.GetKind() {
		case "Deployment":
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, deployment))
		case "ValidatingWebhookConfiguration":
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, webhook))
		}
	}
	deployment.Generation = 4
	deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: 4, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
	webhook.Webhooks[0].ClientConfig.CABundle = []byte("injected CA")
	fake := &fakes.FakeCtrlClient{}
	fake.GetCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) error {
		switch target := obj.(type) {
		case *v1alpha1.ApproverPolicyManager:
			manager.DeepCopyInto(target)
		case *appsv1.Deployment:
			deployment.DeepCopyInto(target)
		case *corev1.Namespace:
			target.Name = operandNamespace
		case *corev1.Secret:
			target.Data = map[string][]byte{"tls.crt": []byte("operand data")}
		case *admissionv1.ValidatingWebhookConfiguration:
			webhook.DeepCopyInto(target)
		default:
			return fmt.Errorf("unexpected Get: %T", obj)
		}
		return nil
	})
	fake.StatusUpdateCalls(func(_ context.Context, obj client.Object, _ ...client.SubResourceUpdateOption) error {
		obj.(*v1alpha1.ApproverPolicyManager).Status.DeepCopyInto(&manager.Status)
		return nil
	})
	return &Reconciler{CtrlClient: fake, log: logr.Discard()}, fake, manager, deployment
}

func TestReconcileReadiness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*appsv1.Deployment)
		ready  bool
	}{
		{"current rollout", func(*appsv1.Deployment) {}, true},
		{"stale observed generation", func(d *appsv1.Deployment) { d.Status.ObservedGeneration = 3 }, false},
		{"old available replica", func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 0 }, false},
		{"not available", func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 0 }, false},
		{"not ready", func(d *appsv1.Deployment) { d.Status.ReadyReplicas = 0 }, false},
		{"extra old replica", func(d *appsv1.Deployment) { d.Status.Replicas = 2 }, false},
		{"unavailable replica", func(d *appsv1.Deployment) { d.Status.UnavailableReplicas = 1 }, false},
		{"scaled to zero", func(d *appsv1.Deployment) { d.Spec.Replicas = ptr.To(int32(0)) }, false},
		{"deleting deployment", func(d *appsv1.Deployment) { now := metav1.Now(); d.DeletionTimestamp = &now }, false},
		{"stale cached spec after apply", func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "old:image" }, false},
		{"host network drift", func(d *appsv1.Deployment) { d.Spec.Template.Spec.HostNetwork = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, fake, manager, deployment := readyReconciler(t)
			tc.mutate(deployment)
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
			require.NoError(t, err)
			require.Equal(t, 10, fake.PatchCallCount())
			ready := manager.Status.GetCondition(v1alpha1.Ready)
			require.NotNil(t, ready)
			if tc.ready {
				require.Equal(t, metav1.ConditionTrue, ready.Status)
				require.Equal(t, v1alpha1.ReasonReady, ready.Reason)
				require.Zero(t, result.RequeueAfter)
			} else {
				require.Equal(t, metav1.ConditionFalse, ready.Status)
				require.Equal(t, v1alpha1.ReasonInProgress, ready.Reason)
				require.Equal(t, requeueInterval, result.RequeueAfter)
			}
			require.Equal(t, manager.Generation, ready.ObservedGeneration)
			require.Equal(t, deployment.Spec.Template.Spec.Containers[0].Image, manager.Status.ApproverPolicyImage)
			require.Zero(t, fake.DeleteCallCount())
			require.Zero(t, fake.CreateCallCount())
			require.Zero(t, fake.UpdateCallCount())
		})
	}
}

func TestReconcileMissingOrDeletingManager(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(fmt.Sprint(deleting), func(t *testing.T) {
			r, fake, manager, _ := readyReconciler(t)
			if deleting {
				now := metav1.Now()
				manager.DeletionTimestamp = &now
			} else {
				fake.GetReturns(apierrors.NewNotFound(schema.GroupResource{Resource: "approverpolicymanagers"}, managerName))
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
			require.NoError(t, err)
			require.Zero(t, result)
			require.Zero(t, fake.PatchCallCount())
			require.Zero(t, fake.StatusUpdateCallCount())
			require.Zero(t, fake.DeleteCallCount())
		})
	}
}

func TestReconcilePrerequisiteFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      string
		err       error
		empty     bool
		permanent bool
	}{
		{"namespace missing", "namespace", apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, operandNamespace), false, false},
		{"namespace forbidden", "namespace", apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, operandNamespace, fmt.Errorf("denied")), false, true},
		{"namespace timeout", "namespace", apierrors.NewTimeoutError("retry", 1), false, false},
		{"TLS secret missing", "secret", apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, operandName+"-tls"), false, false},
		{"TLS secret empty", "secret", nil, true, false},
		{"CA not injected", "webhook", nil, true, false},
		{"CA read forbidden", "webhook", apierrors.NewForbidden(schema.GroupResource{Resource: "validatingwebhookconfigurations"}, operandName, fmt.Errorf("denied")), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, fake, manager, _ := readyReconciler(t)
			base := fake.GetStub
			fake.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
				matched := false
				switch obj.(type) {
				case *corev1.Namespace:
					matched = tc.kind == "namespace"
				case *corev1.Secret:
					matched = tc.kind == "secret"
				case *admissionv1.ValidatingWebhookConfiguration:
					matched = tc.kind == "webhook"
				}
				if matched && tc.err != nil {
					return tc.err
				}
				if err := base(ctx, key, obj); err != nil {
					return err
				}
				if matched && tc.empty {
					switch v := obj.(type) {
					case *corev1.Secret:
						v.Data = nil
					case *admissionv1.ValidatingWebhookConfiguration:
						v.Webhooks[0].ClientConfig.CABundle = nil
					}
				}
				return nil
			})
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
			require.NoError(t, err)
			ready := manager.Status.GetCondition(v1alpha1.Ready)
			require.Equal(t, metav1.ConditionFalse, ready.Status)
			if tc.permanent {
				require.Equal(t, v1alpha1.ReasonFailed, ready.Reason)
				require.Equal(t, metav1.ConditionTrue, manager.Status.GetCondition(v1alpha1.Degraded).Status)
				require.Zero(t, result.RequeueAfter)
			} else {
				require.Equal(t, v1alpha1.ReasonInProgress, ready.Reason)
				require.Equal(t, requeueInterval, result.RequeueAfter)
			}
			if tc.kind == "namespace" {
				require.Zero(t, fake.PatchCallCount())
			}
			require.Zero(t, fake.CreateCallCount())
			require.Zero(t, fake.DeleteCallCount())
		})
	}
}

func TestReconcileStatusAndFailures(t *testing.T) {
	r, fake, manager, deployment := readyReconciler(t)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}}
	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, fake.StatusUpdateCallCount())
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, fake.StatusUpdateCallCount(), "unchanged status must not loop")
	manager.Status.ApproverPolicyImage = "outdated status"
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 2, fake.StatusUpdateCallCount(), "image-only changes must persist")
	deployment.Status.AvailableReplicas = 0
	result, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, requeueInterval, result.RequeueAfter)
	require.Equal(t, metav1.ConditionFalse, manager.Status.GetCondition(v1alpha1.Ready).Status)
	fake.StatusUpdateReturns(fmt.Errorf("status write failed"))
	deployment.Status.AvailableReplicas = 1
	_, err = r.Reconcile(context.Background(), req)
	require.ErrorContains(t, err, "status write failed")
}

func TestReconcileReadAndApplyErrors(t *testing.T) {
	r, fake, _, _ := readyReconciler(t)
	fake.GetReturns(apierrors.NewTimeoutError("read failure", 1))
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
	require.Error(t, err)
	require.Zero(t, fake.PatchCallCount())
	r, fake, manager, _ := readyReconciler(t)
	fake.PatchReturns(apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, operandName, fmt.Errorf("denied")))
	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
	require.NoError(t, err)
	require.Equal(t, 1, fake.PatchCallCount())
	require.Equal(t, metav1.ConditionTrue, manager.Status.GetCondition(v1alpha1.Degraded).Status)
}

func TestReconcileMissingImage(t *testing.T) {
	r, fake, manager, _ := readyReconciler(t)
	t.Setenv(imageEnv, "")
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
	require.NoError(t, err)
	require.Zero(t, result)
	require.Zero(t, fake.PatchCallCount())
	require.Equal(t, metav1.ConditionFalse, manager.Status.GetCondition(v1alpha1.Ready).Status)
	degraded := manager.Status.GetCondition(v1alpha1.Degraded)
	require.Equal(t, metav1.ConditionTrue, degraded.Status)
	require.Contains(t, degraded.Message, imageEnv)
}

func TestStatusConflictAndManagerChange(t *testing.T) {
	r, fake, manager, _ := readyReconciler(t)
	base := fake.StatusUpdateStub
	calls := 0
	fake.StatusUpdateCalls(func(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
		calls++
		if calls == 1 {
			return apierrors.NewConflict(schema.GroupResource{Resource: "approverpolicymanagers"}, managerName, fmt.Errorf("conflict"))
		}
		return base(ctx, obj, opts...)
	})
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	stale := manager.DeepCopy()
	stale.Generation--
	require.ErrorContains(t, r.updateStatus(context.Background(), stale), "changed during reconciliation")
}

func TestOperandPredicateIncludesStatusChanges(t *testing.T) {
	p := operandResourcePredicate()
	old := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: operandName, Namespace: operandNamespace, Generation: 4}}
	updated := old.DeepCopy()
	updated.Status.AvailableReplicas = 1
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: updated}))
	updated.Name = "unrelated"
	require.False(t, p.Create(event.CreateEvent{Object: updated}))
	updated.Name = operandName
	updated.Namespace = "elsewhere"
	require.False(t, p.Create(event.CreateEvent{Object: updated}))
}
