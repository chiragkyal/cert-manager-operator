package approverpolicy

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func readyReconciler(t *testing.T) (*Reconciler, *fakes.FakeCtrlClient, *v1alpha1.ApproverPolicyManager, *appsv1.Deployment) {
	t.Helper()
	objects := testResources(t)
	manager := testManager()
	manager.Finalizers = []string{cleanupFinalizer}
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
				manager.Finalizers = nil // No resources were installed without our finalizer.
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

func TestReconcileInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		field  string
		mutate func(*v1alpha1.ApproverPolicyManager)
	}{
		{"nodeSelector", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.NodeSelector = map[string]string{"invalid key": "value"}
		}},
		{"approveSignerNames", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.ApproveSignerNames = []string{"duplicate", "duplicate"}
		}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			r, fake, manager, _ := readyReconciler(t)
			tc.mutate(manager)
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: managerName}})
			require.NoError(t, err)
			require.Zero(t, result.RequeueAfter)
			require.Zero(t, fake.PatchCallCount())
			require.Zero(t, fake.CreateCallCount())
			ready := manager.Status.GetCondition(v1alpha1.Ready)
			require.Equal(t, metav1.ConditionFalse, ready.Status)
			require.Equal(t, v1alpha1.ReasonFailed, ready.Reason)
			degraded := manager.Status.GetCondition(v1alpha1.Degraded)
			require.Equal(t, metav1.ConditionTrue, degraded.Status)
			require.Equal(t, v1alpha1.ReasonFailed, degraded.Reason)
			require.Contains(t, degraded.Message, tc.field)
		})
	}
}

func TestOperatorCanGrantSignerScope(t *testing.T) {
	data, err := os.ReadFile("../../../config/rbac/role.yaml")
	require.NoError(t, err)
	role := &rbacv1.ClusterRole{}
	require.NoError(t, yaml.Unmarshal(data, role))
	canGrantAllSigners := false
	for _, rule := range role.Rules {
		require.NotContains(t, rule.Verbs, "escalate")
		require.NotContains(t, rule.Verbs, "bind")
		if slices.Contains(rule.APIGroups, "cert-manager.io") && slices.Contains(rule.Resources, "signers") && slices.Contains(rule.Verbs, "approve") && len(rule.ResourceNames) == 0 {
			canGrantAllSigners = true
		}
	}
	require.True(t, canGrantAllSigners, "operator must hold the unrestricted signer permission it grants, without an escalation exemption")
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

func TestFinalizerPrecedesInstallation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			r, fake, manager, _ := readyReconciler(t)
			manager.Finalizers = []string{"other.example/finalizer"}
			fake.UpdateCalls(func(_ context.Context, obj client.Object, _ ...client.UpdateOption) error {
				if fail {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "approverpolicymanagers"}, managerName, fmt.Errorf("denied"))
				}
				obj.(*v1alpha1.ApproverPolicyManager).DeepCopyInto(manager)
				return nil
			})
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
			require.NoError(t, err)
			require.Positive(t, result.RequeueAfter)
			require.Zero(t, fake.PatchCallCount(), "finalizer must be observed before installation")
			require.Contains(t, manager.Finalizers, "other.example/finalizer")
			if fail {
				require.NotContains(t, manager.Finalizers, cleanupFinalizer)
				require.Equal(t, metav1.ConditionTrue, manager.Status.GetCondition(v1alpha1.Degraded).Status)
				return
			}
			require.Contains(t, manager.Finalizers, cleanupFinalizer)
			_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
			require.NoError(t, err)
			require.Equal(t, len(resourceAssets), fake.PatchCallCount())
		})
	}
}

func removalKey(obj client.Object) string {
	return obj.GetObjectKind().GroupVersionKind().Kind + "/" + obj.GetNamespace() + "/" + obj.GetName()
}

func removalReconciler(t *testing.T) (*Reconciler, *fakes.FakeCtrlClient, *v1alpha1.ApproverPolicyManager, map[string]*unstructured.Unstructured) {
	t.Helper()
	resources := testResources(t)
	manager := testManager()
	manager.Finalizers = []string{cleanupFinalizer, "other.example/finalizer"}
	now := metav1.Now()
	manager.DeletionTimestamp = &now
	store := map[string]*unstructured.Unstructured{}
	for i, obj := range resources {
		obj.SetUID(types.UID(fmt.Sprintf("resource-%d", i)))
		obj.SetResourceVersion("1")
		obj.SetLabels(nil) // Mutable labels must not hide inventory during cleanup.
		store[removalKey(obj)] = obj
	}
	fake := &fakes.FakeCtrlClient{}
	fake.GetCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) error {
		if target, ok := obj.(*v1alpha1.ApproverPolicyManager); ok {
			manager.DeepCopyInto(target)
			return nil
		}
		found := store[removalKey(obj)]
		if found == nil {
			return apierrors.NewNotFound(schema.GroupResource{Resource: obj.GetObjectKind().GroupVersionKind().Kind}, obj.GetName())
		}
		found.DeepCopyInto(obj.(*unstructured.Unstructured))
		return nil
	})
	fake.DeleteCalls(func(_ context.Context, obj client.Object, opts ...client.DeleteOption) error {
		options := (&client.DeleteOptions{}).ApplyOptions(opts)
		current := store[removalKey(obj)]
		require.NotNil(t, current)
		require.NotNil(t, options.Preconditions)
		require.Equal(t, current.GetUID(), *options.Preconditions.UID)
		require.Equal(t, current.GetResourceVersion(), *options.Preconditions.ResourceVersion)
		if obj.GetObjectKind().GroupVersionKind().Kind == "Deployment" {
			require.Equal(t, metav1.DeletePropagationForeground, *options.PropagationPolicy)
			current.SetDeletionTimestamp(&now)
			current.SetFinalizers([]string{metav1.FinalizerDeleteDependents})
		} else {
			require.Equal(t, metav1.DeletePropagationBackground, *options.PropagationPolicy)
			delete(store, removalKey(obj))
		}
		return nil
	})
	fake.UpdateCalls(func(_ context.Context, obj client.Object, _ ...client.UpdateOption) error {
		obj.(*v1alpha1.ApproverPolicyManager).DeepCopyInto(manager)
		return nil
	})
	fake.StatusUpdateCalls(func(_ context.Context, obj client.Object, _ ...client.SubResourceUpdateOption) error {
		obj.(*v1alpha1.ApproverPolicyManager).Status.DeepCopyInto(&manager.Status)
		return nil
	})
	return &Reconciler{CtrlClient: fake, log: logr.Discard()}, fake, manager, store
}

func TestRemovalWaitsForForegroundAndConfirmsInventory(t *testing.T) {
	r, fake, manager, store := removalReconciler(t)
	t.Setenv(imageEnv, "")
	manager.Spec.ApproverPolicyConfig.LogFormat = "invalid-but-must-remove"
	request := ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}}
	for range 2 {
		result, err := r.Reconcile(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, requeueInterval, result.RequeueAfter)
		require.Equal(t, 1, fake.DeleteCallCount(), "no other removal while foreground GC waits for workload dependents")
		require.Contains(t, manager.Finalizers, cleanupFinalizer)
		require.Len(t, store, len(resourceAssets))
	}
	delete(store, "Deployment/"+operandNamespace+"/"+operandName) // Simulate GC completing all blocking dependents.
	r = &Reconciler{CtrlClient: fake, log: logr.Discard()}        // Restart has no in-memory cleanup dependency.
	result, err := r.Reconcile(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, requeueInterval, result.RequeueAfter)
	require.Equal(t, len(resourceAssets), fake.DeleteCallCount())
	require.Empty(t, store)
	require.Contains(t, manager.Finalizers, cleanupFinalizer, "successful Delete alone is not confirmed absence")
	result, err = r.Reconcile(context.Background(), request)
	require.NoError(t, err)
	require.Zero(t, result)
	require.Equal(t, []string{"other.example/finalizer"}, manager.Finalizers)
	require.Zero(t, fake.PatchCallCount())
	require.Zero(t, fake.CreateCallCount())
	for i := range fake.DeleteCallCount() {
		_, obj, _ := fake.DeleteArgsForCall(i)
		require.NotContains(t, []string{"CertificateRequestPolicy", "CustomResourceDefinition", "Namespace"}, obj.GetObjectKind().GroupVersionKind().Kind)
	}
}

func TestRemovalPreservesFinalizerOnResourceFailures(t *testing.T) {
	resources := testResources(t)
	for _, resource := range resources {
		for _, failure := range []string{"get", "delete", "precondition", "missing UID", "missing version"} {
			t.Run(removalKey(resource)+"/"+failure, func(t *testing.T) {
				r, fake, manager, store := removalReconciler(t)
				target := removalKey(resource)
				for key := range store {
					if key != target {
						delete(store, key)
					}
				}
				if failure == "missing UID" {
					store[target].SetUID("")
				}
				if failure == "missing version" {
					store[target].SetResourceVersion("")
				}
				get := fake.GetStub
				fake.GetCalls(func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
					if failure == "get" && removalKey(obj) == target {
						return apierrors.NewForbidden(schema.GroupResource{Resource: "resource"}, obj.GetName(), fmt.Errorf("read denied"))
					}
					return get(ctx, key, obj)
				})
				fake.DeleteCalls(func(_ context.Context, obj client.Object, opts ...client.DeleteOption) error {
					require.Equal(t, target, removalKey(obj))
					if failure == "precondition" {
						options := (&client.DeleteOptions{}).ApplyOptions(opts)
						require.NotNil(t, options.Preconditions.UID)
						require.NotNil(t, options.Preconditions.ResourceVersion)
						return apierrors.NewConflict(schema.GroupResource{Resource: "resource"}, obj.GetName(), fmt.Errorf("object replaced or changed owner"))
					}
					return apierrors.NewForbidden(schema.GroupResource{Resource: "resource"}, obj.GetName(), fmt.Errorf("delete denied"))
				})
				result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
				require.NoError(t, err)
				require.Equal(t, requeueInterval, result.RequeueAfter)
				require.Contains(t, manager.Finalizers, cleanupFinalizer)
				require.Zero(t, fake.UpdateCallCount())
				require.Zero(t, fake.PatchCallCount())
				require.Contains(t, store, target)
			})
		}
	}
}

func TestRemovalRetainsForeignResources(t *testing.T) {
	for _, ownership := range []string{"none", "other UID", "other kind", "other version", "other name"} {
		t.Run(ownership, func(t *testing.T) {
			r, fake, manager, store := removalReconciler(t)
			for _, obj := range store {
				owners := obj.GetOwnerReferences()
				switch ownership {
				case "none":
					owners = nil
				case "other UID":
					owners[0].UID = "other"
				case "other kind":
					owners[0].Kind = "TrustManager"
				case "other version":
					owners[0].APIVersion = "other.example/v1"
				case "other name":
					owners[0].Name = "other"
				}
				obj.SetOwnerReferences(owners)
			}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
			require.NoError(t, err)
			require.NotContains(t, manager.Finalizers, cleanupFinalizer)
			require.Zero(t, fake.DeleteCallCount())
			require.Len(t, store, len(resourceAssets))
		})
	}
}

func TestFinalizerUpdateGuardsAndRetries(t *testing.T) {
	for _, scenario := range []string{"conflict", "replacement", "concurrent deletion", "read failure", "write failure"} {
		t.Run(scenario, func(t *testing.T) {
			r, fake, manager, _ := readyReconciler(t)
			manager.Finalizers = []string{"other.example/finalizer"}
			desired := manager.DeepCopy()
			switch scenario {
			case "replacement":
				manager.UID = "replacement"
			case "concurrent deletion":
				now := metav1.Now()
				manager.DeletionTimestamp = &now
			case "read failure":
				fake.GetReturns(fmt.Errorf("unavailable"))
			}
			fake.UpdateCalls(func(_ context.Context, obj client.Object, _ ...client.UpdateOption) error {
				if scenario == "write failure" {
					return fmt.Errorf("write unavailable")
				}
				if fake.UpdateCallCount() == 1 {
					manager.Finalizers = append(manager.Finalizers, "concurrent.example/finalizer")
					return apierrors.NewConflict(schema.GroupResource{Resource: "approverpolicymanagers"}, managerName, fmt.Errorf("conflict"))
				}
				obj.(*v1alpha1.ApproverPolicyManager).DeepCopyInto(manager)
				return nil
			})
			err := r.updateFinalizer(context.Background(), desired, true)
			if scenario == "conflict" {
				require.NoError(t, err)
				require.ElementsMatch(t, []string{"other.example/finalizer", "concurrent.example/finalizer", cleanupFinalizer}, manager.Finalizers)
				require.Equal(t, 2, fake.UpdateCallCount())
			} else {
				require.Error(t, err)
				require.NotContains(t, manager.Finalizers, cleanupFinalizer)
			}
		})
	}
	for _, failStatus := range []bool{false, true} {
		r, fake, manager, store := removalReconciler(t)
		clear(store)
		fake.UpdateReturns(fmt.Errorf("finalizer write unavailable"))
		if failStatus {
			fake.StatusUpdateReturns(fmt.Errorf("status unavailable"))
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
		if failStatus {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, requeueInterval, result.RequeueAfter)
		}
		require.Contains(t, manager.Finalizers, cleanupFinalizer)
	}
}

func TestManagerPredicateObservesDeletion(t *testing.T) {
	p := managerResourcePredicate()
	old := testManager()
	updated := old.DeepCopy()
	now := metav1.Now()
	updated.DeletionTimestamp = &now
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: updated}))
	updated = old.DeepCopy()
	updated.Generation++
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: updated}))
	updated = old.DeepCopy()
	updated.Status.ApproverPolicyImage = "other:image"
	require.False(t, p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: updated}))
}

func TestDiagnosticMessageUpdatesAndRecovery(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(fmt.Sprint(permanent), func(t *testing.T) {
			r, fake, manager, deployment := readyReconciler(t)
			req := ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}}
			_, err := r.Reconcile(context.Background(), req)
			require.NoError(t, err)
			image := deployment.Spec.Template.Spec.Containers[0].Image
			message := "first failure"
			fake.PatchCalls(func(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
				if message == "" {
					return nil
				}
				if permanent {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, operandName, fmt.Errorf("%s", message))
				}
				return fmt.Errorf("%s", message)
			})
			_, err = r.Reconcile(context.Background(), req)
			require.NoError(t, err)
			diagnosticType := v1alpha1.Ready
			if permanent {
				diagnosticType = v1alpha1.Degraded
			}
			first := manager.Status.GetCondition(diagnosticType).DeepCopy()
			require.Contains(t, first.Message, message)
			writes := fake.StatusUpdateCallCount()
			message = "different failure with the same reason"
			_, err = r.Reconcile(context.Background(), req)
			require.NoError(t, err)
			current := manager.Status.GetCondition(diagnosticType)
			require.Equal(t, first.Status, current.Status)
			require.Equal(t, first.Reason, current.Reason)
			require.Equal(t, first.LastTransitionTime, current.LastTransitionTime)
			require.Contains(t, current.Message, message)
			require.Equal(t, writes+1, fake.StatusUpdateCallCount())
			_, err = r.Reconcile(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, writes+1, fake.StatusUpdateCallCount(), "identical diagnostics do not cause status loops")
			require.Equal(t, image, manager.Status.ApproverPolicyImage, "keep the last observed image when apply fails")
			message = ""
			manager.Generation++
			_, err = r.Reconcile(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, metav1.ConditionTrue, manager.Status.GetCondition(v1alpha1.Ready).Status)
			require.Equal(t, metav1.ConditionFalse, manager.Status.GetCondition(v1alpha1.Degraded).Status)
			for _, condition := range manager.Status.Conditions {
				require.Equal(t, manager.Generation, condition.ObservedGeneration)
				require.NotContains(t, condition.Message, "failure")
			}
		})
	}
}

func TestDiagnosticStatusWriteRecoveryAndReplacement(t *testing.T) {
	r, fake, manager, _ := readyReconciler(t)
	write := fake.StatusUpdateStub
	failed := true
	fake.StatusUpdateCalls(func(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
		if failed {
			return fmt.Errorf("status persistence unavailable")
		}
		return write(ctx, obj, opts...)
	})
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
	require.ErrorContains(t, err, "status persistence unavailable")
	require.Empty(t, manager.Status.Conditions, "unpersisted readiness must not be advertised")
	failed = false
	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: managerName}})
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionTrue, manager.Status.GetCondition(v1alpha1.Ready).Status)
	old := manager.DeepCopy()
	manager.UID = "replacement"
	writes := fake.StatusUpdateCallCount()
	require.ErrorContains(t, r.updateStatus(context.Background(), old), "changed during reconciliation")
	require.Equal(t, writes, fake.StatusUpdateCallCount(), "stale diagnostics cannot update a replacement manager")
}
