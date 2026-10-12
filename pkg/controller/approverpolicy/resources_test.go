package approverpolicy

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func testManager() *v1alpha1.ApproverPolicyManager {
	return &v1alpha1.ApproverPolicyManager{ObjectMeta: metav1.ObjectMeta{Name: managerName, UID: types.UID("manager-uid"), Generation: 2}}
}

func testResources(t *testing.T) []*unstructured.Unstructured {
	t.Helper()
	t.Setenv(imageEnv, "quay.io/jetstack/cert-manager-approver-policy:v0.27.0")
	objects, err := desiredResources(testManager())
	require.NoError(t, err)
	return objects
}

func TestDesiredResources(t *testing.T) {
	for level := int32(0); level <= 5; level++ {
		for _, format := range []string{"", "text", "json"} {
			t.Run(fmt.Sprintf("level%d-format%s", level, format), func(t *testing.T) {
				t.Setenv(imageEnv, "example.test/custom:version")
				manager := testManager()
				manager.Spec.ApproverPolicyConfig = v1alpha1.ApproverPolicyConfig{LogLevel: level, LogFormat: format}
				objects, err := desiredResources(manager)
				require.NoError(t, err)
				require.Len(t, objects, 10)
				for _, obj := range objects {
					require.Equal(t, RequestEnqueueLabelValue, obj.GetLabels()[common.ManagedResourceLabelKey])
					require.Equal(t, manager.UID, metav1.GetControllerOf(obj).UID)
					require.NotEqual(t, "Namespace", obj.GetKind())
					switch obj.GetKind() {
					case "ClusterRole":
						rules, _, err := unstructured.NestedSlice(obj.Object, "rules")
						require.NoError(t, err)
						for _, item := range rules {
							rule := item.(map[string]interface{})
							resources, _, err := unstructured.NestedStringSlice(rule, "resources")
							require.NoError(t, err)
							if len(resources) == 1 && resources[0] == "signers" {
								names, _, err := unstructured.NestedStringSlice(rule, "resourceNames")
								require.NoError(t, err)
								require.ElementsMatch(t, []string{"issuers.cert-manager.io/*", "clusterissuers.cert-manager.io/*"}, names)
							}
						}
					case "Secret":
						require.NotContains(t, obj.Object, "data")
						require.NotContains(t, obj.Object, "stringData")
					case "ValidatingWebhookConfiguration":
						webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
						require.NoError(t, err)
						require.NotContains(t, webhooks[0].(map[string]interface{})["clientConfig"], "caBundle")
						require.Equal(t, "cert-manager/cert-manager-approver-policy-tls", obj.GetAnnotations()["cert-manager.io/inject-ca-from-secret"])
					case "Deployment":
						containers, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
						require.NoError(t, err)
						container := containers[0].(map[string]interface{})
						require.Equal(t, "example.test/custom:version", container["image"])
						args, _, err := unstructured.NestedStringSlice(container, "args")
						require.NoError(t, err)
						wantLevel, wantFormat := level, format
						if wantLevel == 0 {
							wantLevel = 1
						}
						if wantFormat == "" {
							wantFormat = "text"
						}
						require.Contains(t, args, fmt.Sprintf("--log-level=%d", wantLevel))
						require.Contains(t, args, "--log-format="+wantFormat)
						require.Contains(t, args, "--webhook-ca-secret-name=cert-manager-approver-policy-tls")
						require.Contains(t, args, "--webhook-ca-secret-namespace=cert-manager")
						require.Equal(t, map[string]interface{}{"allowPrivilegeEscalation": false, "capabilities": map[string]interface{}{"drop": []interface{}{"ALL"}}, "readOnlyRootFilesystem": true}, container["securityContext"])
						require.NotNil(t, container["readinessProbe"])
					}
				}
			})
		}
	}
}

func TestDesiredResourcesRejectInvalidConfiguration(t *testing.T) {
	t.Setenv(imageEnv, "")
	_, err := desiredResources(testManager())
	require.ErrorContains(t, err, imageEnv)
	t.Setenv(imageEnv, "example.test/approver-policy:test")
	for _, config := range []v1alpha1.ApproverPolicyConfig{{LogLevel: -1}, {LogLevel: 6}, {LogFormat: "yaml"}} {
		manager := testManager()
		manager.Spec.ApproverPolicyConfig = config
		_, err := desiredResources(manager)
		require.Error(t, err)
	}
}

func TestApplyResourcesUsesSSAAndPreservesUnmanagedFields(t *testing.T) {
	for _, desired := range testResources(t) {
		t.Run(desired.GetKind()+desired.GetName(), func(t *testing.T) {
			fake := &fakes.FakeCtrlClient{}
			r := &Reconciler{CtrlClient: fake}
			require.NoError(t, r.applyResource(context.Background(), desired))
			require.Equal(t, 1, fake.PatchCallCount())
			_, applied, patch, opts := fake.PatchArgsForCall(0)
			require.Equal(t, types.ApplyPatchType, patch.Type())
			options := (&client.PatchOptions{}).ApplyOptions(opts)
			require.Equal(t, fieldOwner, options.FieldManager)
			require.NotNil(t, options.Force)
			require.True(t, *options.Force)
			require.Equal(t, 0, fake.CreateCallCount())
			require.Equal(t, 0, fake.UpdateCallCount())
			require.Equal(t, desired.Object, applied.(*unstructured.Unstructured).Object)
			existing := desired.DeepCopy()
			_ = unstructured.SetNestedField(existing.Object, "server-default", "metadata", "annotations", "unrelated")
			switch existing.GetKind() {
			case "Secret":
				existing.Object["data"] = map[string]interface{}{"tls.crt": "populated", "tls.key": "retained"}
			case "ValidatingWebhookConfiguration":
				webhooks := existing.Object["webhooks"].([]interface{})
				webhooks[0].(map[string]interface{})["clientConfig"].(map[string]interface{})["caBundle"] = "injected"
			case "Service":
				_ = unstructured.SetNestedField(existing.Object, "10.0.0.1", "spec", "clusterIP")
			case "Deployment":
				existing.Object["status"] = map[string]interface{}{"availableReplicas": int64(1)}
				unstructured.RemoveNestedField(existing.Object, "spec", "template", "spec", "hostNetwork")
			}
			fake.ExistsCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) (bool, error) {
				existing.DeepCopyInto(obj.(*unstructured.Unstructured))
				return true, nil
			})
			require.NoError(t, r.applyResource(context.Background(), desired))
			require.Equal(t, 1, fake.PatchCallCount(), "server-owned fields must not trigger apply")
			labels := existing.GetLabels()
			delete(labels, common.ManagedResourceLabelKey)
			existing.SetLabels(labels)
			require.NoError(t, r.applyResource(context.Background(), desired))
			require.Equal(t, 2, fake.PatchCallCount(), "managed metadata drift must be repaired")
			_, applied, _, _ = fake.PatchArgsForCall(1)
			require.Equal(t, desired.Object, applied.(*unstructured.Unstructured).Object, "never copy injected CA or Secret data into SSA payload")
		})
	}
}

func TestApplyResourceFailures(t *testing.T) {
	desired := testResources(t)[0]
	for _, tc := range []struct {
		name      string
		err       error
		permanent bool
	}{
		{"forbidden", apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, operandName, fmt.Errorf("denied")), true},
		{"timeout", apierrors.NewTimeoutError("retry", 1), false},
		{"conflict", apierrors.NewConflict(schema.GroupResource{Resource: "serviceaccounts"}, operandName, fmt.Errorf("conflict")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakes.FakeCtrlClient{}
			r := &Reconciler{CtrlClient: fake}
			fake.ExistsReturns(false, tc.err)
			require.Equal(t, tc.permanent, common.IsIrrecoverableError(r.applyResource(context.Background(), desired)))
			require.Zero(t, fake.PatchCallCount())
			fake.ExistsReturns(false, nil)
			fake.PatchReturns(tc.err)
			require.Equal(t, tc.permanent, common.IsIrrecoverableError(r.applyResource(context.Background(), desired)))
		})
	}
	fake := &fakes.FakeCtrlClient{}
	fake.ExistsCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) (bool, error) {
		x := desired.DeepCopy()
		refs := x.GetOwnerReferences()
		refs[0].UID = "someone-else"
		x.SetOwnerReferences(refs)
		x.DeepCopyInto(obj.(*unstructured.Unstructured))
		return true, nil
	})
	require.True(t, common.IsIrrecoverableError((&Reconciler{CtrlClient: fake}).applyResource(context.Background(), desired)))
	require.Zero(t, fake.PatchCallCount())
}
