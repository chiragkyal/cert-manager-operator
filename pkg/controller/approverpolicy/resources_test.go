package approverpolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
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
	for level := range int32(6) {
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
								require.Empty(t, names, "omitted signer scope is unrestricted")
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

func configuredManager() *v1alpha1.ApproverPolicyManager {
	m := testManager()
	m.Spec.ApproverPolicyConfig = v1alpha1.ApproverPolicyConfig{
		LogLevel: 4, LogFormat: "json",
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
		},
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{{Weight: 50,
				Preference: corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "example.com/pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"certificates"}}}}}},
		}},
		Tolerations:  []corev1.Toleration{{Key: "example.com/dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
		NodeSelector: map[string]string{"example.com/pool": "certificates"},
	}
	m.Spec.ControllerConfig = v1alpha1.ApproverPolicyControllerConfig{
		Labels: map[string]string{"example.com/team": "platform", "app": "wrong", "app.kubernetes.io/name": "wrong"},
		Annotations: map[string]string{"example.com/owner": "platform", "cert-manager.io/inject-ca-from-secret": "wrong",
			"cert-manager.io/allow-direct-injection": "false", desiredStateAnnotation: "wrong"},
	}
	return m
}

func TestConfigurationOverlays(t *testing.T) {
	t.Setenv(imageEnv, "example.test/approver-policy:test")
	for _, tc := range []struct {
		name string
		m    *v1alpha1.ApproverPolicyManager
	}{
		{"omitted", testManager()},
		{"empty", &v1alpha1.ApproverPolicyManager{Spec: v1alpha1.ApproverPolicyManagerSpec{ApproverPolicyConfig: v1alpha1.ApproverPolicyConfig{
			Affinity: &corev1.Affinity{}, Tolerations: []corev1.Toleration{}, NodeSelector: map[string]string{},
		}}}},
		{"configured", configuredManager()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.m.DeepCopy()
			objects, err := desiredResources(tc.m)
			require.NoError(t, err)
			require.Equal(t, before, tc.m, "constructing resources must not mutate the CR")
			for _, obj := range objects {
				require.Equal(t, operandName, obj.GetLabels()["app"])
				require.Equal(t, operandName, obj.GetLabels()["app.kubernetes.io/name"])
				if tc.name == "configured" {
					require.Equal(t, "platform", obj.GetLabels()["example.com/team"])
					require.Equal(t, "platform", obj.GetAnnotations()["example.com/owner"])
				}
				require.Len(t, obj.GetAnnotations()[desiredStateAnnotation], 64)
				switch obj.GetKind() {
				case "Deployment":
					d := &appsv1.Deployment{}
					require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, d))
					require.Equal(t, map[string]string{"app": operandName}, d.Spec.Selector.MatchLabels)
					require.Equal(t, operandName, d.Spec.Template.Labels["app"])
					require.Equal(t, "linux", d.Spec.Template.Spec.NodeSelector["kubernetes.io/os"])
					require.Equal(t, tc.m.Spec.ApproverPolicyConfig.Resources, d.Spec.Template.Spec.Containers[0].Resources)
					require.Equal(t, tc.m.Spec.ApproverPolicyConfig.Affinity, d.Spec.Template.Spec.Affinity)
					require.EqualValues(t, len(tc.m.Spec.ApproverPolicyConfig.Tolerations), len(d.Spec.Template.Spec.Tolerations))
					if tc.name == "configured" {
						require.Equal(t, tc.m.Spec.ApproverPolicyConfig.Tolerations, d.Spec.Template.Spec.Tolerations)
						require.Equal(t, "certificates", d.Spec.Template.Spec.NodeSelector["example.com/pool"])
						require.Equal(t, "platform", d.Spec.Template.Labels["example.com/team"])
						require.Equal(t, "platform", d.Spec.Template.Annotations["example.com/owner"])
					}
				case "Secret":
					require.Equal(t, "true", obj.GetAnnotations()["cert-manager.io/allow-direct-injection"])
				case "ValidatingWebhookConfiguration":
					require.Equal(t, operandNamespace+"/"+operandName+"-tls", obj.GetAnnotations()["cert-manager.io/inject-ca-from-secret"])
				}
			}
		})
	}
}

func TestConfigurationValidation(t *testing.T) {
	t.Setenv(imageEnv, "example.test/approver-policy:test")
	for _, tc := range []struct {
		name, field string
		mutate      func(*v1alpha1.ApproverPolicyManager)
	}{
		{"negative resources", "resources", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("-1")}
		}},
		{"requests above limits", "resources", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")}
		}},
		{"invalid affinity", "affinity", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0].Weight = 101
		}},
		{"invalid toleration", "tolerations", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.Tolerations[0].Operator = "Invalid"
		}},
		{"invalid node selector", "nodeSelector", func(m *v1alpha1.ApproverPolicyManager) {
			m.Spec.ApproverPolicyConfig.NodeSelector["invalid key"] = "value"
		}},
		{"invalid label", "labels", func(m *v1alpha1.ApproverPolicyManager) { m.Spec.ControllerConfig.Labels["invalid key"] = "value" }},
		{"invalid annotation", "annotations", func(m *v1alpha1.ApproverPolicyManager) { m.Spec.ControllerConfig.Annotations["invalid key"] = "value" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := configuredManager()
			tc.mutate(m)
			objects, err := desiredResources(m)
			require.ErrorContains(t, err, tc.field)
			require.Nil(t, objects)
		})
	}
	for _, tc := range []struct {
		field string
		limit int
	}{{"tolerations", 50}, {"nodeSelector", 50}, {"labels", 20}, {"annotations", 20}} {
		for _, count := range []int{tc.limit, tc.limit + 1} {
			t.Run(fmt.Sprintf("%s/%d", tc.field, count), func(t *testing.T) {
				m := testManager()
				entries := map[string]string{}
				for i := range count {
					key := fmt.Sprintf("example.com/key-%d", i)
					entries[key] = "value"
					if tc.field == "tolerations" {
						m.Spec.ApproverPolicyConfig.Tolerations = append(m.Spec.ApproverPolicyConfig.Tolerations, corev1.Toleration{Key: key, Operator: corev1.TolerationOpExists})
					}
				}
				switch tc.field {
				case "nodeSelector":
					m.Spec.ApproverPolicyConfig.NodeSelector = entries
				case "labels":
					m.Spec.ControllerConfig.Labels = entries
				case "annotations":
					m.Spec.ControllerConfig.Annotations = entries
				}
				_, err := desiredResources(m)
				if count > tc.limit {
					require.ErrorContains(t, err, tc.field)
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}

// The client's field-managed tracker exercises typed Kubernetes SSA ownership,
// including pruning. Call-count fakes alone cannot prove removal semantics.
func TestConfigurationRemovalWithSSA(t *testing.T) {
	t.Setenv(imageEnv, "example.test/approver-policy:test")
	ctx := context.Background()
	tracker := kubefake.NewClientset().Tracker()
	get := func(key client.ObjectKey, obj *unstructured.Unstructured) error {
		gvr, _ := meta.UnsafeGuessKindToResource(obj.GroupVersionKind())
		stored, err := tracker.Get(gvr, key.Namespace, key.Name)
		if err != nil {
			return err
		}
		obj.Object, err = runtime.DefaultUnstructuredConverter.ToUnstructured(stored)
		return err
	}
	patch := func(_ context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		require.Equal(t, types.ApplyPatchType, patch.Type())
		gvr, _ := meta.UnsafeGuessKindToResource(obj.GetObjectKind().GroupVersionKind())
		options := (&client.PatchOptions{}).ApplyOptions(opts)
		return tracker.Apply(gvr, obj, obj.GetNamespace(), *options.AsPatchOptions())
	}
	fake := &fakes.FakeCtrlClient{}
	fake.ExistsCalls(func(_ context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
		err := get(key, obj.(*unstructured.Unstructured))
		return err == nil, client.IgnoreNotFound(err)
	})
	fake.PatchCalls(patch)
	r := &Reconciler{CtrlClient: fake}
	configured, err := desiredResources(configuredManager())
	require.NoError(t, err)
	defaults, err := desiredResources(testManager())
	require.NoError(t, err)
	for i, old := range configured {
		t.Run(old.GetKind()+old.GetName(), func(t *testing.T) {
			require.NoError(t, r.applyResource(ctx, old))
			unmanaged := &unstructured.Unstructured{}
			unmanaged.SetGroupVersionKind(old.GroupVersionKind())
			unmanaged.SetName(old.GetName())
			unmanaged.SetNamespace(old.GetNamespace())
			unmanaged.SetAnnotations(map[string]string{"example.com/external": "keep"})
			if old.GetKind() == "Secret" {
				unmanaged.Object["data"] = map[string]interface{}{"tls.crt": "cHJlc2VydmU="}
			}
			//nolint:staticcheck // Exercise the same shared SSA Patch contract as production.
			require.NoError(t, patch(ctx, unmanaged, client.Apply, client.FieldOwner("external")))
			desired := defaults[i]
			require.NotEqual(t, old.GetAnnotations()[desiredStateAnnotation], desired.GetAnnotations()[desiredStateAnnotation])
			calls := fake.PatchCallCount()
			require.NoError(t, r.applyResource(ctx, desired))
			require.Equal(t, calls+1, fake.PatchCallCount(), "removed settings must trigger SSA")
			got := &unstructured.Unstructured{}
			got.SetGroupVersionKind(desired.GroupVersionKind())
			require.NoError(t, get(client.ObjectKeyFromObject(desired), got))
			require.NotContains(t, got.GetLabels(), "example.com/team")
			require.NotContains(t, got.GetAnnotations(), "example.com/owner")
			require.Equal(t, "keep", got.GetAnnotations()["example.com/external"])
			if got.GetKind() == "Deployment" {
				d := &appsv1.Deployment{}
				require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object, d))
				require.Nil(t, d.Spec.Template.Spec.Affinity)
				require.Empty(t, d.Spec.Template.Spec.Tolerations)
				require.Empty(t, d.Spec.Template.Spec.Containers[0].Resources.Limits)
				require.Empty(t, d.Spec.Template.Spec.Containers[0].Resources.Requests)
				require.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, d.Spec.Template.Spec.NodeSelector)
				require.NotContains(t, d.Spec.Template.Labels, "example.com/team")
				require.NotContains(t, d.Spec.Template.Annotations, "example.com/owner")
			}
			if got.GetKind() == "Secret" {
				require.Equal(t, "cHJlc2VydmU=", got.Object["data"].(map[string]interface{})["tls.crt"])
			}
			require.NoError(t, r.applyResource(ctx, desired))
			require.Equal(t, calls+1, fake.PatchCallCount(), "converged settings must not reapply")
		})
	}
}

func signerRole(t *testing.T, objects []*unstructured.Unstructured) *unstructured.Unstructured {
	t.Helper()
	for _, obj := range objects {
		if obj.GetKind() == "ClusterRole" && obj.GetName() == operandName {
			return obj
		}
	}
	t.Fatal("approver-policy ClusterRole not found")
	return nil
}

func TestSignerScopeConfiguration(t *testing.T) {
	t.Setenv(imageEnv, "example.test/approver-policy:test")
	fifty := make([]string, 50)
	for i := range fifty {
		fifty[i] = fmt.Sprintf("issuers.example.test/%d", i)
	}
	for _, tc := range []struct {
		name    string
		signers []string
		invalid bool
	}{
		{"omitted", nil, false},
		{"empty", []string{}, false},
		{"explicit built-in and external", []string{"issuers.cert-manager.io/*", "googlecasissuers.cas-issuer.jetstack.io/*"}, false},
		{"one character", []string{"a"}, false},
		{"825 characters", []string{strings.Repeat("a", 825)}, false},
		{"825 Unicode characters", []string{strings.Repeat("é", 825)}, false},
		{"50 entries", fifty, false},
		{"51 entries", append(slices.Clone(fifty), "issuers.example.test/50"), true},
		{"duplicate", []string{"issuers.cert-manager.io/*", "issuers.cert-manager.io/*"}, true},
		{"empty entry", []string{""}, true},
		{"826 characters", []string{strings.Repeat("a", 826)}, true},
		{"826 Unicode characters", []string{strings.Repeat("é", 826)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testManager()
			m.Spec.ApproverPolicyConfig.ApproveSignerNames = tc.signers
			before := m.DeepCopy()
			objects, err := desiredResources(m)
			require.Equal(t, before, m, "resource construction must not mutate the configured set")
			if tc.invalid {
				require.ErrorContains(t, err, "approveSignerNames")
				require.Nil(t, objects)
				return
			}
			require.NoError(t, err)
			defaults, err := desiredResources(testManager())
			require.NoError(t, err)
			role := &rbacv1.ClusterRole{}
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(signerRole(t, objects).Object, role))
			found := false
			for _, rule := range role.Rules {
				if slices.Equal(rule.APIGroups, []string{"cert-manager.io"}) && slices.Equal(rule.Resources, []string{"signers"}) {
					found = true
					require.Equal(t, []string{"approve"}, rule.Verbs)
					want := slices.Clone(tc.signers)
					slices.Sort(want)
					require.EqualValues(t, len(want), len(rule.ResourceNames))
					if len(want) > 0 {
						require.Equal(t, want, rule.ResourceNames)
					}
				}
			}
			require.True(t, found)
			for i, obj := range objects {
				require.NotEqual(t, "Namespace", obj.GetKind())
				require.NotEqual(t, "CertificateRequestPolicy", obj.GetKind())
				if obj.GetKind() != "ClusterRole" {
					require.Equal(t, defaults[i], obj, "signer scope changes only the approval role")
				}
			}
		})
	}
}

func TestSignerScopeChangesWithSSA(t *testing.T) {
	t.Setenv(imageEnv, "example.test/approver-policy:test")
	ctx := context.Background()
	tracker := kubefake.NewClientset().Tracker()
	gvr := rbacv1.SchemeGroupVersion.WithResource("clusterroles")
	fake := &fakes.FakeCtrlClient{}
	fake.ExistsCalls(func(_ context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
		stored, err := tracker.Get(gvr, "", key.Name)
		if err != nil {
			return false, client.IgnoreNotFound(err)
		}
		obj.(*unstructured.Unstructured).Object, err = runtime.DefaultUnstructuredConverter.ToUnstructured(stored)
		return true, err
	})
	fake.PatchCalls(func(_ context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		require.Equal(t, types.ApplyPatchType, patch.Type())
		options := (&client.PatchOptions{}).ApplyOptions(opts)
		require.Equal(t, fieldOwner, options.FieldManager)
		require.NotNil(t, options.Force)
		require.True(t, *options.Force)
		return tracker.Apply(gvr, obj, "", *options.AsPatchOptions())
	})
	r := &Reconciler{CtrlClient: fake}
	base := &rbacv1.ClusterRole{}
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(signerRole(t, testResources(t)).Object, base))
	a, b := "issuers.cert-manager.io/*", "googlecasissuers.cas-issuer.jetstack.io/*"
	for _, tc := range []struct {
		name    string
		signers []string
		patches int
	}{
		{"unrestricted", nil, 1},
		{"empty also unrestricted", []string{}, 1},
		{"restrict to external", []string{b}, 2},
		{"expand", []string{a, b}, 3},
		{"reorder is no-op", []string{b, a}, 3},
		{"contract", []string{a}, 4},
		{"clear to empty", []string{}, 5},
		{"restrict again", []string{b}, 6},
		{"remove optional scope", nil, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testManager()
			m.Spec.ApproverPolicyConfig.ApproveSignerNames = tc.signers
			objects, err := desiredResources(m)
			require.NoError(t, err)
			desired := signerRole(t, objects)
			require.NoError(t, r.applyResource(ctx, desired))
			require.Equal(t, tc.patches, fake.PatchCallCount())
			if tc.name == "unrestricted" {
				// A metadata-only apply must omit rules entirely; the typed
				// ClusterRole serializes its required rules field as null.
				external := &unstructured.Unstructured{}
				external.SetGroupVersionKind(desired.GroupVersionKind())
				external.SetName(operandName)
				external.SetAnnotations(map[string]string{"example.com/external": "keep"})
				require.NoError(t, tracker.Apply(gvr, external, "", metav1.PatchOptions{FieldManager: "external"}))
			}
			stored, err := tracker.Get(gvr, "", operandName)
			require.NoError(t, err)
			u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(stored)
			require.NoError(t, err)
			got := &rbacv1.ClusterRole{}
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(u, got))
			require.Equal(t, "keep", got.Annotations["example.com/external"])
			want := base.DeepCopy()
			for i := range want.Rules {
				if slices.Equal(want.Rules[i].Resources, []string{"signers"}) {
					want.Rules[i].ResourceNames = slices.Clone(tc.signers)
					slices.Sort(want.Rules[i].ResourceNames)
					if len(tc.signers) == 0 {
						want.Rules[i].ResourceNames = nil
					}
				}
			}
			require.Equal(t, want.Rules, got.Rules, "scope updates must preserve every unrelated permission")
			require.NoError(t, r.applyResource(ctx, desired))
			require.Equal(t, tc.patches, fake.PatchCallCount(), "converged scope must not reapply")
		})
	}
	require.Zero(t, fake.CreateCallCount())
	require.Zero(t, fake.UpdateCallCount())
	require.Zero(t, fake.DeleteCallCount())
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
