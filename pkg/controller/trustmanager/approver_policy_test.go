package trustmanager

import (
	"context"
	"fmt"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/controller/common/fakes"
)

func integrationTrustManager() *v1alpha1.TrustManager {
	tm := testTrustManager().Build()
	tm.UID = "trust-manager-uid"
	return tm
}

func integrationResources(t *testing.T, tm *v1alpha1.TrustManager) []*unstructured.Unstructured {
	t.Helper()
	objects, err := approverPolicyResources(tm)
	require.NoError(t, err)
	return objects
}

func TestApproverPolicyResourceIdentity(t *testing.T) {
	tm := integrationTrustManager()
	tm.Spec.TrustManagerConfig.TrustNamespace = "custom-trust-namespace"
	tm.Spec.ControllerConfig.Annotations = map[string]string{approverPolicyOwnerAnnotation: "forged", approverPolicyDesiredAnnotation: "forged", "user": "kept"}
	objects := integrationResources(t, tm)
	require.Len(t, objects, 3)
	for _, obj := range objects {
		require.Empty(t, obj.GetNamespace())
		require.Empty(t, obj.GetOwnerReferences(), "retain the existing warn-only TrustManager deletion contract")
		require.Equal(t, string(tm.UID), obj.GetAnnotations()[approverPolicyOwnerAnnotation])
		require.NotEqual(t, "forged", obj.GetAnnotations()[approverPolicyDesiredAnnotation])
		require.Equal(t, "kept", obj.GetAnnotations()["user"])
		require.Equal(t, RequestEnqueueLabelValue, obj.GetLabels()[common.ManagedResourceLabelKey])
	}
	cert := getCertificateObject(getResourceLabels(tm), getResourceAnnotations(tm))
	policy := objects[0]
	require.Equal(t, approverPolicyName, policy.GetName())
	commonName, _, err := unstructured.NestedString(policy.Object, "spec", "allowed", "commonName", "value")
	require.NoError(t, err)
	require.Equal(t, cert.Spec.CommonName, commonName)
	dnsNames, _, err := unstructured.NestedStringSlice(policy.Object, "spec", "allowed", "dnsNames", "values")
	require.NoError(t, err)
	require.Equal(t, cert.Spec.DNSNames, dnsNames)
	namespaces, _, err := unstructured.NestedStringSlice(policy.Object, "spec", "selector", "namespace", "matchNames")
	require.NoError(t, err)
	require.Equal(t, []string{cert.Namespace}, namespaces)
	issuerRef, _, err := unstructured.NestedStringMap(policy.Object, "spec", "selector", "issuerRef")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"name": cert.Spec.IssuerRef.Name, "kind": cert.Spec.IssuerRef.Kind, "group": cert.Spec.IssuerRef.Group}, issuerRef)
	usages, _, err := unstructured.NestedStringSlice(policy.Object, "spec", "allowed", "usages")
	require.NoError(t, err)
	defaultUsages := make([]string, 0, len(certmanagerv1.DefaultKeyUsages()))
	for _, usage := range certmanagerv1.DefaultKeyUsages() {
		defaultUsages = append(defaultUsages, string(usage))
	}
	require.Equal(t, defaultUsages, usages)
	role := &rbacv1.ClusterRole{}
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(objects[1].Object, role))
	require.Equal(t, []rbacv1.PolicyRule{{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{approverPolicyName}}}, role.Rules)
	binding := &rbacv1.ClusterRoleBinding{}
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(objects[2].Object, binding))
	require.Equal(t, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name}, binding.RoleRef)
	require.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "cert-manager", Namespace: cert.Namespace}}, binding.Subjects)
}

func TestApproverPolicyManagementModes(t *testing.T) {
	for _, state := range []v1alpha1.ApproverPolicyManagementState{"", v1alpha1.ApproverPolicyManagementStateManaged, v1alpha1.ApproverPolicyManagementStateUnmanaged} {
		for _, completion := range []string{"true", "false", "absent"} {
			t.Run(string(state)+"/"+completion, func(t *testing.T) {
				r := testReconciler(t)
				fake := &fakes.FakeCtrlClient{}
				r.CtrlClient = fake
				tm := integrationTrustManager()
				tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState = state
				before := tm.DeepCopy()
				fake.GetCalls(func(_ context.Context, key client.ObjectKey, obj client.Object) error {
					require.Equal(t, "cluster", key.Name)
					if completion == "absent" {
						return apierrors.NewNotFound(v1alpha1.Resource("certmanagers"), key.Name)
					}
					obj.(*v1alpha1.CertManager).Status.AutoApproverDisabled = completion == "true"
					return nil
				})
				require.NoError(t, r.reconcileApproverPolicy(tm))
				if state == v1alpha1.ApproverPolicyManagementStateUnmanaged {
					require.Zero(t, fake.GetCallCount())
					require.Zero(t, fake.ExistsCallCount())
					require.Zero(t, fake.PatchCallCount())
				} else {
					require.Equal(t, 1, fake.GetCallCount())
					require.Equal(t, 3, fake.ExistsCallCount())
					if completion == "true" {
						require.Equal(t, 3, fake.PatchCallCount())
					} else {
						require.Zero(t, fake.PatchCallCount())
					}
				}
				require.Zero(t, fake.DeleteCallCount())
				require.Zero(t, fake.StatusUpdateCallCount())
				require.Equal(t, before, tm)
			})
		}
	}
	r := testReconciler(t)
	fake := &fakes.FakeCtrlClient{}
	r.CtrlClient = fake
	tm := integrationTrustManager()
	tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState = "Removed"
	require.True(t, common.IsIrrecoverableError(r.reconcileApproverPolicy(tm)))
	require.Zero(t, fake.GetCallCount())
}

func TestApproverPolicyInstallationOrdersAndTransitions(t *testing.T) {
	for _, initiallyDisabled := range []bool{false, true} {
		t.Run(fmt.Sprint(initiallyDisabled), func(t *testing.T) {
			r := testReconciler(t)
			fake := &fakes.FakeCtrlClient{}
			r.CtrlClient = fake
			tm := integrationTrustManager()
			disabled := initiallyDisabled
			resources := map[string]*unstructured.Unstructured{}
			fake.GetCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) error {
				obj.(*v1alpha1.CertManager).Status.AutoApproverDisabled = disabled
				return nil
			})
			fake.ExistsCalls(func(_ context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
				if existing := resources[key.Name]; existing != nil {
					existing.DeepCopyInto(obj.(*unstructured.Unstructured))
					return true, nil
				}
				return false, nil
			})
			fake.PatchCalls(func(_ context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				require.Equal(t, types.ApplyPatchType, patch.Type())
				options := &client.PatchOptions{}
				for _, opt := range opts {
					opt.ApplyToPatch(options)
				}
				require.Equal(t, fieldOwner, options.FieldManager)
				require.NotNil(t, options.Force)
				require.True(t, *options.Force)
				stored := obj.(*unstructured.Unstructured).DeepCopy()
				stored.SetUID(types.UID("uid-" + obj.GetName()))
				stored.SetResourceVersion("7")
				resources[obj.GetName()] = stored
				return nil
			})
			fake.DeleteCalls(func(_ context.Context, obj client.Object, opts ...client.DeleteOption) error {
				options := &client.DeleteOptions{}
				for _, opt := range opts {
					opt.ApplyToDelete(options)
				}
				require.Equal(t, obj.GetUID(), *options.Preconditions.UID)
				require.Equal(t, obj.GetResourceVersion(), *options.Preconditions.ResourceVersion)
				delete(resources, obj.GetName())
				return nil
			})
			require.NoError(t, r.reconcileApproverPolicy(tm))
			if !initiallyDisabled {
				require.Empty(t, resources)
				disabled = true
				require.NoError(t, r.reconcileApproverPolicy(tm))
			}
			require.Len(t, resources, 3)
			require.NoError(t, r.reconcileApproverPolicy(tm))
			require.Equal(t, 3, fake.PatchCallCount(), "converged resources must not be reapplied")
			tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState = v1alpha1.ApproverPolicyManagementStateUnmanaged
			disabled = false
			reads := fake.GetCallCount() + fake.ExistsCallCount()
			require.NoError(t, r.reconcileApproverPolicy(tm))
			require.Equal(t, reads, fake.GetCallCount()+fake.ExistsCallCount())
			require.Len(t, resources, 3)
			tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState = v1alpha1.ApproverPolicyManagementStateManaged
			require.NoError(t, r.reconcileApproverPolicy(tm))
			require.Empty(t, resources)
			require.Equal(t, 3, fake.DeleteCallCount())
			_, firstDeleted, _ := fake.DeleteArgsForCall(0)
			require.Equal(t, approverPolicyBindingName, firstDeleted.GetName())
			disabled = true
			require.NoError(t, r.reconcileApproverPolicy(tm))
			require.Len(t, resources, 3)
			require.Zero(t, fake.CreateCallCount())
			require.Zero(t, fake.UpdateCallCount())
			require.Zero(t, fake.UpdateWithRetryCallCount())
		})
	}
}

func TestApproverPolicyOwnershipAndDrift(t *testing.T) {
	tm := integrationTrustManager()
	for _, desired := range integrationResources(t, tm) {
		for _, scenario := range []string{"foreign", "old-owner", "owned", "label-drift", "body-drift", "foreign-metadata", "config-removal"} {
			t.Run(desired.GetKind()+"/"+scenario, func(t *testing.T) {
				r := testReconciler(t)
				fake := &fakes.FakeCtrlClient{}
				r.CtrlClient = fake
				existing := desired.DeepCopy()
				existing.SetUID("object-uid")
				existing.SetResourceVersion("42")
				switch scenario {
				case "foreign":
					existing.SetAnnotations(nil)
				case "old-owner":
					annotations := existing.GetAnnotations()
					annotations[approverPolicyOwnerAnnotation] = "old"
					existing.SetAnnotations(annotations)
				case "label-drift":
					existing.SetLabels(nil)
				case "body-drift":
					for _, field := range []string{"spec", "rules", "roleRef", "subjects"} {
						delete(existing.Object, field)
					}
				case "foreign-metadata":
					labels := existing.GetLabels()
					labels["other"] = "keep"
					existing.SetLabels(labels)
					existing.Object["status"] = map[string]interface{}{"ready": true}
				case "config-removal":
					oldTM := tm.DeepCopy()
					oldTM.Spec.ControllerConfig.Annotations = map[string]string{"removed": "value"}
					for _, old := range integrationResources(t, oldTM) {
						if old.GetName() == desired.GetName() {
							existing.SetAnnotations(old.GetAnnotations())
						}
					}
				}
				fake.ExistsCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) (bool, error) {
					existing.DeepCopyInto(obj.(*unstructured.Unstructured))
					return true, nil
				})
				err := r.applyApproverPolicyResource(tm, desired.DeepCopy())
				if scenario == "foreign" || scenario == "old-owner" {
					require.ErrorContains(t, err, "refusing to adopt")
					require.Zero(t, fake.PatchCallCount())
					require.NoError(t, r.removeApproverPolicyResource(tm, desired))
					require.Zero(t, fake.DeleteCallCount())
				} else {
					require.NoError(t, err)
					if scenario == "owned" || scenario == "foreign-metadata" {
						require.Zero(t, fake.PatchCallCount())
					} else {
						require.Equal(t, 1, fake.PatchCallCount())
						_, patched, _, _ := fake.PatchArgsForCall(0)
						require.Equal(t, "42", patched.GetResourceVersion())
					}
				}
			})
		}
	}
}

func TestApproverPolicyFailuresPreserveResources(t *testing.T) {
	tm := integrationTrustManager()
	for _, scenario := range []string{"completion-read", "resource-read", "apply", "delete", "delete-race", "delete-notfound", "delete-missing-identity"} {
		t.Run(scenario, func(t *testing.T) {
			r := testReconciler(t)
			fake := &fakes.FakeCtrlClient{}
			r.CtrlClient = fake
			fake.GetCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) error {
				if scenario == "completion-read" {
					return errTestClient
				}
				obj.(*v1alpha1.CertManager).Status.AutoApproverDisabled = scenario == "apply" || scenario == "resource-read"
				return nil
			})
			objects := integrationResources(t, tm)
			fake.ExistsCalls(func(_ context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
				if scenario == "resource-read" {
					return false, errTestClient
				}
				if scenario == "apply" {
					return false, nil
				}
				for _, resource := range objects {
					if resource.GetName() == key.Name {
						resource.DeepCopyInto(obj.(*unstructured.Unstructured))
						if scenario != "delete-missing-identity" {
							obj.SetUID("uid")
							obj.SetResourceVersion("8")
						}
						return true, nil
					}
				}
				t.Fatal("unexpected resource", key)
				return false, nil
			})
			fake.PatchReturns(errTestClient)
			fake.DeleteCalls(func(_ context.Context, obj client.Object, opts ...client.DeleteOption) error {
				if scenario == "delete-notfound" {
					return apierrors.NewNotFound(schema.GroupResource{Resource: "resource"}, obj.GetName())
				}
				if scenario == "delete-race" {
					return apierrors.NewConflict(schema.GroupResource{Resource: "resource"}, obj.GetName(), fmt.Errorf("UID precondition failed"))
				}
				return errTestClient
			})
			err := r.reconcileApproverPolicy(tm)
			if scenario == "delete-notfound" {
				require.NoError(t, err)
			} else {
				require.True(t, common.IsRetryRequiredError(err), "%v", err)
			}
			if scenario == "completion-read" {
				require.Zero(t, fake.ExistsCallCount())
			}
			if scenario == "completion-read" || scenario == "resource-read" || scenario == "apply" || scenario == "delete-missing-identity" {
				require.Zero(t, fake.DeleteCallCount())
			}
		})
	}
}

func TestApproverPolicyWatches(t *testing.T) {
	oldCM := &v1alpha1.CertManager{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Generation: 1}}
	newCM := oldCM.DeepCopy()
	newCM.Status.AutoApproverDisabled = true
	p := approverHandoffPredicate()
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: oldCM, ObjectNew: newCM}), "status-only transition must enqueue")
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: newCM, ObjectNew: oldCM}))
	require.False(t, p.Update(event.UpdateEvent{ObjectOld: oldCM, ObjectNew: oldCM.DeepCopy()}))
	require.True(t, p.Create(event.CreateEvent{Object: oldCM}))
	require.True(t, p.Delete(event.DeleteEvent{Object: newCM}))
	newCM.Name = "other"
	require.False(t, p.Create(event.CreateEvent{Object: newCM}))
	for _, obj := range []client.Object{&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: approverPolicyRoleName}}, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: approverPolicyBindingName}}, integrationResources(t, integrationTrustManager())[0]} {
		obj.SetLabels(nil)
		require.True(t, isApproverPolicyResource(obj), "unlabeled collisions must be visible")
		before := obj.DeepCopyObject().(client.Object)
		before.SetLabels(map[string]string{common.ManagedResourceLabelKey: RequestEnqueueLabelValue})
		require.True(t, predicate.NewPredicateFuncs(isApproverPolicyResource).Update(event.UpdateEvent{ObjectOld: before, ObjectNew: obj}))
		for _, state := range []v1alpha1.ApproverPolicyManagementState{"", v1alpha1.ApproverPolicyManagementStateManaged, v1alpha1.ApproverPolicyManagementStateUnmanaged} {
			r := testReconciler(t)
			fake := &fakes.FakeCtrlClient{}
			r.CtrlClient = fake
			fake.GetCalls(func(_ context.Context, _ client.ObjectKey, got client.Object) error {
				got.(*v1alpha1.TrustManager).Spec.TrustManagerConfig.ApproverPolicy.ManagementState = state
				return nil
			})
			requests := r.mapApproverPolicyEvent(context.Background(), obj)
			if state == v1alpha1.ApproverPolicyManagementStateUnmanaged {
				require.Empty(t, requests)
			} else {
				require.Len(t, requests, 1)
				require.Equal(t, "cluster", requests[0].Name)
			}
		}
		obj.SetName("user-owned")
		require.False(t, isApproverPolicyResource(obj))
	}
}

func TestApproverPolicyRBACServerSideApply(t *testing.T) {
	// The typed tracker executes structured merge, including field pruning;
	// merely counting Patch calls would not verify configuration removal.
	for _, desired := range integrationResources(t, integrationTrustManager())[1:] {
		t.Run(desired.GetKind(), func(t *testing.T) {
			tracker := kubefake.NewClientset().Tracker()
			resource := "clusterroles"
			if desired.GetKind() == "ClusterRoleBinding" {
				resource = "clusterrolebindings"
			}
			gvr := rbacv1.SchemeGroupVersion.WithResource(resource)
			r := testReconciler(t)
			fake := &fakes.FakeCtrlClient{}
			r.CtrlClient = fake
			fake.ExistsCalls(func(_ context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
				got, err := tracker.Get(gvr, "", key.Name)
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(got)
				obj.(*unstructured.Unstructured).Object = data
				return true, err
			})
			fake.PatchCalls(func(_ context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				require.Equal(t, types.ApplyPatchType, patch.Type())
				options := &client.PatchOptions{}
				for _, opt := range opts {
					opt.ApplyToPatch(options)
				}
				return tracker.Apply(gvr, obj.(*unstructured.Unstructured), "", *options.AsPatchOptions())
			})
			tm := integrationTrustManager()
			withMetadata := desired.DeepCopy()
			annotations := withMetadata.GetAnnotations()
			annotations["remove-me"] = "value"
			withMetadata.SetAnnotations(annotations)
			require.NoError(t, r.applyApproverPolicyResource(tm, withMetadata))
			// Simulate an unrelated manager adding metadata via its own apply.
			extra := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": desired.GetAPIVersion(), "kind": desired.GetKind(), "metadata": map[string]interface{}{"name": desired.GetName(), "annotations": map[string]interface{}{"keep-me": "value"}}}}
			require.NoError(t, tracker.Apply(gvr, extra, "", metav1.PatchOptions{FieldManager: "user"}))
			// Change the desired hash as a real configuration-removal render does.
			annotations = desired.GetAnnotations()
			annotations[approverPolicyDesiredAnnotation] = "new-config"
			desired.SetAnnotations(annotations)
			require.NoError(t, r.applyApproverPolicyResource(tm, desired.DeepCopy()))
			got, err := tracker.Get(gvr, "", desired.GetName())
			require.NoError(t, err)
			obj := got.(client.Object)
			require.Equal(t, "value", obj.GetAnnotations()["keep-me"])
			require.NotContains(t, obj.GetAnnotations(), "remove-me")
			require.NoError(t, r.applyApproverPolicyResource(tm, desired.DeepCopy()))
			require.Equal(t, 2, fake.PatchCallCount())
		})
	}
}

func TestApproverPolicyBeforeServiceCertificateAndUnmanagedStatus(t *testing.T) {
	t.Setenv(trustManagerImageNameEnvVarName, testImage)
	for _, unmanaged := range []bool{false, true} {
		t.Run(fmt.Sprint(unmanaged), func(t *testing.T) {
			r := testReconciler(t)
			fake := &fakes.FakeCtrlClient{}
			r.CtrlClient = fake
			tm := integrationTrustManager()
			if unmanaged {
				tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState = v1alpha1.ApproverPolicyManagementStateUnmanaged
			}
			fake.GetCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) error {
				switch typed := obj.(type) {
				case *v1alpha1.CertManager:
					require.False(t, unmanaged, "Unmanaged must not read completion")
					typed.Status.AutoApproverDisabled = true
				case *v1alpha1.TrustManager:
					tm.DeepCopyInto(typed)
				}
				return nil
			})
			fake.ExistsCalls(func(_ context.Context, _ client.ObjectKey, obj client.Object) (bool, error) {
				if _, ok := obj.(*corev1.Namespace); ok {
					return true, nil
				}
				if _, ok := obj.(*unstructured.Unstructured); ok {
					require.False(t, unmanaged)
				}
				return false, nil
			})
			var applied []string
			fake.PatchCalls(func(_ context.Context, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
				if _, ok := obj.(*certmanagerv1.Certificate); ok && !unmanaged {
					require.Contains(t, applied, approverPolicyName)
					require.Contains(t, applied, approverPolicyBindingName)
				}
				if _, ok := obj.(*unstructured.Unstructured); ok {
					require.False(t, unmanaged)
				}
				applied = append(applied, obj.GetName())
				return nil
			})
			_, err := r.processReconcileRequest(tm, client.ObjectKey{Name: tm.Name})
			require.NoError(t, err)
			for _, condition := range tm.Status.Conditions {
				if condition.Type == v1alpha1.Ready {
					require.Equal(t, metav1.ConditionTrue, condition.Status)
				}
			}
		})
	}
}
