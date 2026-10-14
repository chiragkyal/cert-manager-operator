package trustmanager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

const (
	approverPolicyName              = "trust-manager-policy"
	approverPolicyRoleName          = "trust-manager-policy-role"
	approverPolicyBindingName       = "trust-manager-policy-binding"
	approverPolicyOwnerAnnotation   = "trust-manager.operator.openshift.io/approver-policy-owner"
	approverPolicyDesiredAnnotation = "trust-manager.operator.openshift.io/approver-policy-desired-state"
)

func approverPolicyObject() *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "policy.cert-manager.io", Version: "v1alpha1", Kind: "CertificateRequestPolicy"})
	return obj
}

func approverPolicyManaged(tm *v1alpha1.TrustManager) bool {
	state := tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState
	// Also support objects not yet defaulted by the API server.
	return state == "" || state == v1alpha1.ApproverPolicyManagementStateManaged
}

// reconcileApproverPolicy runs before service-certificate reconciliation: waiting
// for that certificate first would deadlock issuance after the approver handoff.
func (r *Reconciler) reconcileApproverPolicy(tm *v1alpha1.TrustManager) error {
	if tm.Spec.TrustManagerConfig.ApproverPolicy.ManagementState == v1alpha1.ApproverPolicyManagementStateUnmanaged {
		return nil
	}
	if !approverPolicyManaged(tm) {
		return common.NewIrrecoverableError(fmt.Errorf("expected Managed or Unmanaged"), "invalid trustManagerConfig.approverPolicy.managementState")
	}
	cm := &v1alpha1.CertManager{}
	if err := r.Get(r.ctx, client.ObjectKey{Name: "cluster"}, cm); err != nil && !apierrors.IsNotFound(err) {
		// A failed read is not evidence that the default approver was restored.
		return common.FromClientError(err, "read cert-manager approver handoff completion")
	}
	objects, err := approverPolicyResources(tm)
	if err != nil {
		return common.NewIrrecoverableError(err, "load trust-manager approver-policy resources")
	}
	if !cm.Status.AutoApproverDisabled {
		// Revoke use before removing the policy. Never remove unrelated resources.
		for i := len(objects) - 1; i >= 0; i-- {
			if err := r.removeApproverPolicyResource(tm, objects[i]); err != nil {
				return err
			}
		}
		return nil
	}
	if tm.UID == "" {
		return common.NewIrrecoverableError(fmt.Errorf("TrustManager has no UID"), "cannot identify approver-policy resource ownership")
	}
	for _, obj := range objects {
		if err := r.applyApproverPolicyResource(tm, obj); err != nil {
			return err
		}
	}
	return nil
}

func approverPolicyResources(tm *v1alpha1.TrustManager) ([]*unstructured.Unstructured, error) {
	objects := make([]*unstructured.Unstructured, 0, 3)
	for _, asset := range []string{
		"certificaterequestpolicy_trust-manager-policy.yml",
		"clusterrole_trust-manager-policy-role.yml",
		"clusterrolebinding_trust-manager-policy-binding.yml",
	} {
		data, err := assets.Asset("trust-manager/resources/" + asset)
		if err != nil {
			return nil, fmt.Errorf("construct trust-manager approval policy resources: %w", err)
		}
		data, err = yaml.ToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("construct trust-manager approval policy resources: %w", err)
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(data); err != nil {
			return nil, fmt.Errorf("construct trust-manager approval policy resources: %w", err)
		}
		common.UpdateResourceLabels(obj, getResourceLabels(tm))
		annotations := getResourceAnnotations(tm)
		// Deliberately use an ownership annotation, not an owner reference:
		// deleting TrustManager retains its resources under the existing lifecycle.
		annotations[approverPolicyOwnerAnnotation] = string(tm.UID)
		delete(annotations, approverPolicyDesiredAnnotation)
		obj.SetAnnotations(annotations)
		data, err = json.Marshal(obj.Object)
		if err != nil {
			return nil, fmt.Errorf("construct trust-manager approval policy resources: %w", err)
		}
		// Configuration removal must trigger SSA too, so it relinquishes fields
		// previously managed by us while preserving unrelated user metadata.
		annotations[approverPolicyDesiredAnnotation] = fmt.Sprintf("%x", sha256.Sum256(data))
		obj.SetAnnotations(annotations)
		objects = append(objects, obj)
	}
	return objects, nil
}

func ownsApproverPolicyResource(tm *v1alpha1.TrustManager, obj client.Object) bool {
	return tm.UID != "" && obj.GetAnnotations()[approverPolicyOwnerAnnotation] == string(tm.UID)
}

func (r *Reconciler) applyApproverPolicyResource(tm *v1alpha1.TrustManager, desired *unstructured.Unstructured) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(desired.GroupVersionKind())
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "read %s %s", desired.GetKind(), desired.GetName())
	}
	if exists {
		if !ownsApproverPolicyResource(tm, existing) {
			return common.NewIrrecoverableError(fmt.Errorf("resource is not owned by this TrustManager"), "refusing to adopt %s %s", desired.GetKind(), desired.GetName())
		}
		if !approverPolicyResourceModified(desired, existing) {
			return nil
		}
		// Do not overwrite a replacement or a concurrent ownership change.
		desired.SetResourceVersion(existing.GetResourceVersion())
	}
	//nolint:staticcheck // Shared CtrlClient exposes SSA through Patch, not the newer Apply method.
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "apply %s %s", desired.GetKind(), desired.GetName())
	}
	return nil
}

func approverPolicyResourceModified(desired, existing *unstructured.Unstructured) bool {
	if managedLabelsModified(desired, existing) || managedAnnotationsModified(desired, existing) {
		return true
	}
	for _, field := range []string{"spec", "rules", "roleRef", "subjects"} {
		if !reflect.DeepEqual(desired.Object[field], existing.Object[field]) {
			return true
		}
	}
	return false
}

func (r *Reconciler) removeApproverPolicyResource(tm *v1alpha1.TrustManager, desired *unstructured.Unstructured) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(desired.GroupVersionKind())
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "read %s %s for removal", desired.GetKind(), desired.GetName())
	}
	if !exists || !ownsApproverPolicyResource(tm, existing) {
		return nil
	}
	uid, version := existing.GetUID(), existing.GetResourceVersion()
	if uid == "" || version == "" {
		return common.NewRetryRequiredError(fmt.Errorf("missing UID or resourceVersion"), "cannot safely remove %s %s", existing.GetKind(), existing.GetName())
	}
	if err := r.Delete(r.ctx, existing, client.Preconditions{UID: &uid, ResourceVersion: &version}); err != nil && !apierrors.IsNotFound(err) {
		return common.FromClientError(err, "remove %s %s", existing.GetKind(), existing.GetName())
	}
	return nil
}

// Integration identity must remain observable even without the managed label.
func isApproverPolicyResource(obj client.Object) bool {
	if obj == nil {
		return false
	}
	switch typed := obj.(type) {
	case *rbacv1.ClusterRole:
		return obj.GetName() == approverPolicyRoleName
	case *rbacv1.ClusterRoleBinding:
		return obj.GetName() == approverPolicyBindingName
	case *unstructured.Unstructured:
		return typed.GroupVersionKind() == approverPolicyObject().GroupVersionKind() && obj.GetName() == approverPolicyName
	}
	return false
}

// The shared informer remains registered, but integration events cause no
// reconciliation or status changes for an Unmanaged TrustManager.
func (r *Reconciler) mapApproverPolicyEvent(ctx context.Context, _ client.Object) []reconcile.Request {
	tm := &v1alpha1.TrustManager{}
	if err := r.Get(ctx, client.ObjectKey{Name: trustManagerObjectName}, tm); err != nil {
		if !apierrors.IsNotFound(err) {
			r.log.Error(err, "read TrustManager for approver-policy event")
		}
		return nil
	}
	if !approverPolicyManaged(tm) {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: trustManagerObjectName}}}
}

func approverHandoffPredicate() predicate.Predicate {
	match := func(obj client.Object) bool { return obj != nil && obj.GetName() == "cluster" }
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return match(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return match(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return match(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldCM, oldOK := e.ObjectOld.(*v1alpha1.CertManager)
			newCM, newOK := e.ObjectNew.(*v1alpha1.CertManager)
			return oldOK && newOK && match(newCM) && oldCM.Status.AutoApproverDisabled != newCM.Status.AutoApproverDisabled
		},
	}
}
