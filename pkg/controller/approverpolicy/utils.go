package approverpolicy

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := admissionregistrationv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
}

// updateStatus is for updating the status subresource of approverpolicymanagers.openshift.operator.io.
func (r *Reconciler) updateStatus(ctx context.Context, changed *v1alpha1.ApproverPolicyManager) error {
	namespacedName := client.ObjectKeyFromObject(changed)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		r.log.V(4).Info("updating approverpolicymanager.openshift.operator.io status", "request", namespacedName)
		current := &v1alpha1.ApproverPolicyManager{}
		if err := r.Get(ctx, namespacedName, current); err != nil {
			return fmt.Errorf("failed to fetch approverpolicymanager.openshift.operator.io %q for status update: %w", namespacedName, err)
		}
		changed.Status.DeepCopyInto(&current.Status)

		if err := r.StatusUpdate(ctx, current); err != nil {
			return fmt.Errorf("failed to update approverpolicymanager.openshift.operator.io %q status: %w", namespacedName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// addFinalizer adds finalizer to approverpolicymanagers.openshift.operator.io resource.
func (r *Reconciler) addFinalizer(ctx context.Context, apm *v1alpha1.ApproverPolicyManager) error {
	namespacedName := client.ObjectKeyFromObject(apm)
	if !controllerutil.ContainsFinalizer(apm, finalizer) {
		if !controllerutil.AddFinalizer(apm, finalizer) {
			return fmt.Errorf("failed to add finalizer %q on approverpolicymanager.openshift.operator.io %q", finalizer, namespacedName)
		}

		// update approverpolicymanagers.openshift.operator.io on adding finalizer.
		if err := r.UpdateWithRetry(ctx, apm); err != nil {
			return fmt.Errorf("failed to add finalizers on %q approverpolicymanager.openshift.operator.io with %w", namespacedName, err)
		}

		updated := &v1alpha1.ApproverPolicyManager{}
		if err := r.Get(ctx, namespacedName, updated); err != nil {
			return fmt.Errorf("failed to fetch approverpolicymanager.openshift.operator.io %q after updating finalizers: %w", namespacedName, err)
		}
		updated.DeepCopyInto(apm)
		return nil
	}
	return nil
}

// removeFinalizer removes finalizers added to approverpolicymanagers.openshift.operator.io resource.
func (r *Reconciler) removeFinalizer(ctx context.Context, apm *v1alpha1.ApproverPolicyManager, finalizer string) error {
	namespacedName := client.ObjectKeyFromObject(apm)
	if controllerutil.ContainsFinalizer(apm, finalizer) {
		if !controllerutil.RemoveFinalizer(apm, finalizer) {
			return fmt.Errorf("failed to remove finalizer %q from approverpolicymanager.openshift.operator.io %q", finalizer, namespacedName)
		}

		if err := r.UpdateWithRetry(ctx, apm); err != nil {
			return fmt.Errorf("failed to remove finalizers on %q approverpolicymanager.openshift.operator.io with %w", namespacedName, err)
		}
		return nil
	}

	return nil
}

func validateApproverPolicyConfig(apm *v1alpha1.ApproverPolicyManager) error {
	if reflect.ValueOf(apm.Spec.ApproverPolicyConfig).IsZero() {
		return fmt.Errorf("spec.approverPolicyConfig config cannot be empty")
	}

	if labels := apm.Spec.ControllerConfig.Labels; len(labels) > 0 {
		if err := common.ValidateLabelsConfig(labels, controllerConfigFieldPath); err != nil {
			return err
		}
	}
	if annotations := apm.Spec.ControllerConfig.Annotations; len(annotations) > 0 {
		if err := common.ValidateAnnotationsConfig(annotations, controllerConfigFieldPath); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) updateCondition(apm *v1alpha1.ApproverPolicyManager, prependErr error) error {
	if err := r.updateStatus(r.ctx, apm); err != nil {
		errUpdate := fmt.Errorf("failed to update %s status: %w", apm.GetName(), err)
		if prependErr != nil {
			return utilerrors.NewAggregate([]error{prependErr, errUpdate})
		}
		return errUpdate
	}
	return prependErr
}

// getResourceLabels returns the labels to apply to all resources created by the controller.
// It merges user-specified labels with the controller's default labels.
func getResourceLabels(apm *v1alpha1.ApproverPolicyManager) map[string]string {
	resourceLabels := make(map[string]string)
	if len(apm.Spec.ControllerConfig.Labels) != 0 {
		maps.Copy(resourceLabels, apm.Spec.ControllerConfig.Labels)
	}
	maps.Copy(resourceLabels, controllerDefaultResourceLabels)
	return resourceLabels
}

// getResourceAnnotations returns the annotations to apply to resources.
// It merges user-specified annotations with any required annotations.
func getResourceAnnotations(apm *v1alpha1.ApproverPolicyManager) map[string]string {
	annotations := make(map[string]string)
	if len(apm.Spec.ControllerConfig.Annotations) != 0 {
		maps.Copy(annotations, apm.Spec.ControllerConfig.Annotations)
	}
	return annotations
}

// updateResourceAnnotations merges user-provided annotations into the object's existing annotations.
// User-provided annotations take precedence over existing ones on key conflicts.
func updateResourceAnnotations(obj client.Object, annotations map[string]string) {
	if len(annotations) == 0 {
		return
	}
	existing := obj.GetAnnotations()
	if existing == nil {
		existing = make(map[string]string)
	}
	maps.Copy(existing, annotations)
	obj.SetAnnotations(existing)
}

// managedLabelsModified checks whether all labels present in desired exist
// with matching values in existing. Extra labels on existing (added by users
// or other controllers) are allowed and do not count as modified.
func managedLabelsModified(desired, existing client.Object) bool {
	existingLabels := existing.GetLabels()
	for k, v := range desired.GetLabels() {
		if existingLabels[k] != v {
			return true
		}
	}
	return false
}

// managedAnnotationsModified checks whether all annotations present in desired
// exist with matching values in existing. Extra annotations on existing are
// allowed and do not count as modified.
func managedAnnotationsModified(desired, existing client.Object) bool {
	existingAnnotations := existing.GetAnnotations()
	for k, v := range desired.GetAnnotations() {
		if existingAnnotations[k] != v {
			return true
		}
	}
	return false
}

// managedMetadataModified returns true if any managed label or annotation has drifted.
func managedMetadataModified(desired, existing client.Object) bool {
	return managedLabelsModified(desired, existing) || managedAnnotationsModified(desired, existing)
}

// namespaceExists checks if a namespace exists in the cluster.
func (r *Reconciler) namespaceExists(namespace string) (bool, error) {
	ns := &corev1.Namespace{}
	key := client.ObjectKey{Name: namespace}
	return r.Exists(r.ctx, key, ns)
}
