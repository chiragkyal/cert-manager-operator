package trustmanager

import (
	"context"
	"fmt"
	"reflect"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

// =============================================================================
// SCHEME AND CODEC SETUP
// =============================================================================
// The scheme and codecs are used to decode YAML manifests from bindata
// into Go objects. Each type we want to decode must be registered.
var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	// Register all the types we need to decode from bindata
	if err := appsv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := certmanagerv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := admissionregistrationv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
}

// =============================================================================
// STATUS UPDATE
// =============================================================================

// updateStatus updates the status subresource of TrustManager.
// Uses retry logic to handle conflicts from concurrent updates.
func (r *Reconciler) updateStatus(ctx context.Context, trustManager *v1alpha1.TrustManager) error {
	name := trustManager.GetName()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		r.log.V(4).Info("updating TrustManager status", "name", name)

		// Fetch current state
		current := &v1alpha1.TrustManager{}
		if err := r.Get(ctx, client.ObjectKey{Name: name}, current); err != nil {
			return fmt.Errorf("failed to fetch TrustManager %q for status update: %w", name, err)
		}

		// Copy our status into the current object
		trustManager.Status.DeepCopyInto(&current.Status)

		// Update the status subresource
		if err := r.StatusUpdate(ctx, current); err != nil {
			return fmt.Errorf("failed to update TrustManager %q status: %w", name, err)
		}

		return nil
	})
}

// =============================================================================
// OBJECT MANIPULATION HELPERS
// =============================================================================

// updateNamespace sets the namespace on a Kubernetes object.
func updateNamespace(obj client.Object, namespace string) {
	obj.SetNamespace(namespace)
}

// updateResourceLabels replaces all labels on an object.
func updateResourceLabels(obj client.Object, labels map[string]string) {
	obj.SetLabels(labels)
}

// updateResourceAnnotations replaces all annotations on an object.
func updateResourceAnnotations(obj client.Object, annotations map[string]string) {
	if annotations != nil {
		obj.SetAnnotations(annotations)
	}
}

// mergeLabels merges additional labels into existing labels.
func mergeLabels(existing, additional map[string]string) map[string]string {
	result := make(map[string]string, len(existing)+len(additional))
	for k, v := range existing {
		result[k] = v
	}
	for k, v := range additional {
		result[k] = v
	}
	return result
}

// =============================================================================
// BINDATA DECODERS
// =============================================================================
// These functions decode YAML bytes from bindata into typed Go objects.
// They panic on error because bindata is embedded at build time and
// should always be valid. A panic here indicates a build problem.

func decodeDeploymentObjBytes(objBytes []byte) *appsv1.Deployment {
	obj, err := runtime.Decode(codecs.UniversalDecoder(appsv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode Deployment: %v", err))
	}
	return obj.(*appsv1.Deployment)
}

func decodeServiceAccountObjBytes(objBytes []byte) *corev1.ServiceAccount {
	obj, err := runtime.Decode(codecs.UniversalDecoder(corev1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode ServiceAccount: %v", err))
	}
	return obj.(*corev1.ServiceAccount)
}

func decodeServiceObjBytes(objBytes []byte) *corev1.Service {
	obj, err := runtime.Decode(codecs.UniversalDecoder(corev1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode Service: %v", err))
	}
	return obj.(*corev1.Service)
}

func decodeClusterRoleObjBytes(objBytes []byte) *rbacv1.ClusterRole {
	obj, err := runtime.Decode(codecs.UniversalDecoder(rbacv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode ClusterRole: %v", err))
	}
	return obj.(*rbacv1.ClusterRole)
}

func decodeClusterRoleBindingObjBytes(objBytes []byte) *rbacv1.ClusterRoleBinding {
	obj, err := runtime.Decode(codecs.UniversalDecoder(rbacv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode ClusterRoleBinding: %v", err))
	}
	return obj.(*rbacv1.ClusterRoleBinding)
}

func decodeRoleObjBytes(objBytes []byte) *rbacv1.Role {
	obj, err := runtime.Decode(codecs.UniversalDecoder(rbacv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode Role: %v", err))
	}
	return obj.(*rbacv1.Role)
}

func decodeRoleBindingObjBytes(objBytes []byte) *rbacv1.RoleBinding {
	obj, err := runtime.Decode(codecs.UniversalDecoder(rbacv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode RoleBinding: %v", err))
	}
	return obj.(*rbacv1.RoleBinding)
}

func decodeCertificateObjBytes(objBytes []byte) *certmanagerv1.Certificate {
	obj, err := runtime.Decode(codecs.UniversalDecoder(certmanagerv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode Certificate: %v", err))
	}
	return obj.(*certmanagerv1.Certificate)
}

func decodeIssuerObjBytes(objBytes []byte) *certmanagerv1.Issuer {
	obj, err := runtime.Decode(codecs.UniversalDecoder(certmanagerv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode Issuer: %v", err))
	}
	return obj.(*certmanagerv1.Issuer)
}

func decodeValidatingWebhookConfigurationObjBytes(objBytes []byte) *admissionregistrationv1.ValidatingWebhookConfiguration {
	obj, err := runtime.Decode(codecs.UniversalDecoder(admissionregistrationv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to decode ValidatingWebhookConfiguration: %v", err))
	}
	return obj.(*admissionregistrationv1.ValidatingWebhookConfiguration)
}

// =============================================================================
// CHANGE DETECTION
// =============================================================================
// These functions determine if an object needs to be updated by comparing
// the desired state with the current state in the cluster.

// hasObjectChanged compares desired and fetched objects to detect drift.
func hasObjectChanged(desired, fetched client.Object) bool {
	if reflect.TypeOf(desired) != reflect.TypeOf(fetched) {
		panic("both objects must be of the same type")
	}

	var specChanged bool
	switch d := desired.(type) {
	case *appsv1.Deployment:
		specChanged = deploymentSpecChanged(d, fetched.(*appsv1.Deployment))
	case *corev1.Service:
		specChanged = serviceSpecChanged(d, fetched.(*corev1.Service))
	case *rbacv1.ClusterRole:
		specChanged = !reflect.DeepEqual(d.Rules, fetched.(*rbacv1.ClusterRole).Rules)
	case *rbacv1.ClusterRoleBinding:
		f := fetched.(*rbacv1.ClusterRoleBinding)
		specChanged = !reflect.DeepEqual(d.RoleRef, f.RoleRef) || !reflect.DeepEqual(d.Subjects, f.Subjects)
	case *rbacv1.Role:
		specChanged = !reflect.DeepEqual(d.Rules, fetched.(*rbacv1.Role).Rules)
	case *rbacv1.RoleBinding:
		f := fetched.(*rbacv1.RoleBinding)
		specChanged = !reflect.DeepEqual(d.RoleRef, f.RoleRef) || !reflect.DeepEqual(d.Subjects, f.Subjects)
	case *certmanagerv1.Certificate:
		specChanged = !reflect.DeepEqual(d.Spec, fetched.(*certmanagerv1.Certificate).Spec)
	case *certmanagerv1.Issuer:
		specChanged = !reflect.DeepEqual(d.Spec, fetched.(*certmanagerv1.Issuer).Spec)
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		specChanged = !reflect.DeepEqual(d.Webhooks, fetched.(*admissionregistrationv1.ValidatingWebhookConfiguration).Webhooks)
	case *corev1.ServiceAccount:
		// ServiceAccounts don't have a spec that we control
		specChanged = false
	default:
		panic(fmt.Sprintf("unsupported object type: %T", desired))
	}

	// Also check if labels changed
	labelsChanged := !reflect.DeepEqual(desired.GetLabels(), fetched.GetLabels())

	return specChanged || labelsChanged
}

// deploymentSpecChanged checks if deployment spec has meaningful changes.
func deploymentSpecChanged(desired, fetched *appsv1.Deployment) bool {
	// Check replicas
	if desired.Spec.Replicas != nil && fetched.Spec.Replicas != nil {
		if *desired.Spec.Replicas != *fetched.Spec.Replicas {
			return true
		}
	}

	// Check selector
	if !reflect.DeepEqual(desired.Spec.Selector, fetched.Spec.Selector) {
		return true
	}

	// Check pod template labels
	if !reflect.DeepEqual(desired.Spec.Template.Labels, fetched.Spec.Template.Labels) {
		return true
	}

	// Check containers
	if len(desired.Spec.Template.Spec.Containers) != len(fetched.Spec.Template.Spec.Containers) {
		return true
	}

	if len(desired.Spec.Template.Spec.Containers) > 0 {
		dc := desired.Spec.Template.Spec.Containers[0]
		fc := fetched.Spec.Template.Spec.Containers[0]

		if dc.Image != fc.Image ||
			dc.Name != fc.Name ||
			!reflect.DeepEqual(dc.Args, fc.Args) ||
			!reflect.DeepEqual(dc.Resources, fc.Resources) {
			return true
		}
	}

	// Check service account
	if desired.Spec.Template.Spec.ServiceAccountName != fetched.Spec.Template.Spec.ServiceAccountName {
		return true
	}

	// Check node selector, tolerations, affinity
	if !reflect.DeepEqual(desired.Spec.Template.Spec.NodeSelector, fetched.Spec.Template.Spec.NodeSelector) ||
		!reflect.DeepEqual(desired.Spec.Template.Spec.Tolerations, fetched.Spec.Template.Spec.Tolerations) ||
		!reflect.DeepEqual(desired.Spec.Template.Spec.Affinity, fetched.Spec.Template.Spec.Affinity) {
		return true
	}

	return false
}

// serviceSpecChanged checks if service spec has meaningful changes.
func serviceSpecChanged(desired, fetched *corev1.Service) bool {
	return desired.Spec.Type != fetched.Spec.Type ||
		!reflect.DeepEqual(desired.Spec.Ports, fetched.Spec.Ports) ||
		!reflect.DeepEqual(desired.Spec.Selector, fetched.Spec.Selector)
}
