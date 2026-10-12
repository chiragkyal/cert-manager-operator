package approverpolicy

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

const imageEnv = "RELATED_IMAGE_APPROVER_POLICY"

// These are existing imported assets. Keep TLS data and injected CA bundles out
// of apply payloads: they belong to the operand and cert-manager cainjector.
var resourceAssets = []string{
	"serviceaccount_cert-manager-approver-policy.yml",
	"clusterrole_cert-manager-approver-policy.yml",
	"clusterrolebinding_cert-manager-approver-policy.yml",
	"role_cert-manager-approver-policy.yml",
	"rolebinding_cert-manager-approver-policy.yml",
	"service_cert-manager-approver-policy.yml",
	"service_cert-manager-approver-policy-metrics.yml",
	"secret_cert-manager-approver-policy-tls.yml",
	"validatingwebhookconfiguration_cert-manager-approver-policy.yml",
	"deployment_cert-manager-approver-policy.yml",
}

func desiredResources(manager *v1alpha1.ApproverPolicyManager) ([]*unstructured.Unstructured, error) {
	image := strings.TrimSpace(os.Getenv(imageEnv))
	if image == "" {
		return nil, fmt.Errorf("%s must be configured for approver-policy", imageEnv)
	}
	config := manager.Spec.ApproverPolicyConfig
	if config.LogLevel == 0 {
		config.LogLevel = 1 // API defaults; also support objects before defaulting in unit clients.
	}
	if config.LogFormat == "" {
		config.LogFormat = "text"
	}
	if config.LogLevel < 1 || config.LogLevel > 5 || (config.LogFormat != "text" && config.LogFormat != "json") {
		return nil, fmt.Errorf("invalid approverPolicyConfig logging: level must be 1–5 and format text or json")
	}
	var objects []*unstructured.Unstructured
	for _, name := range resourceAssets {
		data, err := assets.Asset("approver-policy/resources/" + name)
		if err != nil {
			return nil, err
		}
		data, err = yaml.ToJSON(data)
		if err != nil {
			return nil, err
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(data); err != nil {
			return nil, err
		}
		labels := obj.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels[common.ManagedResourceLabelKey] = RequestEnqueueLabelValue
		obj.SetLabels(labels)
		obj.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(manager,
			schema.GroupVersionKind{Group: v1alpha1.SchemeGroupVersion.Group, Version: v1alpha1.SchemeGroupVersion.Version, Kind: "ApproverPolicyManager"})})
		switch obj.GetKind() {
		case "ClusterRole":
			// The initial installation approves only cert-manager's built-in
			// issuers. Keep this within the operator's existing signer grant;
			// configurable external signers belong to a later phase.
			rules, _, err := unstructured.NestedSlice(obj.Object, "rules")
			if err != nil {
				return nil, err
			}
			for _, item := range rules {
				rule := item.(map[string]interface{})
				resources, _, err := unstructured.NestedStringSlice(rule, "resources")
				if err != nil {
					return nil, err
				}
				if len(resources) == 1 && resources[0] == "signers" {
					if err := unstructured.SetNestedStringSlice(rule, []string{"issuers.cert-manager.io/*", "clusterissuers.cert-manager.io/*"}, "resourceNames"); err != nil {
						return nil, err
					}
				}
			}
			if err := unstructured.SetNestedSlice(obj.Object, rules, "rules"); err != nil {
				return nil, err
			}
		case "Secret":
			delete(obj.Object, "data")
			delete(obj.Object, "stringData")
		case "ValidatingWebhookConfiguration":
			webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
			if err != nil {
				return nil, err
			}
			for _, webhook := range webhooks {
				unstructured.RemoveNestedField(webhook.(map[string]interface{}), "clientConfig", "caBundle")
			}
			if err := unstructured.SetNestedSlice(obj.Object, webhooks, "webhooks"); err != nil {
				return nil, err
			}
		case "Deployment":
			containers, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
			if err != nil || len(containers) != 1 {
				return nil, fmt.Errorf("unexpected approver-policy Deployment containers: %v", err)
			}
			container := containers[0].(map[string]interface{})
			args, _, err := unstructured.NestedStringSlice(container, "args")
			if err != nil {
				return nil, err
			}
			args = common.MergeContainerArgs(args, []string{fmt.Sprintf("--log-level=%d", config.LogLevel), "--log-format=" + config.LogFormat})
			if err := unstructured.SetNestedStringSlice(container, args, "args"); err != nil {
				return nil, err
			}
			container["image"] = image
			if err := unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers"); err != nil {
				return nil, err
			}
		}
		objects = append(objects, obj)
	}
	return objects, nil
}

func (r *Reconciler) applyResource(ctx context.Context, desired *unstructured.Unstructured) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(desired.GroupVersionKind())
	exists, err := r.Exists(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "read %s %s", desired.GetKind(), desired.GetName())
	}
	if exists {
		if owner := metav1.GetControllerOf(existing); owner != nil && owner.UID != desired.GetOwnerReferences()[0].UID {
			return common.NewIrrecoverableError(fmt.Errorf("already controlled by %s %s", owner.Kind, owner.Name), "cannot adopt %s %s", desired.GetKind(), desired.GetName())
		}
		if managedFieldsEqual(desired.Object, existing.Object) {
			return nil
		}
	}
	// Patch mutates its input with the server response; retain the original desired
	// projection for the readiness comparison and never re-apply server-owned fields.
	if err := r.Patch(ctx, desired.DeepCopy(), client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "apply %s %s", desired.GetKind(), desired.GetName())
	}
	return nil
}

// managedFieldsEqual compares the imported/overlaid fields, not status, allocated
// Service addresses, defaulted fields, Secret data or the injected webhook CA.
func managedFieldsEqual(desired, existing interface{}) bool {
	switch wanted := desired.(type) {
	case map[string]interface{}:
		actual, ok := existing.(map[string]interface{})
		if !ok {
			return false
		}
		for key, value := range wanted {
			if !managedFieldsEqual(value, actual[key]) {
				return false
			}
		}
		return true
	case []interface{}:
		actual, ok := existing.([]interface{})
		if !ok || len(wanted) != len(actual) {
			return false
		}
		for i := range wanted {
			if !managedFieldsEqual(wanted[i], actual[i]) {
				return false
			}
		}
		return true
	case bool:
		// Kubernetes omits false non-pointer booleans such as hostNetwork
		// when serializing typed objects. A missing field has the same value.
		if existing == nil {
			return !wanted
		}
		return reflect.DeepEqual(wanted, existing)
	default:
		return reflect.DeepEqual(desired, existing)
	}
}
