package approverpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

const imageEnv = "RELATED_IMAGE_APPROVER_POLICY"

const desiredStateAnnotation = "approver-policy.operator.openshift.io/desired-state-hash"

const defaultLogFormat = "text"

const secretKind = "Secret"

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

// importedResources supplies the fixed inventory even when the current image or
// user configuration is invalid. Removal must not depend on install validation.
func importedResources() ([]*unstructured.Unstructured, error) {
	objects := make([]*unstructured.Unstructured, 0, len(resourceAssets))
	for _, name := range resourceAssets {
		data, err := assets.Asset("approver-policy/resources/" + name)
		if err != nil {
			return nil, fmt.Errorf("construct approver-policy resources: %w", err)
		}
		data, err = yaml.ToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("construct approver-policy resources: %w", err)
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(data); err != nil {
			return nil, fmt.Errorf("construct approver-policy resources: %w", err)
		}
		objects = append(objects, obj)
	}
	return objects, nil
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
		config.LogFormat = defaultLogFormat
	}
	if config.LogLevel < 1 || config.LogLevel > 5 || (config.LogFormat != defaultLogFormat && config.LogFormat != "json") {
		return nil, fmt.Errorf("invalid approverPolicyConfig logging: level must be 1–5 and format text or json")
	}
	if err := validateConfiguration(manager); err != nil {
		return nil, fmt.Errorf("construct approver-policy resources: %w", err)
	}
	overlays, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&config)
	if err != nil {
		return nil, fmt.Errorf("convert approverPolicyConfig: %w", err)
	}
	objects, err := importedResources()
	if err != nil {
		return nil, fmt.Errorf("construct approver-policy resources: %w", err)
	}
	for _, obj := range objects {
		applyMetadata(obj, manager.Spec.ControllerConfig)
		obj.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(manager,
			schema.GroupVersionKind{Group: v1alpha1.SchemeGroupVersion.Group, Version: v1alpha1.SchemeGroupVersion.Version, Kind: "ApproverPolicyManager"})})
		switch obj.GetKind() {
		case "ClusterRole":
			// Signer scope is enforced by approval RBAC, not an operand flag.
			// Sort a copy so set reordering does not cause unnecessary applies.
			signerNames := slices.Clone(config.ApproveSignerNames)
			slices.Sort(signerNames)
			rules, _, err := unstructured.NestedSlice(obj.Object, "rules")
			if err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			for _, item := range rules {
				rule, ok := item.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("expected object in approver-policy ClusterRole rules")
				}
				resources, _, err := unstructured.NestedStringSlice(rule, "resources")
				if err != nil {
					return nil, fmt.Errorf("construct approver-policy resources: %w", err)
				}
				groups, _, err := unstructured.NestedStringSlice(rule, "apiGroups")
				if err != nil {
					return nil, fmt.Errorf("construct approver-policy resources: %w", err)
				}
				verbs, _, err := unstructured.NestedStringSlice(rule, "verbs")
				if err != nil {
					return nil, fmt.Errorf("construct approver-policy resources: %w", err)
				}
				if len(groups) == 1 && groups[0] == "cert-manager.io" && len(resources) == 1 && resources[0] == "signers" && slices.Contains(verbs, "approve") {
					if len(signerNames) == 0 {
						unstructured.RemoveNestedField(rule, "resourceNames")
					} else if err := unstructured.SetNestedStringSlice(rule, signerNames, "resourceNames"); err != nil {
						return nil, fmt.Errorf("construct approver-policy resources: %w", err)
					}
				}
			}
			if err := unstructured.SetNestedSlice(obj.Object, rules, "rules"); err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
		case secretKind:
			delete(obj.Object, "data")
			delete(obj.Object, "stringData")
		case "ValidatingWebhookConfiguration":
			webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
			if err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			for _, webhook := range webhooks {
				fields, ok := webhook.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("expected object in approver-policy webhooks")
				}
				unstructured.RemoveNestedField(fields, "clientConfig", "caBundle")
			}
			if err := unstructured.SetNestedSlice(obj.Object, webhooks, "webhooks"); err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
		case "Deployment":
			podMetadata, _, err := unstructured.NestedMap(obj.Object, "spec", "template", "metadata")
			if err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			pod := &unstructured.Unstructured{Object: map[string]interface{}{"metadata": podMetadata}}
			applyMetadata(pod, manager.Spec.ControllerConfig)
			podMetadata, _, err = unstructured.NestedMap(pod.Object, "metadata")
			if err != nil {
				return nil, fmt.Errorf("read overlaid approver-policy pod metadata: %w", err)
			}
			if err := unstructured.SetNestedMap(obj.Object, podMetadata, "spec", "template", "metadata"); err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			for _, key := range []string{"affinity", "tolerations"} {
				if value, ok := overlays[key]; ok {
					if err := unstructured.SetNestedField(obj.Object, value, "spec", "template", "spec", key); err != nil {
						return nil, fmt.Errorf("construct approver-policy resources: %w", err)
					}
				}
			}
			selectors, _, err := unstructured.NestedStringMap(obj.Object, "spec", "template", "spec", "nodeSelector")
			if err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			if selectors == nil {
				selectors = map[string]string{}
			}
			maps.Copy(selectors, config.NodeSelector)
			if err := unstructured.SetNestedStringMap(obj.Object, selectors, "spec", "template", "spec", "nodeSelector"); err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			containers, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
			if err != nil {
				return nil, fmt.Errorf("read approver-policy containers: %w", err)
			}
			if len(containers) != 1 {
				return nil, fmt.Errorf("expected one approver-policy container")
			}
			container, ok := containers[0].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected object in approver-policy containers")
			}
			args, _, err := unstructured.NestedStringSlice(container, "args")
			if err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			args = common.MergeContainerArgs(args, []string{fmt.Sprintf("--log-level=%d", config.LogLevel), "--log-format=" + config.LogFormat})
			if err := unstructured.SetNestedStringSlice(container, args, "args"); err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
			container["image"] = image
			if resources, ok := overlays["resources"]; ok {
				container["resources"] = resources
			}
			if err := unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers"); err != nil {
				return nil, fmt.Errorf("construct approver-policy resources: %w", err)
			}
		}
		// A subset comparison alone misses fields removed from the CR. Changing
		// this fingerprint forces SSA to relinquish/prune previously owned fields.
		// Hash only the desired projection, never server/TLS fields or the hash itself.
		data, err := json.Marshal(obj.Object)
		if err != nil {
			return nil, fmt.Errorf("construct approver-policy resources: %w", err)
		}
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[desiredStateAnnotation] = fmt.Sprintf("%x", sha256.Sum256(data))
		obj.SetAnnotations(annotations)
	}
	return objects, nil
}

func validateConfiguration(manager *v1alpha1.ApproverPolicyManager) error {
	config, metadata := manager.Spec.ApproverPolicyConfig, manager.Spec.ControllerConfig
	operandPath, controllerPath := field.NewPath("spec", "approverPolicyConfig"), field.NewPath("spec", "controllerConfig")
	for _, limit := range []struct {
		path *field.Path
		size int
		max  int
	}{
		{operandPath.Child("approveSignerNames"), len(config.ApproveSignerNames), 50},
		{operandPath.Child("tolerations"), len(config.Tolerations), 50},
		{operandPath.Child("nodeSelector"), len(config.NodeSelector), 50},
		{controllerPath.Child("labels"), len(metadata.Labels), 20},
		{controllerPath.Child("annotations"), len(metadata.Annotations), 20},
	} {
		if limit.size > limit.max {
			return field.TooMany(limit.path, limit.size, limit.max)
		}
	}
	seenSigners := make(map[string]bool, len(config.ApproveSignerNames))
	for i, signer := range config.ApproveSignerNames {
		path := operandPath.Child("approveSignerNames").Index(i)
		if size := utf8.RuneCountInString(signer); size < 1 || size > 825 {
			return field.Invalid(path, signer, "must contain between 1 and 825 characters")
		}
		if seenSigners[signer] {
			return field.Duplicate(path, signer)
		}
		seenSigners[signer] = true
	}
	for _, err := range []error{
		common.ValidateResourceRequirements(config.Resources, operandPath),
		common.ValidateAffinityRules(config.Affinity, operandPath),
		common.ValidateTolerationsConfig(config.Tolerations, operandPath),
		common.ValidateNodeSelectorConfig(config.NodeSelector, operandPath),
		common.ValidateLabelsConfig(metadata.Labels, controllerPath),
		common.ValidateAnnotationsConfig(metadata.Annotations, controllerPath),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

// Required imported metadata and the cache identity always override user values.
// Apply the same contract to resource and Pod metadata without changing selectors.
func applyMetadata(obj *unstructured.Unstructured, config v1alpha1.ApproverPolicyControllerConfig) {
	labels := map[string]string{}
	maps.Copy(labels, config.Labels)
	maps.Copy(labels, obj.GetLabels())
	labels[common.ManagedResourceLabelKey] = RequestEnqueueLabelValue
	obj.SetLabels(labels)
	annotations := map[string]string{}
	maps.Copy(annotations, config.Annotations)
	maps.Copy(annotations, obj.GetAnnotations())
	delete(annotations, desiredStateAnnotation)
	if len(annotations) > 0 {
		obj.SetAnnotations(annotations)
	}
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
	//nolint:staticcheck // Shared CtrlClient exposes SSA through Patch, not the newer Apply method.
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
