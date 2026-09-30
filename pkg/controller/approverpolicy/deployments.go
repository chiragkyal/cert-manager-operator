package approverpolicy

import (
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

func (r *Reconciler) createOrApplyDeployment(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) error {
	desired, err := r.getDeploymentObject(apm, resourceLabels, resourceAnnotations)
	if err != nil {
		return err
	}

	deploymentName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())
	r.log.V(4).Info("reconciling deployment resource", "name", deploymentName)

	existing := &appsv1.Deployment{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		return common.FromClientError(err, "failed to check if deployment %q exists", deploymentName)
	}
	if exists && !deploymentModified(desired, existing) {
		r.log.V(4).Info("deployment resource exists and is in desired state", "name", deploymentName)
		return nil
	}

	r.log.V(2).Info("deployment resource has been modified, updating to desired state", "name", deploymentName)
	if err := r.Patch(r.ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return common.FromClientError(err, "failed to apply deployment %q", deploymentName)
	}

	r.eventRecorder.Eventf(apm, corev1.EventTypeNormal, "Reconciled", "deployment resource %s applied", deploymentName)
	return nil
}

func (r *Reconciler) getDeploymentObject(apm *v1alpha1.ApproverPolicyManager, resourceLabels, resourceAnnotations map[string]string) (*appsv1.Deployment, error) {
	deployment := common.DecodeObjBytes[*appsv1.Deployment](codecs, appsv1.SchemeGroupVersion, assets.MustAsset(deploymentAssetName))

	if err := validateDeploymentManifest(deployment); err != nil {
		return nil, common.NewIrrecoverableError(err, "invalid approver-policy deployment manifest")
	}

	common.UpdateName(deployment, approverPolicyDeploymentName)
	common.UpdateNamespace(deployment, operandNamespace)
	common.UpdateResourceLabels(deployment, resourceLabels)
	updateResourceAnnotations(deployment, resourceAnnotations)
	updatePodTemplateLabels(deployment, resourceLabels)
	updateDeploymentArgs(deployment, apm)
	updateServiceAccountName(deployment)

	if err := updateImage(deployment); err != nil {
		return nil, common.NewIrrecoverableError(err, "failed to update approver-policy image")
	}

	if err := updateResourceRequirements(deployment, apm); err != nil {
		return nil, err
	}
	if err := updateAffinityRules(deployment, apm); err != nil {
		return nil, err
	}
	if err := updatePodTolerations(deployment, apm); err != nil {
		return nil, err
	}
	if err := updateNodeSelector(deployment, apm); err != nil {
		return nil, err
	}

	return deployment, nil
}

// validateDeploymentManifest checks that the bindata deployment contains the
// expected container. Without this, the update helpers silently no-op and the
// operator would apply a deployment with stale defaults.
func validateDeploymentManifest(deployment *appsv1.Deployment) error {
	for _, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == approverPolicyContainerName {
			return nil
		}
	}
	return fmt.Errorf("deployment manifest missing required container %q", approverPolicyContainerName)
}

func updatePodTemplateLabels(deployment *appsv1.Deployment, resourceLabels map[string]string) {
	deployment.Spec.Template.Labels = resourceLabels
}

func updateDeploymentArgs(deployment *appsv1.Deployment, apm *v1alpha1.ApproverPolicyManager) {
	config := apm.Spec.ApproverPolicyConfig

	args := []string{
		fmt.Sprintf("--log-format=%s", config.LogFormat),
		fmt.Sprintf("--log-level=%d", config.LogLevel),
		"--metrics-bind-address=:9402",
		"--readiness-probe-bind-address=:6060",
		"--webhook-host=0.0.0.0",
		"--webhook-port=10250",
		fmt.Sprintf("--webhook-service-name=%s", approverPolicyServiceName),
		fmt.Sprintf("--webhook-ca-secret-namespace=%s", operandNamespace),
		fmt.Sprintf("--webhook-ca-secret-name=%s", webhookTLSSecretName),
	}

	for i, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == approverPolicyContainerName {
			deployment.Spec.Template.Spec.Containers[i].Args = args
		}
	}
}

func updateImage(deployment *appsv1.Deployment) error {
	image := os.Getenv(approverPolicyImageNameEnvVarName)
	if image == "" {
		return fmt.Errorf("%s environment variable with approver-policy image not set", approverPolicyImageNameEnvVarName)
	}
	for i, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == approverPolicyContainerName {
			deployment.Spec.Template.Spec.Containers[i].Image = image
		}
	}
	return nil
}

func updateResourceRequirements(deployment *appsv1.Deployment, apm *v1alpha1.ApproverPolicyManager) error {
	resources := apm.Spec.ApproverPolicyConfig.Resources
	if len(resources.Limits) == 0 && len(resources.Requests) == 0 {
		return nil
	}
	if err := common.ValidateResourceRequirements(resources, approverPolicyConfigFieldPath); err != nil {
		return err
	}
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == approverPolicyContainerName {
			deployment.Spec.Template.Spec.Containers[i].Resources = resources
		}
	}
	return nil
}

func updateAffinityRules(deployment *appsv1.Deployment, apm *v1alpha1.ApproverPolicyManager) error {
	if apm.Spec.ApproverPolicyConfig.Affinity == nil {
		return nil
	}
	if err := common.ValidateAffinityRules(apm.Spec.ApproverPolicyConfig.Affinity, approverPolicyConfigFieldPath); err != nil {
		return err
	}
	deployment.Spec.Template.Spec.Affinity = apm.Spec.ApproverPolicyConfig.Affinity
	return nil
}

func updatePodTolerations(deployment *appsv1.Deployment, apm *v1alpha1.ApproverPolicyManager) error {
	if apm.Spec.ApproverPolicyConfig.Tolerations == nil {
		return nil
	}
	if err := common.ValidateTolerationsConfig(apm.Spec.ApproverPolicyConfig.Tolerations, approverPolicyConfigFieldPath); err != nil {
		return err
	}
	deployment.Spec.Template.Spec.Tolerations = apm.Spec.ApproverPolicyConfig.Tolerations
	return nil
}

func updateNodeSelector(deployment *appsv1.Deployment, apm *v1alpha1.ApproverPolicyManager) error {
	if apm.Spec.ApproverPolicyConfig.NodeSelector == nil {
		return nil
	}
	if err := common.ValidateNodeSelectorConfig(apm.Spec.ApproverPolicyConfig.NodeSelector, approverPolicyConfigFieldPath); err != nil {
		return err
	}
	if deployment.Spec.Template.Spec.NodeSelector == nil {
		deployment.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}
	// Merge user-specified node selectors with any default selectors from the manifest.
	// User-specified selectors take precedence.
	for k, v := range apm.Spec.ApproverPolicyConfig.NodeSelector {
		deployment.Spec.Template.Spec.NodeSelector[k] = v
	}
	return nil
}

func updateServiceAccountName(deployment *appsv1.Deployment) {
	deployment.Spec.Template.Spec.ServiceAccountName = approverPolicyServiceAccountName
}

// deploymentModified compares only the fields we manage via SSA.
// For the readiness probe, only the fields explicitly set in our bindata are
// compared to avoid false positives from API-server-defaulted probe scalars
// (TimeoutSeconds, SuccessThreshold, FailureThreshold).
func deploymentModified(desired, existing *appsv1.Deployment) bool {
	if managedMetadataModified(desired, existing) {
		return true
	}

	if !ptr.Equal(desired.Spec.Replicas, existing.Spec.Replicas) ||
		!reflect.DeepEqual(desired.Spec.Selector, existing.Spec.Selector) {
		return true
	}

	if !maps.Equal(desired.Spec.Template.Labels, existing.Spec.Template.Labels) ||
		!maps.Equal(desired.Spec.Template.Annotations, existing.Spec.Template.Annotations) {
		return true
	}

	desiredPodSpec := desired.Spec.Template.Spec
	existingPodSpec := existing.Spec.Template.Spec

	if desiredPodSpec.ServiceAccountName != existingPodSpec.ServiceAccountName ||
		!maps.Equal(desiredPodSpec.NodeSelector, existingPodSpec.NodeSelector) ||
		!reflect.DeepEqual(desiredPodSpec.Affinity, existingPodSpec.Affinity) ||
		!reflect.DeepEqual(desiredPodSpec.Tolerations, existingPodSpec.Tolerations) {
		return true
	}

	if len(desiredPodSpec.Containers) != len(existingPodSpec.Containers) {
		return true
	}

	for i := range desiredPodSpec.Containers {
		if containerModified(&desiredPodSpec.Containers[i], &existingPodSpec.Containers[i]) {
			return true
		}
	}

	return false
}

func containerModified(desired, existing *corev1.Container) bool {
	if desired.Name != existing.Name ||
		desired.Image != existing.Image ||
		desired.ImagePullPolicy != existing.ImagePullPolicy {
		return true
	}

	if !slices.Equal(desired.Args, existing.Args) ||
		!reflect.DeepEqual(desired.Resources, existing.Resources) ||
		!reflect.DeepEqual(desired.SecurityContext, existing.SecurityContext) {
		return true
	}

	if !containerPortsMatch(desired.Ports, existing.Ports) {
		return true
	}

	if readinessProbeModified(desired.ReadinessProbe, existing.ReadinessProbe) {
		return true
	}

	return false
}

func containerPortsMatch(desired, existing []corev1.ContainerPort) bool {
	if len(desired) != len(existing) {
		return false
	}
	for _, dp := range desired {
		matched := false
		for _, ep := range existing {
			if dp.ContainerPort == ep.ContainerPort && dp.Name == ep.Name {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// readinessProbeModified compares only the probe fields we explicitly set in
// bindata (HTTPGet, InitialDelaySeconds, PeriodSeconds), avoiding
// API-server-defaulted int32 fields like TimeoutSeconds and FailureThreshold.
func readinessProbeModified(desired, existing *corev1.Probe) bool {
	if desired == nil && existing == nil {
		return false
	}
	if desired == nil || existing == nil {
		return true
	}
	if desired.InitialDelaySeconds != existing.InitialDelaySeconds ||
		desired.PeriodSeconds != existing.PeriodSeconds {
		return true
	}
	if desired.HTTPGet != nil && existing.HTTPGet != nil {
		if desired.HTTPGet.Path != existing.HTTPGet.Path ||
			desired.HTTPGet.Port != existing.HTTPGet.Port {
			return true
		}
	} else if desired.HTTPGet != existing.HTTPGet {
		return true
	}
	return false
}
