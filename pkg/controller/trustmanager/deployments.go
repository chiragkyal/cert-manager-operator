package trustmanager

import (
	"fmt"
	"os"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// =============================================================================
// DEPLOYMENT RECONCILIATION
// =============================================================================
// The Deployment is the core resource that runs the trust-manager pod.
// We customize it based on the TrustManagerConfig:
// - Image from RELATED_IMAGE_TRUST_MANAGER env var
// - Command line args from config (logLevel, logFormat, trustNamespace, etc.)
// - Resource requirements
// - Scheduling (nodeSelector, tolerations, affinity)

// createOrApplyDeployment reconciles the trust-manager Deployment.
func (r *Reconciler) createOrApplyDeployment(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	desired := r.getDeploymentObject(trustManager, resourceLabels)
	deployName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling Deployment", "name", deployName)

	fetched := &appsv1.Deployment{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if Deployment %s exists", deployName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Deployment %s already exists", deployName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("Deployment has changed, updating", "name", deployName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update Deployment %s", deployName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Deployment %s updated", deployName)
		} else {
			r.log.V(4).Info("Deployment is in expected state", "name", deployName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create Deployment %s", deployName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Deployment %s created", deployName)
	}

	// Update status with image and secretTargets info
	if err := r.updateDeploymentStatus(trustManager, desired); err != nil {
		return FromClientError(err, "failed to update status with Deployment info")
	}

	return nil
}

// getDeploymentObject builds the Deployment with all customizations.
func (r *Reconciler) getDeploymentObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *appsv1.Deployment {
	deploy := decodeDeploymentObjBytes(assets.MustAsset(deploymentAssetName))

	// Set namespace to cert-manager
	updateNamespace(deploy, operandNamespace)

	// Apply labels to deployment metadata
	updateResourceLabels(deploy, resourceLabels)

	// Update pod template labels
	if deploy.Spec.Template.Labels == nil {
		deploy.Spec.Template.Labels = make(map[string]string)
	}
	for k, v := range resourceLabels {
		deploy.Spec.Template.Labels[k] = v
	}

	// Apply user-specified annotations if any
	if trustManager.Spec.ControllerConfig != nil && trustManager.Spec.ControllerConfig.Annotations != nil {
		updateResourceAnnotations(deploy, trustManager.Spec.ControllerConfig.Annotations)
	}

	// Update container configuration
	r.updateContainerConfig(deploy, trustManager)

	// Update scheduling configuration
	r.updateSchedulingConfig(deploy, trustManager)

	return deploy
}

// updateContainerConfig updates the trust-manager container with image and args.
func (r *Reconciler) updateContainerConfig(deploy *appsv1.Deployment, trustManager *v1alpha1.TrustManager) {
	config := trustManager.Spec.TrustManagerConfig

	// Find the trust-manager container
	var container *corev1.Container
	for i := range deploy.Spec.Template.Spec.Containers {
		if deploy.Spec.Template.Spec.Containers[i].Name == trustManagerContainerName {
			container = &deploy.Spec.Template.Spec.Containers[i]
			break
		}
	}
	if container == nil {
		r.log.Error(nil, "trust-manager container not found in deployment template")
		return
	}

	// Update image from environment variable
	image := os.Getenv(trustManagerImageNameEnvVarName)
	if image != "" {
		container.Image = image
		r.log.V(4).Info("using image from environment", "image", image)
	}

	// Build command line arguments
	container.Args = r.buildContainerArgs(config)

	// Update resource requirements if specified
	if config.Resources.Limits != nil || config.Resources.Requests != nil {
		container.Resources = config.Resources
	}

	// Configure DefaultCAPackage volume mount if enabled
	r.configureDefaultCAPackageVolume(deploy, container, config)
}

// configureDefaultCAPackageVolume adds or removes the DefaultCAPackage volume and volume mount.
func (r *Reconciler) configureDefaultCAPackageVolume(
	deploy *appsv1.Deployment,
	container *corev1.Container,
	config v1alpha1.TrustManagerConfig,
) {
	defaultCAEnabled := config.DefaultCAPackage != nil && config.DefaultCAPackage.Enabled

	// Check if volume already exists
	volumeExists := false
	volumeIndex := -1
	for i, vol := range deploy.Spec.Template.Spec.Volumes {
		if vol.Name == defaultCAPackageVolumeName {
			volumeExists = true
			volumeIndex = i
			break
		}
	}

	// Check if volume mount already exists
	mountExists := false
	mountIndex := -1
	for i, mount := range container.VolumeMounts {
		if mount.Name == defaultCAPackageVolumeName {
			mountExists = true
			mountIndex = i
			break
		}
	}

	if defaultCAEnabled {
		// Add volume if not exists
		if !volumeExists {
			volume := corev1.Volume{
				Name: defaultCAPackageVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: defaultCAPackageConfigMapName,
						},
					},
				},
			}
			deploy.Spec.Template.Spec.Volumes = append(deploy.Spec.Template.Spec.Volumes, volume)
			r.log.V(4).Info("added DefaultCAPackage volume to deployment")
		}

		// Add volume mount if not exists
		if !mountExists {
			volumeMount := corev1.VolumeMount{
				Name:      defaultCAPackageVolumeName,
				MountPath: defaultCAPackageVolumeMountPath,
				ReadOnly:  true,
			}
			container.VolumeMounts = append(container.VolumeMounts, volumeMount)
			r.log.V(4).Info("added DefaultCAPackage volume mount to container")
		}
	} else {
		// Remove volume if exists
		if volumeExists && volumeIndex >= 0 {
			deploy.Spec.Template.Spec.Volumes = append(
				deploy.Spec.Template.Spec.Volumes[:volumeIndex],
				deploy.Spec.Template.Spec.Volumes[volumeIndex+1:]...,
			)
			r.log.V(4).Info("removed DefaultCAPackage volume from deployment")
		}

		// Remove volume mount if exists
		if mountExists && mountIndex >= 0 {
			container.VolumeMounts = append(
				container.VolumeMounts[:mountIndex],
				container.VolumeMounts[mountIndex+1:]...,
			)
			r.log.V(4).Info("removed DefaultCAPackage volume mount from container")
		}
	}
}

// buildContainerArgs builds the command line arguments for trust-manager.
func (r *Reconciler) buildContainerArgs(config v1alpha1.TrustManagerConfig) []string {
	args := []string{
		// Log configuration
		fmt.Sprintf("%s=%s", argLogFormat, getLogFormat(config.LogFormat)),
		fmt.Sprintf("%s=%d", argLogLevel, getLogLevel(config.LogLevel)),

		// Fixed args (from bindata, not configurable)
		"--metrics-port=9402",
		"--readiness-probe-port=6060",
		"--readiness-probe-path=/readyz",
		"--leader-elect=true",
		"--leader-election-lease-duration=15s",
		"--leader-election-renew-deadline=10s",
		"--webhook-host=0.0.0.0",
		"--webhook-port=6443",
		"--webhook-certificate-dir=/tls",

		// Trust namespace
		fmt.Sprintf("%s=%s", argTrustNamespace, getTrustNamespace(config.TrustNamespace)),
	}

	// Default CA package location
	// If DefaultCAPackage is enabled, use the OpenShift package location
	// Otherwise, don't set the argument (no default package)
	if config.DefaultCAPackage != nil && config.DefaultCAPackage.Enabled {
		args = append(args, fmt.Sprintf("%s=%s", argDefaultPackageLocation, defaultCAPackageLocation))
	}
	// Note: If DefaultCAPackage is not enabled, we don't set --default-package-location
	// This means trust-manager won't have a default package and Bundles using
	// useDefaultCAs: true will fail validation

	// Secret targets configuration
	secretTargetsEnabled := false
	if config.SecretTargets != nil && config.SecretTargets.Enabled {
		secretTargetsEnabled = true
	}
	args = append(args, fmt.Sprintf("%s=%s", argSecretTargetsEnabled, strconv.FormatBool(secretTargetsEnabled)))

	// Filter expired certificates
	if config.FilterExpiredCertificates {
		args = append(args, fmt.Sprintf("%s=%s", argFilterExpiredCertificates, "true"))
	}

	return args
}

// updateSchedulingConfig updates scheduling-related pod spec fields.
func (r *Reconciler) updateSchedulingConfig(deploy *appsv1.Deployment, trustManager *v1alpha1.TrustManager) {
	config := trustManager.Spec.TrustManagerConfig

	// Node selector
	if len(config.NodeSelector) > 0 {
		if deploy.Spec.Template.Spec.NodeSelector == nil {
			deploy.Spec.Template.Spec.NodeSelector = make(map[string]string)
		}
		for k, v := range config.NodeSelector {
			deploy.Spec.Template.Spec.NodeSelector[k] = v
		}
	}

	// Tolerations
	if len(config.Tolerations) > 0 {
		deploy.Spec.Template.Spec.Tolerations = config.Tolerations
	}

	// Affinity
	if config.Affinity != nil {
		deploy.Spec.Template.Spec.Affinity = config.Affinity
	}
}

// updateDeploymentStatus updates the TrustManager status with deployment info.
func (r *Reconciler) updateDeploymentStatus(trustManager *v1alpha1.TrustManager, deploy *appsv1.Deployment) error {
	changed := false

	// Get image from container
	var image string
	for _, container := range deploy.Spec.Template.Spec.Containers {
		if container.Name == trustManagerContainerName {
			image = container.Image
			break
		}
	}

	if trustManager.Status.TrustManagerImage != image {
		trustManager.Status.TrustManagerImage = image
		changed = true
	}

	// Update secretTargetsEnabled status
	secretTargetsEnabled := false
	if trustManager.Spec.TrustManagerConfig.SecretTargets != nil {
		secretTargetsEnabled = trustManager.Spec.TrustManagerConfig.SecretTargets.Enabled
	}
	if trustManager.Status.SecretTargetsEnabled != secretTargetsEnabled {
		trustManager.Status.SecretTargetsEnabled = secretTargetsEnabled
		changed = true
	}

	if changed {
		return r.updateStatus(r.ctx, trustManager)
	}

	return nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getLogFormat returns the log format, defaulting to "text".
func getLogFormat(format string) string {
	if format == "" {
		return "text"
	}
	return format
}

// getLogLevel returns the log level, defaulting to 1.
func getLogLevel(level int32) int32 {
	if level == 0 {
		return 1
	}
	return level
}

// getTrustNamespace returns the trust namespace, defaulting to "cert-manager".
func getTrustNamespace(ns string) string {
	if ns == "" {
		return "cert-manager"
	}
	return ns
}
