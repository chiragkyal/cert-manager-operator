package trustmanager

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

// =============================================================================
// DEFAULT CA PACKAGE RECONCILIATION
// =============================================================================
// This file implements the OpenShift-specific default CA package feature.
//
// Instead of using the upstream Debian-based init container to provide the
// default CA bundle, we leverage OpenShift's native trusted CA bundle injection
// mechanism via the Cluster Network Operator (CNO).
//
// ## Workflow:
// 1. Operator creates a ConfigMap with annotation "config.openshift.io/inject-trusted-cabundle: true"
// 2. CNO detects this annotation and injects the cluster's trusted CA bundle into the ConfigMap
// 3. Operator reads the injected bundle from the "ca-bundle.crt" key
// 4. Operator formats the bundle into trust-manager's expected JSON format
// 5. Operator creates a second ConfigMap containing this JSON package
// 6. This package ConfigMap is mounted to trust-manager at /packages
// 7. trust-manager is started with --default-package-location=/packages/cert-manager-package-openshift.json
//
// ## Benefits:
// - Uses CA certificates that OpenShift explicitly trusts
// - Automatically updates when cluster CA bundle changes
// - No dependency on external Debian package images
// - Works in air-gapped environments

// trustPackage represents the JSON structure expected by trust-manager
// for the default CA package.
//
// The upstream format is produced by jq in debian-trust-package-fetch.sh:
//
//	echo "{}" | jq \
//	  --rawfile bundle $TMP_DIR/ca-certificates.crt \
//	  --arg name "$PACKAGE_NAME" \
//	  --arg version "$installed_version$version_suffix" \
//	  '.name = $name | .bundle = $bundle | .version = $version'
//
// This produces JSON like:
//
//	{
//	  "name": "cert-manager-package-debian",
//	  "bundle": "-----BEGIN CERTIFICATE-----\nMIIF3jCC...",
//	  "version": "20230311.0"
//	}
//
// Go's json.Marshal properly escapes the bundle string (newlines become \n, etc.)
// which matches the jq --rawfile behavior.
//
// See: https://github.com/cert-manager/trust-manager/blob/main/make/debian-trust-package-fetch.sh#L144-L151
type trustPackage struct {
	Name    string `json:"name"`
	Bundle  string `json:"bundle"`
	Version string `json:"version"`
}

// createOrApplyDefaultCAPackage reconciles the default CA package ConfigMaps.
// This is only called when DefaultCAPackage.Enabled is true.
//
// Returns:
// - (true, nil) if the CA bundle is not yet injected by CNO (should requeue)
// - (false, nil) if reconciliation was successful
// - (false, error) if there was an error
func (r *Reconciler) createOrApplyDefaultCAPackage(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) (bool, error) {
	r.log.V(2).Info("reconciling default CA package")

	// Step 1: Create or update the injection ConfigMap
	// CNO will inject the trusted CA bundle into this ConfigMap
	if err := r.createOrApplyInjectionConfigMap(trustManager, resourceLabels, isNewReconcile); err != nil {
		return false, err
	}

	// Step 2: Read the injected CA bundle from the injection ConfigMap
	caBundle, resourceVersion, err := r.readInjectedCABundle()
	if err != nil {
		return false, err
	}

	// If CA bundle is empty, CNO hasn't injected it yet - requeue
	if caBundle == "" {
		r.log.V(1).Info("CA bundle not yet injected by CNO, will requeue",
			"configMap", defaultCAInjectionConfigMapName)
		return true, nil
	}

	r.log.V(2).Info("read injected CA bundle",
		"configMap", defaultCAInjectionConfigMapName,
		"bundleLength", len(caBundle),
		"resourceVersion", resourceVersion)

	// Step 3: Format the CA bundle into trust-manager's JSON package format
	packageJSON, err := formatTrustPackage(caBundle, resourceVersion)
	if err != nil {
		return false, NewIrrecoverableError(err, "failed to format trust package")
	}

	// Step 4: Create or update the package ConfigMap
	if err := r.createOrApplyPackageConfigMap(trustManager, resourceLabels, packageJSON, isNewReconcile); err != nil {
		return false, err
	}

	// Step 5: Update status
	if err := r.updateDefaultCAPackageStatus(trustManager, true); err != nil {
		return false, err
	}

	return false, nil
}

// createOrApplyInjectionConfigMap creates or updates the ConfigMap that CNO
// will inject the trusted CA bundle into.
func (r *Reconciler) createOrApplyInjectionConfigMap(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	configMapName := fmt.Sprintf("%s/%s", operandNamespace, defaultCAInjectionConfigMapName)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultCAInjectionConfigMapName,
			Namespace: operandNamespace,
			Labels:    resourceLabels,
			Annotations: map[string]string{
				// This annotation triggers CNO to inject the trusted CA bundle
				cnoInjectTrustedCABundleAnnotation: "true",
			},
		},
		// Data will be populated by CNO with the ca-bundle.crt key
		Data: map[string]string{},
	}

	r.log.V(4).Info("reconciling injection ConfigMap", "name", configMapName)

	fetched := &corev1.ConfigMap{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if injection ConfigMap %s exists", configMapName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Injection ConfigMap %s already exists", configMapName)
		}

		// Check if labels and annotation are correct
		needsUpdate := false

		// Ensure annotation is present
		if fetched.Annotations == nil || fetched.Annotations[cnoInjectTrustedCABundleAnnotation] != "true" {
			if fetched.Annotations == nil {
				fetched.Annotations = make(map[string]string)
			}
			fetched.Annotations[cnoInjectTrustedCABundleAnnotation] = "true"
			needsUpdate = true
		}

		// Ensure labels are present
		for k, v := range resourceLabels {
			if fetched.Labels == nil || fetched.Labels[k] != v {
				if fetched.Labels == nil {
					fetched.Labels = make(map[string]string)
				}
				fetched.Labels[k] = v
				needsUpdate = true
			}
		}

		if needsUpdate {
			r.log.V(2).Info("injection ConfigMap needs update", "name", configMapName)
			if err := r.Update(r.ctx, fetched); err != nil {
				return FromClientError(err, "failed to update injection ConfigMap %s", configMapName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Injection ConfigMap %s updated", configMapName)
		} else {
			r.log.V(4).Info("injection ConfigMap is in expected state", "name", configMapName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create injection ConfigMap %s", configMapName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Injection ConfigMap %s created", configMapName)
	}

	return nil
}

// readInjectedCABundle reads the CA bundle injected by CNO from the injection ConfigMap.
// Returns the CA bundle, the ConfigMap's resource version, and any error.
// Returns empty string if the CA bundle hasn't been injected yet.
func (r *Reconciler) readInjectedCABundle() (string, string, error) {
	configMap := &corev1.ConfigMap{}
	key := client.ObjectKey{
		Namespace: operandNamespace,
		Name:      defaultCAInjectionConfigMapName,
	}

	if err := r.Get(r.ctx, key, configMap); err != nil {
		if errors.IsNotFound(err) {
			return "", "", nil // ConfigMap doesn't exist yet
		}
		return "", "", FromClientError(err, "failed to get injection ConfigMap %s/%s",
			operandNamespace, defaultCAInjectionConfigMapName)
	}

	caBundle, exists := configMap.Data[cnoInjectedCABundleKey]
	if !exists || caBundle == "" {
		return "", configMap.ResourceVersion, nil // CNO hasn't injected the bundle yet
	}

	return caBundle, configMap.ResourceVersion, nil
}

// formatTrustPackage creates the JSON package in the format expected by trust-manager.
//
// The format follows upstream's debian-trust-package-fetch.sh output:
// - name: Package identifier (e.g., "cert-manager-package-openshift")
// - bundle: PEM-encoded CA certificates (Go's json.Marshal escapes newlines as \n)
// - version: Version string with .0 suffix (upstream uses "<ca-certificates-version>.0")
//
// We use the ConfigMap's resourceVersion as the version base since the CA bundle
// content changes when CNO updates it, which increments the resourceVersion.
func formatTrustPackage(caBundle, resourceVersion string) (string, error) {
	pkg := trustPackage{
		Name:    defaultCAPackageName,
		Bundle:  caBundle,
		Version: resourceVersion + ".0", // Append .0 to match upstream versioning pattern
	}

	// jq produces pretty-printed JSON by default, so we use MarshalIndent
	// trust-manager's JSON parser handles both compact and pretty-printed formats
	jsonBytes, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal trust package to JSON: %w", err)
	}

	return string(jsonBytes), nil
}

// createOrApplyPackageConfigMap creates or updates the ConfigMap containing
// the formatted JSON package that will be mounted to trust-manager.
func (r *Reconciler) createOrApplyPackageConfigMap(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	packageJSON string,
	isNewReconcile bool,
) error {
	configMapName := fmt.Sprintf("%s/%s", operandNamespace, defaultCAPackageConfigMapName)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultCAPackageConfigMapName,
			Namespace: operandNamespace,
			Labels:    resourceLabels,
		},
		Data: map[string]string{
			defaultCAPackageJSONFile: packageJSON,
		},
	}

	r.log.V(4).Info("reconciling package ConfigMap", "name", configMapName)

	fetched := &corev1.ConfigMap{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if package ConfigMap %s exists", configMapName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Package ConfigMap %s already exists", configMapName)
		}

		// Check if data has changed
		if fetched.Data[defaultCAPackageJSONFile] != packageJSON {
			r.log.V(2).Info("package ConfigMap data has changed, updating", "name", configMapName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update package ConfigMap %s", configMapName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Package ConfigMap %s updated with new CA bundle", configMapName)
		} else {
			r.log.V(4).Info("package ConfigMap is in expected state", "name", configMapName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create package ConfigMap %s", configMapName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Package ConfigMap %s created", configMapName)
	}

	return nil
}

// updateDefaultCAPackageStatus updates the TrustManager status with DefaultCAPackage info.
func (r *Reconciler) updateDefaultCAPackageStatus(trustManager *v1alpha1.TrustManager, enabled bool) error {
	if trustManager.Status.DefaultCAPackage == nil {
		trustManager.Status.DefaultCAPackage = &v1alpha1.DefaultCAPackageStatus{}
	}

	if trustManager.Status.DefaultCAPackage.Enabled != enabled {
		trustManager.Status.DefaultCAPackage.Enabled = enabled
		return r.updateStatus(r.ctx, trustManager)
	}

	return nil
}

// deleteDefaultCAPackageConfigMaps deletes the ConfigMaps created for the default CA package.
func (r *Reconciler) deleteDefaultCAPackageConfigMaps() error {
	configMapsToDelete := []string{
		defaultCAInjectionConfigMapName,
		defaultCAPackageConfigMapName,
	}

	for _, name := range configMapsToDelete {
		configMap := &corev1.ConfigMap{}
		key := client.ObjectKey{
			Namespace: operandNamespace,
			Name:      name,
		}

		if err := r.Get(r.ctx, key, configMap); err != nil {
			if errors.IsNotFound(err) {
				continue // Already deleted
			}
			return FromClientError(err, "failed to get ConfigMap %s/%s for deletion", operandNamespace, name)
		}

		// Only delete if it has our label
		if configMap.Labels != nil && configMap.Labels[requestEnqueueLabelKey] == requestEnqueueLabelValue {
			r.log.V(2).Info("deleting default CA package ConfigMap",
				"name", name, "namespace", operandNamespace)
			if err := r.Delete(r.ctx, configMap); err != nil && !errors.IsNotFound(err) {
				return FromClientError(err, "failed to delete ConfigMap %s/%s", operandNamespace, name)
			}
		}
	}

	return nil
}

// isDefaultCAPackageEnabled checks if the default CA package feature is enabled.
func isDefaultCAPackageEnabled(trustManager *v1alpha1.TrustManager) bool {
	return trustManager.Spec.TrustManagerConfig.DefaultCAPackage != nil &&
		trustManager.Spec.TrustManagerConfig.DefaultCAPackage.Enabled
}
