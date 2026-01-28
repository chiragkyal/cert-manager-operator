package platformutil

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
)

// featureGatesGVR is the GroupVersionResource for OpenShift FeatureGates.
var featureGatesGVR = schema.GroupVersionResource{
	Group:    "config.openshift.io",
	Version:  "v1",
	Resource: "featuregates",
}

// techPreviewCompatibleFeatureSets contains the OpenShift FeatureSets that allow TechPreview features
var techPreviewCompatibleFeatureSets = map[configv1.FeatureSet]bool{
	configv1.TechPreviewNoUpgrade: true,
	configv1.DevPreviewNoUpgrade:  true,
	configv1.CustomNoUpgrade:      true,
}

// PlatformChecker provides methods to check platform-specific capabilities.
type PlatformChecker struct {
	discovery    *ResourceDiscovery
	configGetter configv1client.FeatureGatesGetter
}

// NewPlatformChecker creates a new PlatformChecker
func NewPlatformChecker(discoveryClient discovery.DiscoveryInterface, configGetter configv1client.FeatureGatesGetter) *PlatformChecker {
	return &PlatformChecker{
		discovery:    NewResourceDiscovery(discoveryClient),
		configGetter: configGetter,
	}
}

// IsTechPreviewAllowed checks if TechPreview features are allowed on this platform.
// On OpenShift: requires TechPreview-compatible FeatureSet (TechPreviewNoUpgrade, DevPreviewNoUpgrade, or CustomNoUpgrade)
// On MicroShift: always allowed (FeatureSet gating is not enforced)
func (p *PlatformChecker) IsTechPreviewAllowed(ctx context.Context) (bool, string, error) {
	// Check if featuregates.config.openshift.io CRD exists (OpenShift has it, MicroShift doesn't)
	isOpenShift, err := p.discovery.ResourceExists(featureGatesGVR)
	if err != nil {
		return false, "failed to detect platform type", fmt.Errorf("failed to detect platform: %w", err)
	}

	if !isOpenShift {
		// MicroShift - FeatureSet gating is not enforced
		return true, "FeatureSet gating not enforced on this platform", nil
	}

	// OpenShift - check FeatureSet
	featureGate, err := p.configGetter.FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, "failed to check FeatureSet", fmt.Errorf("failed to get featuregate/cluster: %w", err)
	}

	if techPreviewCompatibleFeatureSets[featureGate.Spec.FeatureSet] {
		return true, "TechPreview-compatible FeatureSet enabled", nil
	}

	return false, "TechPreview-compatible FeatureSet not enabled (requires TechPreviewNoUpgrade, DevPreviewNoUpgrade, or CustomNoUpgrade)", nil
}
