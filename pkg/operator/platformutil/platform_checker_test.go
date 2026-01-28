package platformutil

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakediscovery "k8s.io/client-go/discovery/fake"
)

// fakeFeatureGatesGetter implements configv1client.FeatureGatesGetter for testing
type fakeFeatureGatesGetter struct {
	featureGate *configv1.FeatureGate
	err         error
}

func (f *fakeFeatureGatesGetter) FeatureGates() configv1client.FeatureGateInterface {
	return &fakeFeatureGateInterface{
		featureGate: f.featureGate,
		err:         f.err,
	}
}

// fakeFeatureGateInterface implements configv1client.FeatureGateInterface for testing
// Only Get is implemented since that's all we use
type fakeFeatureGateInterface struct {
	configv1client.FeatureGateInterface
	featureGate *configv1.FeatureGate
	err         error
}

func (f *fakeFeatureGateInterface) Get(ctx context.Context, name string, opts metav1.GetOptions) (*configv1.FeatureGate, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.featureGate, nil
}

func createFeatureGate(featureSet configv1.FeatureSet) *configv1.FeatureGate {
	return &configv1.FeatureGate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.FeatureGateSpec{
			FeatureGateSelection: configv1.FeatureGateSelection{
				FeatureSet: featureSet,
			},
		},
	}
}

func createFakeDiscoveryWithFeatureGates(hasFeatureGatesCRD bool) *fakediscovery.FakeDiscovery {
	var resources []*metav1.APIResourceList
	if hasFeatureGatesCRD {
		resources = []*metav1.APIResourceList{
			{
				GroupVersion: "config.openshift.io/v1",
				APIResources: []metav1.APIResource{
					{
						Name:    "featuregates",
						Group:   "config.openshift.io",
						Version: "v1",
						Kind:    "FeatureGate",
					},
				},
			},
		}
	}
	return createFakeDiscoveryWithResources(resources)
}

func TestIsTechPreviewAllowed(t *testing.T) {
	ctx := context.Background()

	t.Run("platform without FeatureSet gating - always allowed", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(false)
		checker := NewPlatformChecker(discovery, nil) // configGetter not needed when FeatureSet gating is absent

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, reason, "not enforced")
	})

	t.Run("TechPreviewNoUpgrade FeatureSet - allowed", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(true)
		configGetter := &fakeFeatureGatesGetter{
			featureGate: createFeatureGate(configv1.TechPreviewNoUpgrade),
		}
		checker := NewPlatformChecker(discovery, configGetter)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, reason, "TechPreview-compatible")
	})

	t.Run("DevPreviewNoUpgrade FeatureSet - allowed", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(true)
		configGetter := &fakeFeatureGatesGetter{
			featureGate: createFeatureGate(configv1.DevPreviewNoUpgrade),
		}
		checker := NewPlatformChecker(discovery, configGetter)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, reason, "TechPreview-compatible")
	})

	t.Run("CustomNoUpgrade FeatureSet - allowed", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(true)
		configGetter := &fakeFeatureGatesGetter{
			featureGate: createFeatureGate(configv1.CustomNoUpgrade),
		}
		checker := NewPlatformChecker(discovery, configGetter)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, reason, "TechPreview-compatible")
	})

	t.Run("Default FeatureSet - not allowed", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(true)
		configGetter := &fakeFeatureGatesGetter{
			featureGate: createFeatureGate(configv1.Default),
		}
		checker := NewPlatformChecker(discovery, configGetter)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Contains(t, reason, "not enabled")
	})

	t.Run("empty FeatureSet - not allowed", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(true)
		configGetter := &fakeFeatureGatesGetter{
			featureGate: createFeatureGate(""), // empty string is Default
		}
		checker := NewPlatformChecker(discovery, configGetter)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Contains(t, reason, "not enabled")
	})

	t.Run("discovery error", func(t *testing.T) {
		// Use the erroneous discovery client from testing helpers
		discovery := createErroneousFakeDiscoveryClient()
		checker := NewPlatformChecker(discovery, nil)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, reason, "failed to detect platform")
	})

	t.Run("featuregate get error", func(t *testing.T) {
		discovery := createFakeDiscoveryWithFeatureGates(true)
		configGetter := &fakeFeatureGatesGetter{
			err: errors.New("failed to get featuregate"),
		}
		checker := NewPlatformChecker(discovery, configGetter)

		allowed, reason, err := checker.IsTechPreviewAllowed(ctx)
		require.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, reason, "failed to check FeatureSet")
	})
}
