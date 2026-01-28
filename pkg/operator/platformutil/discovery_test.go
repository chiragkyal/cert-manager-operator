package platformutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	operatorv1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

func TestResourceDiscovery(t *testing.T) {
	fixedGVRForTest := operatorv1alpha1.SchemeGroupVersion.WithResource("certmanagers")

	t.Run("resource exists", func(t *testing.T) {
		fakeClient := createFakeClient(true)
		discovery := NewResourceDiscovery(fakeClient.Discovery())

		exists, err := discovery.ResourceExists(fixedGVRForTest)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("resource does not exist", func(t *testing.T) {
		fakeClient := createFakeClient(false)
		discovery := NewResourceDiscovery(fakeClient.Discovery())

		exists, err := discovery.ResourceExists(fixedGVRForTest)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("discovery error", func(t *testing.T) {
		errorProneDiscoveryClient := createErroneousFakeDiscoveryClient()
		discovery := NewResourceDiscovery(errorProneDiscoveryClient)

		_, err := discovery.ResourceExists(fixedGVRForTest)
		require.Error(t, err)
	})
}
