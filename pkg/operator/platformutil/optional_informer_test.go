package platformutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	operatorv1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

func TestOptionalInformer(t *testing.T) {
	type fakeInformerFactoryStub struct{}
	dummyInformerInit := func() fakeInformerFactoryStub {
		return struct{}{}
	}

	fixedGVRForTest := operatorv1alpha1.SchemeGroupVersion.WithResource("certmanagers")

	t.Run("positive cases with no expected errors", func(t *testing.T) {
		tests := []struct {
			isCRDPresent   bool
			expectInformer bool
		}{
			// positive cases with no error
			// false => false, true => true
			{isCRDPresent: false, expectInformer: false},
			{isCRDPresent: true, expectInformer: true},
		}

		for _, tt := range tests {
			fakeClient := createFakeClient(tt.isCRDPresent)

			optInformer, err := NewOptionalInformer(context.TODO(), fixedGVRForTest,
				fakeClient.Discovery(), dummyInformerInit)
			require.NoError(t, err)

			discovered, err := optInformer.discover()
			require.NoError(t, err)
			assert.Equal(t, tt.isCRDPresent, discovered, "discovery does not match CRD registration")

			assert.Equal(t, tt.expectInformer, optInformer.Applicable(), "undesired optional informer applicable(ity)")
			assert.Equal(t, tt.expectInformer, optInformer.InformerFactory != nil, "broken informer factory init func call")
		}
	})

	t.Run("negative case with an expected error", func(t *testing.T) {
		errorProneDiscoveryClient := createErroneousFakeDiscoveryClient()
		_, err := NewOptionalInformer(context.TODO(), fixedGVRForTest,
			errorProneDiscoveryClient, dummyInformerInit)

		require.Error(t, err)
	})
}
