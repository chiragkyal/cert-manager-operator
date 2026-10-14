package operator

import (
	"fmt"
	"testing"

	"github.com/openshift/cert-manager-operator/pkg/features"
	"github.com/stretchr/testify/require"
)

func TestConfiguredOperandControllers(t *testing.T) {
	t.Cleanup(func() {
		require.NoError(t, features.SetupWithFlagValue("IstioCSR=true,TrustManager=false,ApproverPolicyManager=false"))
	})
	for bits := range 8 {
		want := ControllerConfig{EnableIstioCSR: bits&1 != 0, EnableTrustManager: bits&2 != 0, EnableApproverPolicyManager: bits&4 != 0}
		require.NoError(t, features.SetupWithFlagValue(fmt.Sprintf("IstioCSR=%t,TrustManager=%t,ApproverPolicyManager=%t", want.EnableIstioCSR, want.EnableTrustManager, want.EnableApproverPolicyManager)))
		// No cluster FeatureGate state is required to select internal controllers.
		require.Equal(t, want, configuredOperandControllers(nil))
	}
}
