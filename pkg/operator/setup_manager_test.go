package operator

import (
	"reflect"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/approverpolicy"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/controller/istiocsr"
	"github.com/openshift/cert-manager-operator/pkg/controller/trustmanager"
)

func TestOptionalControllerRegistrationAndCache(t *testing.T) {
	for bits := 0; bits < 8; bits++ {
		config := ControllerConfig{EnableIstioCSR: bits&1 != 0, EnableTrustManager: bits&2 != 0, EnableApproverPolicyManager: bits&4 != 0}
		var expected []func(ctrl.Manager) error
		if config.EnableIstioCSR {
			expected = append(expected, setupIstioCSRController)
		}
		if config.EnableTrustManager {
			expected = append(expected, setupTrustManagerController)
		}
		if config.EnableApproverPolicyManager {
			expected = append(expected, setupApproverPolicyController)
		}
		actual := enabledControllerSetups(config)
		require.Len(t, actual, len(expected))
		for i := range expected {
			require.Equal(t, reflect.ValueOf(expected[i]).Pointer(), reflect.ValueOf(actual[i]).Pointer())
		}
		objects, err := buildCacheObjectList(config)
		require.NoError(t, err)
		_, _, found := findExistingCacheEntry(objects, &v1alpha1.ApproverPolicyManager{})
		require.Equal(t, config.EnableApproverPolicyManager, found)
		for _, obj := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}, &certmanagerv1.Issuer{}, &certmanagerv1.ClusterIssuer{}} {
			_, _, found := findExistingCacheEntry(objects, obj)
			require.False(t, found, "%T must remain unfiltered", obj)
		}
		_, deployment, found := findExistingCacheEntry(objects, &appsv1.Deployment{})
		if bits == 0 {
			require.False(t, found)
			continue
		}
		require.True(t, found)
		for value, enabled := range map[string]bool{istiocsr.RequestEnqueueLabelValue: config.EnableIstioCSR, trustmanager.RequestEnqueueLabelValue: config.EnableTrustManager, approverpolicy.RequestEnqueueLabelValue: config.EnableApproverPolicyManager} {
			require.Equal(t, enabled, deployment.Label.Matches(labels.Set{common.ManagedResourceLabelKey: value}))
		}
		require.False(t, deployment.Label.Matches(labels.Set{common.ManagedResourceLabelKey: "unrelated"}))
	}
}
