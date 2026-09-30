package certmanager

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	operatorv1alpha1lister "github.com/openshift/cert-manager-operator/pkg/operator/listers/operator/v1alpha1"
)

// fakeApproverPolicyManagerInformer implements operatorv1alpha1informer.ApproverPolicyManagerInformer
// for tests, wrapping a lister backed by a plain cache.Indexer.
type fakeApproverPolicyManagerInformer struct {
	lister operatorv1alpha1lister.ApproverPolicyManagerLister
}

func (f *fakeApproverPolicyManagerInformer) Informer() cache.SharedIndexInformer {
	return nil
}

func (f *fakeApproverPolicyManagerInformer) Lister() operatorv1alpha1lister.ApproverPolicyManagerLister {
	return f.lister
}

func newTestApproverPolicyManagerLister(t *testing.T, objs ...*v1alpha1.ApproverPolicyManager) operatorv1alpha1lister.ApproverPolicyManagerLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, obj := range objs {
		require.NoError(t, indexer.Add(obj))
	}
	return operatorv1alpha1lister.NewApproverPolicyManagerLister(indexer)
}

func newTestClusterRoleLister(t *testing.T, objs ...*rbacv1.ClusterRole) rbaclisters.ClusterRoleLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, obj := range objs {
		require.NoError(t, indexer.Add(obj))
	}
	return rbaclisters.NewClusterRoleLister(indexer)
}

func testApproverPolicyManagerWithReadyStatus(status metav1.ConditionStatus) *v1alpha1.ApproverPolicyManager {
	apm := &v1alpha1.ApproverPolicyManager{
		ObjectMeta: metav1.ObjectMeta{Name: approverPolicyManagerName},
	}
	apm.Status.SetCondition(v1alpha1.Ready, status, v1alpha1.ReasonReady, "")
	return apm
}

func testApproveClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: approveClusterRoleName}}
}

func TestShouldDisableBuiltinApprover(t *testing.T) {
	tests := []struct {
		name           string
		approverPolicy []*v1alpha1.ApproverPolicyManager
		clusterRole    []*rbacv1.ClusterRole
		want           bool
	}{
		{
			name:           "ApproverPolicyManager NotFound -> re-enable",
			approverPolicy: nil,
			clusterRole:    []*rbacv1.ClusterRole{testApproveClusterRole()},
			want:           false,
		},
		{
			name:           "ClusterRole absent (latch already disabled) -> stay disabled",
			approverPolicy: []*v1alpha1.ApproverPolicyManager{testApproverPolicyManagerWithReadyStatus(metav1.ConditionFalse)},
			clusterRole:    nil,
			want:           true,
		},
		{
			name:           "ClusterRole present and ApproverPolicyManager Ready=True -> trigger disable",
			approverPolicy: []*v1alpha1.ApproverPolicyManager{testApproverPolicyManagerWithReadyStatus(metav1.ConditionTrue)},
			clusterRole:    []*rbacv1.ClusterRole{testApproveClusterRole()},
			want:           true,
		},
		{
			name:           "ClusterRole present and ApproverPolicyManager not yet Ready -> wait",
			approverPolicy: []*v1alpha1.ApproverPolicyManager{testApproverPolicyManagerWithReadyStatus(metav1.ConditionFalse)},
			clusterRole:    []*rbacv1.ClusterRole{testApproveClusterRole()},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			approverPolicyLister := newTestApproverPolicyManagerLister(t, tt.approverPolicy...)
			clusterRoleLister := newTestClusterRoleLister(t, tt.clusterRole...)

			got, err := shouldDisableBuiltinApprover(approverPolicyLister, clusterRoleLister)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsApproverPolicyManagerReady(t *testing.T) {
	tests := []struct {
		name string
		apm  *v1alpha1.ApproverPolicyManager
		want bool
	}{
		{
			name: "no conditions set",
			apm:  &v1alpha1.ApproverPolicyManager{},
			want: false,
		},
		{
			name: "ready true",
			apm:  testApproverPolicyManagerWithReadyStatus(metav1.ConditionTrue),
			want: true,
		},
		{
			name: "ready false",
			apm:  testApproverPolicyManagerWithReadyStatus(metav1.ConditionFalse),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isApproverPolicyManagerReady(tt.apm))
		})
	}
}

func TestWithAutoApproverDisableArgHook(t *testing.T) {
	newControllerDeployment := func(args []string) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: certmanagerControllerDeployment},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: certmanagerControllerDeployment, Args: args}},
					},
				},
			},
		}
	}

	t.Run("injects disable arg when built-in approver should be disabled", func(t *testing.T) {
		approverPolicyLister := newTestApproverPolicyManagerLister(t, testApproverPolicyManagerWithReadyStatus(metav1.ConditionTrue))
		clusterRoleLister := newTestClusterRoleLister(t, testApproveClusterRole())

		hook := withAutoApproverDisableArgHook(&fakeApproverPolicyManagerInformer{lister: approverPolicyLister}, clusterRoleLister)
		deployment := newControllerDeployment([]string{"--v=2"})

		require.NoError(t, hook(nil, deployment))
		require.Contains(t, deployment.Spec.Template.Spec.Containers[0].Args, disableBuiltinApproverArg)
	})

	t.Run("does not inject arg when ApproverPolicyManager not found", func(t *testing.T) {
		approverPolicyLister := newTestApproverPolicyManagerLister(t)
		clusterRoleLister := newTestClusterRoleLister(t, testApproveClusterRole())

		hook := withAutoApproverDisableArgHook(&fakeApproverPolicyManagerInformer{lister: approverPolicyLister}, clusterRoleLister)
		deployment := newControllerDeployment([]string{"--v=2"})

		require.NoError(t, hook(nil, deployment))
		require.NotContains(t, deployment.Spec.Template.Spec.Containers[0].Args, disableBuiltinApproverArg)
	})

	t.Run("is idempotent when disable arg already present", func(t *testing.T) {
		approverPolicyLister := newTestApproverPolicyManagerLister(t, testApproverPolicyManagerWithReadyStatus(metav1.ConditionTrue))
		clusterRoleLister := newTestClusterRoleLister(t) // latch: ClusterRole already deleted

		hook := withAutoApproverDisableArgHook(&fakeApproverPolicyManagerInformer{lister: approverPolicyLister}, clusterRoleLister)
		deployment := newControllerDeployment([]string{"--v=2", disableBuiltinApproverArg})

		require.NoError(t, hook(nil, deployment))
		args := deployment.Spec.Template.Spec.Containers[0].Args
		count := 0
		for _, a := range args {
			if a == disableBuiltinApproverArg {
				count++
			}
		}
		require.Equal(t, 1, count, "expected the disable arg to appear exactly once, got %v", args)
	})
}
