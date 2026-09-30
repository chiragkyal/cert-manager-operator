package approverpolicy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	"github.com/go-logr/logr/testr"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/testutil"
)

var errTestClient = fmt.Errorf("test client error")

type approverPolicyManagerBuilder struct {
	*v1alpha1.ApproverPolicyManager
}

func testApproverPolicyManager() *approverPolicyManagerBuilder {
	return &approverPolicyManagerBuilder{
		ApproverPolicyManager: &v1alpha1.ApproverPolicyManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: approverPolicyManagerObjectName,
			},
			Spec: v1alpha1.ApproverPolicyManagerSpec{
				ApproverPolicyConfig: v1alpha1.ApproverPolicyConfig{
					LogLevel:  1,
					LogFormat: "text",
				},
			},
		},
	}
}

func (b *approverPolicyManagerBuilder) WithLabels(labels map[string]string) *approverPolicyManagerBuilder {
	b.Spec.ControllerConfig.Labels = labels
	return b
}

func (b *approverPolicyManagerBuilder) WithAnnotations(annotations map[string]string) *approverPolicyManagerBuilder {
	b.Spec.ControllerConfig.Annotations = annotations
	return b
}

func (b *approverPolicyManagerBuilder) WithResources(resources corev1.ResourceRequirements) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.Resources = resources
	return b
}

func (b *approverPolicyManagerBuilder) WithTolerations(tolerations []corev1.Toleration) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.Tolerations = tolerations
	return b
}

func (b *approverPolicyManagerBuilder) WithNodeSelector(nodeSelector map[string]string) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.NodeSelector = nodeSelector
	return b
}

func (b *approverPolicyManagerBuilder) WithAffinity(affinity *corev1.Affinity) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.Affinity = affinity
	return b
}

func (b *approverPolicyManagerBuilder) WithLogLevel(level int32) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.LogLevel = level
	return b
}

func (b *approverPolicyManagerBuilder) WithLogFormat(format string) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.LogFormat = format
	return b
}

func (b *approverPolicyManagerBuilder) WithApproveSignerNames(names []string) *approverPolicyManagerBuilder {
	b.Spec.ApproverPolicyConfig.ApproveSignerNames = names
	return b
}

func (b *approverPolicyManagerBuilder) WithReadyCondition(status metav1.ConditionStatus) *approverPolicyManagerBuilder {
	b.Status.SetCondition(v1alpha1.Ready, status, v1alpha1.ReasonReady, "")
	return b
}

func (b *approverPolicyManagerBuilder) Build() *v1alpha1.ApproverPolicyManager {
	return b.ApproverPolicyManager
}

func testReconciler(t *testing.T) *Reconciler {
	return &Reconciler{
		ctx:           context.Background(),
		eventRecorder: record.NewFakeRecorder(100),
		log:           testr.New(t),
		scheme:        testutil.Scheme,
	}
}

func testResourceLabels() map[string]string {
	return getResourceLabels(testApproverPolicyManager().Build())
}

func testResourceAnnotations() map[string]string {
	return getResourceAnnotations(testApproverPolicyManager().Build())
}

func assertError(t *testing.T, err error, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil {
			t.Errorf("expected error containing %q, got nil", wantErr)
			return
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Errorf("expected error containing %q, got %q", wantErr, err.Error())
		}
	} else if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
