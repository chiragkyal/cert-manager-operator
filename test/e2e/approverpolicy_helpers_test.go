//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	operatorclientv1alpha1 "github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned/typed/operator/v1alpha1"
)

// ---------------------------------------------------------------------------
// ApproverPolicyManager CR builder
// ---------------------------------------------------------------------------

type approverPolicyManagerCRBuilder struct {
	apm *v1alpha1.ApproverPolicyManager
}

func newApproverPolicyManagerCR() *approverPolicyManagerCRBuilder {
	return &approverPolicyManagerCRBuilder{
		apm: &v1alpha1.ApproverPolicyManager{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: v1alpha1.ApproverPolicyManagerSpec{
				ApproverPolicyConfig: v1alpha1.ApproverPolicyConfig{},
			},
		},
	}
}

func (b *approverPolicyManagerCRBuilder) WithResources(resources corev1.ResourceRequirements) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ApproverPolicyConfig.Resources = resources
	return b
}

func (b *approverPolicyManagerCRBuilder) WithTolerations(tolerations []corev1.Toleration) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ApproverPolicyConfig.Tolerations = tolerations
	return b
}

func (b *approverPolicyManagerCRBuilder) WithNodeSelector(nodeSelector map[string]string) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ApproverPolicyConfig.NodeSelector = nodeSelector
	return b
}

func (b *approverPolicyManagerCRBuilder) WithAffinity(affinity *corev1.Affinity) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ApproverPolicyConfig.Affinity = affinity
	return b
}

func (b *approverPolicyManagerCRBuilder) WithLogLevel(level int32) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ApproverPolicyConfig.LogLevel = level
	return b
}

func (b *approverPolicyManagerCRBuilder) WithApproveSignerNames(names []string) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ApproverPolicyConfig.ApproveSignerNames = names
	return b
}

func (b *approverPolicyManagerCRBuilder) WithLabels(labels map[string]string) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ControllerConfig.Labels = labels
	return b
}

func (b *approverPolicyManagerCRBuilder) WithAnnotations(annotations map[string]string) *approverPolicyManagerCRBuilder {
	b.apm.Spec.ControllerConfig.Annotations = annotations
	return b
}

func (b *approverPolicyManagerCRBuilder) Build() *v1alpha1.ApproverPolicyManager {
	return b.apm
}

// ---------------------------------------------------------------------------
// ApproverPolicyManager CR helpers
// ---------------------------------------------------------------------------

func approverPolicyManagerClient() operatorclientv1alpha1.ApproverPolicyManagerInterface {
	return certmanageroperatorclient.OperatorV1alpha1().ApproverPolicyManagers()
}

func waitForApproverPolicyManagerReady(ctx context.Context) v1alpha1.ApproverPolicyManagerStatus {
	By("waiting for ApproverPolicyManager CR to be ready")
	status, err := pollTillApproverPolicyManagerAvailable(ctx, approverPolicyManagerClient(), "cluster")
	Expect(err).Should(BeNil())
	return status
}

func createApproverPolicyManager(ctx context.Context, b *approverPolicyManagerCRBuilder) {
	By("creating ApproverPolicyManager CR")
	_, err := approverPolicyManagerClient().Create(ctx, b.Build(), metav1.CreateOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	waitForApproverPolicyManagerReady(ctx)
}

func deleteApproverPolicyManager(ctx context.Context) {
	By("deleting ApproverPolicyManager CR")
	_ = approverPolicyManagerClient().Delete(ctx, "cluster", metav1.DeleteOptions{})
	Eventually(func() bool {
		_, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}, lowTimeout, fastPollInterval).Should(BeTrue())
}

// pollTillApproverPolicyManagerAvailable polls the ApproverPolicyManager object and returns
// its status once it is available (Ready=True, not Degraded), otherwise returns a time-out error.
func pollTillApproverPolicyManagerAvailable(ctx context.Context, client operatorclientv1alpha1.ApproverPolicyManagerInterface, name string) (v1alpha1.ApproverPolicyManagerStatus, error) {
	return pollTillApproverPolicyManagerAvailableWithTimeout(ctx, client, name, highTimeout)
}

func pollTillApproverPolicyManagerAvailableWithTimeout(ctx context.Context, client operatorclientv1alpha1.ApproverPolicyManagerInterface, name string, timeout time.Duration) (v1alpha1.ApproverPolicyManagerStatus, error) {
	var status v1alpha1.ApproverPolicyManagerStatus

	err := wait.PollUntilContextTimeout(ctx, slowPollInterval, timeout, true, func(context.Context) (bool, error) {
		apm, err := client.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		status = apm.Status

		readyCondition := meta.FindStatusCondition(status.Conditions, v1alpha1.Ready)
		if readyCondition == nil {
			return false, nil
		}

		degradedCondition := meta.FindStatusCondition(status.Conditions, v1alpha1.Degraded)
		if degradedCondition != nil && degradedCondition.Status == metav1.ConditionTrue {
			return false, nil
		}

		return readyCondition.Status == metav1.ConditionTrue, nil
	})

	return status, err
}

// verifyApproverPolicyManagedLabels verifies that the resource has all the expected
// labels for resources managed by the ApproverPolicyManager controller.
func verifyApproverPolicyManagedLabels(labels map[string]string) {
	Expect(labels).Should(HaveKeyWithValue("app", approverPolicyCommonName))
	Expect(labels).Should(HaveKeyWithValue("app.kubernetes.io/name", approverPolicyCommonName))
	Expect(labels).Should(HaveKeyWithValue("app.kubernetes.io/instance", approverPolicyCommonName))
	Expect(labels).Should(HaveKeyWithValue("app.kubernetes.io/managed-by", "cert-manager-operator"))
	Expect(labels).Should(HaveKeyWithValue("app.kubernetes.io/part-of", "cert-manager-operator"))
	Expect(labels).Should(HaveKey("app.kubernetes.io/version"))
}

// verifyApproverPolicyResourceRecreation deletes a resource and verifies it is recreated
// by the controller within the timeout period.
func verifyApproverPolicyResourceRecreation(deleteFunc func() error, getFunc func() error) {
	err := deleteFunc()
	Expect(err).ShouldNot(HaveOccurred())

	Eventually(func() error {
		return getFunc()
	}, lowTimeout, fastPollInterval).Should(Succeed(), "resource was not recreated by controller")
}

func approverPolicyManagerBeforeAll(ctx context.Context, unsupportedAddonFeatures, operatorLogLevel *string) func() {
	return func() {
		var err error

		By("capturing original UNSUPPORTED_ADDON_FEATURES from subscription before patching")
		*unsupportedAddonFeatures, err = getSubscriptionEnvVar(ctx, loader, "UNSUPPORTED_ADDON_FEATURES")
		Expect(err).NotTo(HaveOccurred())

		By("capturing original OPERATOR_LOG_LEVEL from subscription before patching")
		*operatorLogLevel, err = getSubscriptionEnvVar(ctx, loader, "OPERATOR_LOG_LEVEL")
		Expect(err).NotTo(HaveOccurred())

		By("enabling ApproverPolicyManager feature gate via subscription")
		err = patchSubscriptionWithEnvVars(ctx, loader, map[string]string{
			"UNSUPPORTED_ADDON_FEATURES": "ApproverPolicyManager=true",
			"OPERATOR_LOG_LEVEL":         "4",
		})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for operator deployment to rollout with ApproverPolicyManager env var set")
		err = waitForDeploymentEnvVarAndRollout(ctx, operatorNamespace, operatorDeploymentName, "UNSUPPORTED_ADDON_FEATURES", "ApproverPolicyManager=true", lowTimeout)
		Expect(err).NotTo(HaveOccurred())
	}
}

func approverPolicyManagerFeatureGateDisabledBeforeAll(ctx context.Context, unsupportedAddonFeatures, operatorLogLevel *string) func() {
	return func() {
		var err error

		By("capturing original UNSUPPORTED_ADDON_FEATURES from subscription before patching")
		*unsupportedAddonFeatures, err = getSubscriptionEnvVar(ctx, loader, "UNSUPPORTED_ADDON_FEATURES")
		Expect(err).NotTo(HaveOccurred())

		By("capturing original OPERATOR_LOG_LEVEL from subscription before patching")
		*operatorLogLevel, err = getSubscriptionEnvVar(ctx, loader, "OPERATOR_LOG_LEVEL")
		Expect(err).NotTo(HaveOccurred())

		By("ensuring ApproverPolicyManager operator feature gate is not enabled via subscription")
		err = patchSubscriptionWithEnvVars(ctx, loader, map[string]string{
			"UNSUPPORTED_ADDON_FEATURES": "",
		})
		Expect(err).NotTo(HaveOccurred())

		By("waiting for operator deployment to rollout without UNSUPPORTED_ADDON_FEATURES")
		err = waitForDeploymentEnvVarRemovedAndRollout(ctx, operatorNamespace, operatorDeploymentName, "UNSUPPORTED_ADDON_FEATURES", lowTimeout)
		Expect(err).NotTo(HaveOccurred())
	}
}

func approverPolicyManagerAfterAll(ctx context.Context, unsupportedAddonFeatures, operatorLogLevel *string) func() {
	return func() {
		By("restoring UNSUPPORTED_ADDON_FEATURES on subscription to pre-suite value")
		err := patchSubscriptionWithEnvVars(ctx, loader, map[string]string{
			"UNSUPPORTED_ADDON_FEATURES": *unsupportedAddonFeatures,
			"OPERATOR_LOG_LEVEL":         *operatorLogLevel,
		})
		Expect(err).NotTo(HaveOccurred())
		if *unsupportedAddonFeatures == "" {
			By("waiting for operator deployment to rollout after removing UNSUPPORTED_ADDON_FEATURES")
			err = waitForDeploymentEnvVarRemovedAndRollout(ctx, operatorNamespace, operatorDeploymentName, "UNSUPPORTED_ADDON_FEATURES", lowTimeout)
		} else {
			By("waiting for operator deployment to rollout with restored UNSUPPORTED_ADDON_FEATURES")
			err = waitForDeploymentEnvVarAndRollout(ctx, operatorNamespace, operatorDeploymentName, "UNSUPPORTED_ADDON_FEATURES", *unsupportedAddonFeatures, lowTimeout)
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func approverPolicyManagerBeforeEach() func() {
	return func() {
		By("waiting for operator status to become available")
		err := VerifyHealthyOperatorConditions(certmanageroperatorclient.OperatorV1alpha1())
		Expect(err).NotTo(HaveOccurred(), "Operator is expected to be available")
	}
}

func approverPolicyManagerAfterEach(ctx context.Context) func() {
	return func() {
		By("cleaning up ApproverPolicyManager CR if it exists")
		deleteApproverPolicyManager(ctx)
	}
}
