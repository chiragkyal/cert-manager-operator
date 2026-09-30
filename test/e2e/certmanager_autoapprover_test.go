//go:build e2e
// +build e2e

package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Stories 10 & 11 of the approver-policy-controller enhancement: cert-manager's built-in
// CertificateRequest auto-approver (the "cert-manager-controller-approve:cert-manager-io"
// ClusterRole/ClusterRoleBinding plus the "-certificaterequests-approver" controller disable
// arg) is automatically torn down once approver-policy reports Ready=True, and automatically
// restored once the ApproverPolicyManager CR is deleted.
const (
	autoApproverClusterRoleName = "cert-manager-controller-approve:cert-manager-io"
)

// findOperatorCondition returns the operatorv1.OperatorCondition with the given type, or nil.
func findOperatorCondition(conditions []operatorv1.OperatorCondition, condType string) *operatorv1.OperatorCondition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

var _ = Describe("CertManager built-in auto-approver disabling", Ordered, Label("Platform:Generic", "Feature:ApproverPolicyManager", "TechPreview"), func() {
	var (
		ctx = context.Background()

		clientset                        *kubernetes.Clientset
		originalUnsupportedAddonFeatures string
		originalOperatorLogLevel         string
	)

	BeforeAll(func() {
		var err error
		clientset, err = kubernetes.NewForConfig(cfg)
		Expect(err).Should(BeNil())
		approverPolicyManagerBeforeAll(ctx, &originalUnsupportedAddonFeatures, &originalOperatorLogLevel)()
	})

	AfterAll(approverPolicyManagerAfterAll(ctx, &originalUnsupportedAddonFeatures, &originalOperatorLogLevel))

	BeforeEach(approverPolicyManagerBeforeEach())

	AfterEach(approverPolicyManagerAfterEach(ctx))

	It("should disable the built-in auto-approver once approver-policy is Ready, and re-enable it once ApproverPolicyManager is deleted", func() {
		By("verifying the built-in approve ClusterRole exists by default")
		Eventually(func(g Gomega) {
			_, err := clientset.RbacV1().ClusterRoles().Get(ctx, autoApproverClusterRoleName, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying the built-in approve ClusterRoleBinding exists by default")
		Eventually(func(g Gomega) {
			_, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, autoApproverClusterRoleName, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying the cert-manager controller deployment does not disable the approver controller by default")
		Eventually(func(g Gomega) {
			dep, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, certmanagerControllerDeployment, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(dep.Spec.Template.Spec.Containers).ShouldNot(BeEmpty())
			g.Expect(dep.Spec.Template.Spec.Containers[0].Args).ShouldNot(ContainElement("--controllers=*,-certificaterequests-approver"))
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("creating the ApproverPolicyManager CR and waiting for it to become Ready")
		createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

		By("verifying the built-in approve ClusterRole is deleted")
		Eventually(func(g Gomega) {
			_, err := clientset.RbacV1().ClusterRoles().Get(ctx, autoApproverClusterRoleName, metav1.GetOptions{})
			g.Expect(err).Should(HaveOccurred())
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying the built-in approve ClusterRoleBinding is deleted")
		Eventually(func(g Gomega) {
			_, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, autoApproverClusterRoleName, metav1.GetOptions{})
			g.Expect(err).Should(HaveOccurred())
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying the cert-manager controller deployment gains the approver-disable arg")
		Eventually(func(g Gomega) {
			dep, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, certmanagerControllerDeployment, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(dep.Spec.Template.Spec.Containers).ShouldNot(BeEmpty())
			g.Expect(dep.Spec.Template.Spec.Containers[0].Args).Should(ContainElement("--controllers=*,-certificaterequests-approver"))
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("waiting for the cert-manager controller deployment rollout to complete")
		err := pollTillDeploymentAvailable(ctx, clientset, operandNamespace, certmanagerControllerDeployment)
		Expect(err).ShouldNot(HaveOccurred())

		By("verifying the CertManager CR reports AutoApproverDisabled=True")
		Eventually(func(g Gomega) {
			cm, err := certmanageroperatorclient.OperatorV1alpha1().CertManagers().Get(ctx, "cluster", metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
			cond := findOperatorCondition(cm.Status.Conditions, v1alpha1.AutoApproverDisabled)
			g.Expect(cond).ShouldNot(BeNil())
			g.Expect(cond.Status).Should(Equal(operatorv1.ConditionTrue))
			g.Expect(cond.Reason).Should(Equal(v1alpha1.ReasonApproverPolicyReady))
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("deleting the ApproverPolicyManager CR")
		deleteApproverPolicyManager(ctx)

		By("verifying the built-in approve ClusterRole is recreated")
		Eventually(func(g Gomega) {
			_, err := clientset.RbacV1().ClusterRoles().Get(ctx, autoApproverClusterRoleName, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying the built-in approve ClusterRoleBinding is recreated")
		Eventually(func(g Gomega) {
			_, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, autoApproverClusterRoleName, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying the cert-manager controller deployment loses the approver-disable arg")
		Eventually(func(g Gomega) {
			dep, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, certmanagerControllerDeployment, metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(dep.Spec.Template.Spec.Containers).ShouldNot(BeEmpty())
			g.Expect(dep.Spec.Template.Spec.Containers[0].Args).ShouldNot(ContainElement("--controllers=*,-certificaterequests-approver"))
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("waiting for the cert-manager controller deployment rollout to complete again")
		err = pollTillDeploymentAvailable(ctx, clientset, operandNamespace, certmanagerControllerDeployment)
		Expect(err).ShouldNot(HaveOccurred())

		By("verifying the CertManager CR reports AutoApproverDisabled=False")
		Eventually(func(g Gomega) {
			cm, err := certmanageroperatorclient.OperatorV1alpha1().CertManagers().Get(ctx, "cluster", metav1.GetOptions{})
			g.Expect(err).ShouldNot(HaveOccurred())
			cond := findOperatorCondition(cm.Status.Conditions, v1alpha1.AutoApproverDisabled)
			g.Expect(cond).ShouldNot(BeNil())
			g.Expect(cond.Status).Should(Equal(operatorv1.ConditionFalse))
			g.Expect(cond.Reason).Should(Equal(v1alpha1.ReasonAutoApprovalEnabled))
		}, lowTimeout, fastPollInterval).Should(Succeed())

		By("verifying operator status returns to healthy after restoring the built-in auto-approver")
		err = VerifyHealthyOperatorConditions(certmanageroperatorclient.OperatorV1alpha1())
		Expect(err).ShouldNot(HaveOccurred())
	})
})
