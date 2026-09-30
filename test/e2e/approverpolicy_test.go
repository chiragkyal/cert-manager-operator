//go:build e2e
// +build e2e

package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
)

const (
	approverPolicyNamespace          = "cert-manager"
	approverPolicyServiceAccountName = "cert-manager-approver-policy"
	approverPolicyCommonName         = "cert-manager-approver-policy"

	approverPolicyDeploymentName     = "cert-manager-approver-policy"
	approverPolicyServiceName        = "cert-manager-approver-policy"
	approverPolicyMetricsServiceName = "cert-manager-approver-policy-metrics"

	approverPolicyClusterRoleName        = "cert-manager-approver-policy"
	approverPolicyClusterRoleBindingName = "cert-manager-approver-policy"
	approverPolicyRoleName               = "cert-manager-approver-policy"
	approverPolicyRoleBindingName        = "cert-manager-approver-policy"

	approverPolicyWebhookConfigName = "cert-manager-approver-policy"
	approverPolicyTLSSecretName     = "cert-manager-approver-policy-tls"
)

// ApproverPolicyManager is deployed and reconciled when --unsupported-addon-features=ApproverPolicyManager=true.
var _ = Describe("ApproverPolicyManager", Ordered, Label("Platform:Generic", "Feature:ApproverPolicyManager", "TechPreview"), func() {
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

	// -------------------------------------------------------------------------
	// Resource creation and verification
	// -------------------------------------------------------------------------

	Context("resource creation", func() {
		It("should create all resources managed by the controller with correct labels", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("verifying ServiceAccount")
			Eventually(func(g Gomega) {
				sa, err := clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Get(ctx, approverPolicyServiceAccountName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(sa.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying Deployment")
			Eventually(func(g Gomega) {
				dep, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(dep.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying webhook Service")
			Eventually(func(g Gomega) {
				svc, err := clientset.CoreV1().Services(approverPolicyNamespace).Get(ctx, approverPolicyServiceName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(svc.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying metrics Service")
			Eventually(func(g Gomega) {
				svc, err := clientset.CoreV1().Services(approverPolicyNamespace).Get(ctx, approverPolicyMetricsServiceName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(svc.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying webhook TLS Secret")
			Eventually(func(g Gomega) {
				secret, err := clientset.CoreV1().Secrets(approverPolicyNamespace).Get(ctx, approverPolicyTLSSecretName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(secret.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying Role")
			Eventually(func(g Gomega) {
				role, err := clientset.RbacV1().Roles(approverPolicyNamespace).Get(ctx, approverPolicyRoleName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(role.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying RoleBinding")
			Eventually(func(g Gomega) {
				rb, err := clientset.RbacV1().RoleBindings(approverPolicyNamespace).Get(ctx, approverPolicyRoleBindingName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(rb.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying ClusterRole")
			Eventually(func(g Gomega) {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(cr.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying ClusterRoleBinding")
			Eventually(func(g Gomega) {
				crb, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, approverPolicyClusterRoleBindingName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(crb.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying ValidatingWebhookConfiguration")
			Eventually(func(g Gomega) {
				vwc, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, approverPolicyWebhookConfigName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				verifyApproverPolicyManagedLabels(vwc.Labels)
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// Resource deletion and recreation (reconciliation)
	// -------------------------------------------------------------------------

	Context("resource deletion and recreation", func() {
		It("should recreate resources managed by the controller when deleted externally", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("deleting and verifying recreation of ServiceAccount")
			verifyApproverPolicyResourceRecreation(func() error {
				return clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Delete(ctx, approverPolicyServiceAccountName, metav1.DeleteOptions{})
			}, func() error {
				_, err := clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Get(ctx, approverPolicyServiceAccountName, metav1.GetOptions{})
				return err
			})

			By("deleting and verifying recreation of ClusterRole")
			verifyApproverPolicyResourceRecreation(func() error {
				return clientset.RbacV1().ClusterRoles().Delete(ctx, approverPolicyClusterRoleName, metav1.DeleteOptions{})
			}, func() error {
				_, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				return err
			})

			By("deleting and verifying recreation of ClusterRoleBinding")
			verifyApproverPolicyResourceRecreation(func() error {
				return clientset.RbacV1().ClusterRoleBindings().Delete(ctx, approverPolicyClusterRoleBindingName, metav1.DeleteOptions{})
			}, func() error {
				_, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, approverPolicyClusterRoleBindingName, metav1.GetOptions{})
				return err
			})

			By("deleting and verifying recreation of webhook Service")
			verifyApproverPolicyResourceRecreation(func() error {
				return clientset.CoreV1().Services(approverPolicyNamespace).Delete(ctx, approverPolicyServiceName, metav1.DeleteOptions{})
			}, func() error {
				_, err := clientset.CoreV1().Services(approverPolicyNamespace).Get(ctx, approverPolicyServiceName, metav1.GetOptions{})
				return err
			})

			By("deleting and verifying recreation of Deployment")
			verifyApproverPolicyResourceRecreation(func() error {
				return clientset.AppsV1().Deployments(approverPolicyNamespace).Delete(ctx, approverPolicyDeploymentName, metav1.DeleteOptions{})
			}, func() error {
				_, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				return err
			})

			By("deleting and verifying recreation of ValidatingWebhookConfiguration")
			verifyApproverPolicyResourceRecreation(func() error {
				return clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, approverPolicyWebhookConfigName, metav1.DeleteOptions{})
			}, func() error {
				_, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, approverPolicyWebhookConfigName, metav1.GetOptions{})
				return err
			})
		})
	})

	// -------------------------------------------------------------------------
	// Label drift reconciliation
	// -------------------------------------------------------------------------

	Context("label drift reconciliation", func() {
		It("should restore labels when modified externally on managed resources", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("modifying ServiceAccount labels externally")
			sa, err := clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Get(ctx, approverPolicyServiceAccountName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			sa.Labels["app.kubernetes.io/instance"] = "modified-value"
			_, err = clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Update(ctx, sa, metav1.UpdateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			By("verifying controller restores ServiceAccount labels")
			Eventually(func(g Gomega) {
				sa, err := clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Get(ctx, approverPolicyServiceAccountName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(sa.Labels).Should(HaveKeyWithValue("app.kubernetes.io/instance", approverPolicyCommonName))
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("modifying ClusterRole labels externally")
			cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			cr.Labels["app"] = "tampered"
			_, err = clientset.RbacV1().ClusterRoles().Update(ctx, cr, metav1.UpdateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			By("verifying controller restores ClusterRole labels")
			Eventually(func(g Gomega) {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(cr.Labels).Should(HaveKeyWithValue("app", approverPolicyCommonName))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// Deployment configuration
	// -------------------------------------------------------------------------

	Context("deployment configuration", func() {
		It("should have deployment available with correct configuration", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("waiting for approver-policy deployment to become available")
			err := pollTillDeploymentAvailable(ctx, clientset, approverPolicyNamespace, approverPolicyDeploymentName)
			Expect(err).ShouldNot(HaveOccurred())

			By("verifying deployment references correct ServiceAccount")
			dep, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(dep.Spec.Template.Spec.ServiceAccountName).Should(Equal(approverPolicyServiceAccountName))
		})

		It("should update deployment args when log level changes", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())
			err := pollTillDeploymentAvailable(ctx, clientset, approverPolicyNamespace, approverPolicyDeploymentName)
			Expect(err).ShouldNot(HaveOccurred())

			By("updating ApproverPolicyManager CR with new log level")
			Eventually(func() error {
				apm, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
				if err != nil {
					return err
				}
				apm.Spec.ApproverPolicyConfig.LogLevel = 3
				_, err = approverPolicyManagerClient().Update(ctx, apm, metav1.UpdateOptions{})
				return err
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying deployment args are updated with new log level")
			Eventually(func(g Gomega) {
				dep, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(dep.Spec.Template.Spec.Containers).ShouldNot(BeEmpty())
				g.Expect(dep.Spec.Template.Spec.Containers[0].Args).Should(ContainElement("--log-level=3"))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})

		It("should apply custom resource requirements to deployment", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR().WithResources(corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("200m"),
					corev1.ResourceMemory: resource.MustParse("256Mi"),
				},
			}))

			By("verifying deployment has custom resource requirements")
			Eventually(func(g Gomega) {
				dep, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(dep.Spec.Template.Spec.Containers).ShouldNot(BeEmpty())
				container := dep.Spec.Template.Spec.Containers[0]
				g.Expect(container.Resources.Requests.Cpu().String()).Should(Equal("50m"))
				g.Expect(container.Resources.Requests.Memory().String()).Should(Equal("64Mi"))
				g.Expect(container.Resources.Limits.Cpu().String()).Should(Equal("200m"))
				g.Expect(container.Resources.Limits.Memory().String()).Should(Equal("256Mi"))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})

		It("should apply custom tolerations to deployment", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR().WithTolerations([]corev1.Toleration{
				{
					Key:      "test-key",
					Operator: corev1.TolerationOpEqual,
					Value:    "test-value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}))

			By("verifying deployment has custom tolerations")
			Eventually(func(g Gomega) {
				dep, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())

				var found bool
				for _, t := range dep.Spec.Template.Spec.Tolerations {
					if t.Key == "test-key" && t.Value == "test-value" && t.Effect == corev1.TaintEffectNoSchedule {
						found = true
						break
					}
				}
				g.Expect(found).Should(BeTrue(), "custom toleration not found on deployment")
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})

		It("should apply custom nodeSelector to deployment", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR().WithNodeSelector(map[string]string{
				"test-node-label": "test-value",
			}))

			By("verifying deployment has custom nodeSelector")
			Eventually(func(g Gomega) {
				dep, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(dep.Spec.Template.Spec.NodeSelector).Should(HaveKeyWithValue("test-node-label", "test-value"))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// approveSignerNames dynamic RBAC (Story 7)
	// -------------------------------------------------------------------------

	Context("approveSignerNames configuration", func() {
		It("should restrict the signers approve rule to configured resourceNames", func() {
			signerNames := []string{"issuers.cert-manager.io/*", "clusterissuers.cert-manager.io/*"}
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR().WithApproveSignerNames(signerNames))

			By("verifying ClusterRole restricts the signers approve rule to configured resourceNames")
			Eventually(func(g Gomega) {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				rule := findSignersApproveRule(cr.Rules)
				g.Expect(rule).ShouldNot(BeNil(), "expected a signers/approve rule")
				g.Expect(rule.ResourceNames).Should(ConsistOf(signerNames))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})

		It("should remove resourceNames restriction when approveSignerNames is emptied", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR().WithApproveSignerNames([]string{"issuers.cert-manager.io/*"}))

			By("verifying ClusterRole initially restricts resourceNames")
			Eventually(func(g Gomega) {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				rule := findSignersApproveRule(cr.Rules)
				g.Expect(rule).ShouldNot(BeNil())
				g.Expect(rule.ResourceNames).ShouldNot(BeEmpty())
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("emptying approveSignerNames")
			Eventually(func() error {
				apm, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
				if err != nil {
					return err
				}
				apm.Spec.ApproverPolicyConfig.ApproveSignerNames = nil
				_, err = approverPolicyManagerClient().Update(ctx, apm, metav1.UpdateOptions{})
				return err
			}, lowTimeout, fastPollInterval).Should(Succeed())

			By("verifying ClusterRole no longer restricts resourceNames on the signers/approve rule")
			Eventually(func(g Gomega) {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				rule := findSignersApproveRule(cr.Rules)
				g.Expect(rule).ShouldNot(BeNil())
				g.Expect(rule.ResourceNames).Should(BeEmpty())
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// RBAC configuration
	// -------------------------------------------------------------------------

	Context("RBAC configuration", func() {
		It("should configure ClusterRoleBinding with correct subjects and roleRef", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("verifying ClusterRoleBinding references correct ClusterRole and ServiceAccount")
			Eventually(func(g Gomega) {
				crb, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, approverPolicyClusterRoleBindingName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(crb.RoleRef.Name).Should(Equal(approverPolicyClusterRoleName))
				g.Expect(crb.RoleRef.Kind).Should(Equal("ClusterRole"))

				g.Expect(crb.Subjects).ShouldNot(BeEmpty())
				g.Expect(crb.Subjects[0].Kind).Should(Equal("ServiceAccount"))
				g.Expect(crb.Subjects[0].Name).Should(Equal(approverPolicyServiceAccountName))
				g.Expect(crb.Subjects[0].Namespace).Should(Equal(approverPolicyNamespace))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// Webhook configuration
	// -------------------------------------------------------------------------

	Context("webhook configuration", func() {
		It("should configure webhook service reference correctly", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("verifying webhook service references are correct")
			Eventually(func(g Gomega) {
				vwc, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, approverPolicyWebhookConfigName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(vwc.Webhooks).ShouldNot(BeEmpty())

				for _, wh := range vwc.Webhooks {
					g.Expect(wh.ClientConfig.Service).ShouldNot(BeNil())
					g.Expect(wh.ClientConfig.Service.Name).Should(Equal(approverPolicyServiceName))
					g.Expect(wh.ClientConfig.Service.Namespace).Should(Equal(approverPolicyNamespace))
				}
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})

		It("should have CA injection annotation on the webhook TLS Secret", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("verifying webhook TLS Secret has allow-direct-injection annotation")
			Eventually(func(g Gomega) {
				secret, err := clientset.CoreV1().Secrets(approverPolicyNamespace).Get(ctx, approverPolicyTLSSecretName, metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(secret.Annotations).Should(HaveKey("cert-manager.io/allow-direct-injection"))
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// Status reporting
	// -------------------------------------------------------------------------

	Context("status reporting", func() {
		It("should report approver-policy image in status", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("verifying ApproverPolicyManager status has image set")
			Eventually(func(g Gomega) {
				apm, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(apm.Status.ApproverPolicyImage).ShouldNot(BeEmpty())
			}, lowTimeout, fastPollInterval).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// Finalizer-gated cleanup (Story 9)
	// -------------------------------------------------------------------------

	Context("finalizer-gated cleanup", func() {
		It("should add a finalizer and delete all operator-created resources when the CR is deleted", func() {
			createApproverPolicyManager(ctx, newApproverPolicyManagerCR())

			By("verifying finalizer is present on the ApproverPolicyManager CR")
			apm, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(apm.Finalizers).ShouldNot(BeEmpty())

			By("deleting the ApproverPolicyManager CR")
			err = approverPolicyManagerClient().Delete(ctx, "cluster", metav1.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			By("verifying the CR is fully removed once cleanup completes")
			Eventually(func() bool {
				_, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue())

			By("verifying the Deployment was deleted as part of cleanup")
			Eventually(func() bool {
				_, err := clientset.AppsV1().Deployments(approverPolicyNamespace).Get(ctx, approverPolicyDeploymentName, metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue())

			By("verifying the ClusterRole was deleted as part of cleanup")
			Eventually(func() bool {
				_, err := clientset.RbacV1().ClusterRoles().Get(ctx, approverPolicyClusterRoleName, metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue())

			By("verifying the ClusterRoleBinding was deleted as part of cleanup")
			Eventually(func() bool {
				_, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, approverPolicyClusterRoleBindingName, metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue())

			By("verifying the ServiceAccount was deleted as part of cleanup")
			Eventually(func() bool {
				_, err := clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Get(ctx, approverPolicyServiceAccountName, metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue())

			By("verifying the ValidatingWebhookConfiguration was deleted as part of cleanup")
			Eventually(func() bool {
				_, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, approverPolicyWebhookConfigName, metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue())
		})
	})

	// -------------------------------------------------------------------------
	// Singleton validation
	// -------------------------------------------------------------------------

	Context("singleton validation", func() {
		It("should reject ApproverPolicyManager with name other than 'cluster'", func(ctx SpecContext) {
			By("attempting to create ApproverPolicyManager with invalid name")
			_, err := approverPolicyManagerClient().Create(ctx, &v1alpha1.ApproverPolicyManager{
				ObjectMeta: metav1.ObjectMeta{Name: "invalid-name"},
				Spec: v1alpha1.ApproverPolicyManagerSpec{
					ApproverPolicyConfig: v1alpha1.ApproverPolicyConfig{},
				},
			}, metav1.CreateOptions{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("ApproverPolicyManager is a singleton"))
			Expect(err.Error()).Should(ContainSubstring(".metadata.name must be 'cluster'"))
		})
	})
})

// ApproverPolicyManager operator feature gate defaults to disabled. Creating an ApproverPolicyManager
// CR must not deploy the operand when --unsupported-addon-features does not enable it.
var _ = Describe("ApproverPolicyManager with operator feature gate disabled", Ordered, Label("Platform:Generic", "Feature:ApproverPolicyManager", "TechPreview:Inverted"), func() {
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
		approverPolicyManagerFeatureGateDisabledBeforeAll(ctx, &originalUnsupportedAddonFeatures, &originalOperatorLogLevel)()
	})

	AfterAll(approverPolicyManagerAfterAll(ctx, &originalUnsupportedAddonFeatures, &originalOperatorLogLevel))

	BeforeEach(approverPolicyManagerBeforeEach())

	AfterEach(approverPolicyManagerAfterEach(ctx))

	It("should not create ServiceAccount or populate status when operator feature gate is disabled", func() {
		By("creating ApproverPolicyManager CR with default settings")
		_, err := approverPolicyManagerClient().Create(ctx, &v1alpha1.ApproverPolicyManager{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: v1alpha1.ApproverPolicyManagerSpec{
				ApproverPolicyConfig: v1alpha1.ApproverPolicyConfig{},
			},
		}, metav1.CreateOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		By("verifying ApproverPolicyManager CR exists")
		_, err = approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		By("verifying ServiceAccount is not created and status stays unset (controller not running without feature gate)")
		Consistently(func(g Gomega) {
			_, err := clientset.CoreV1().ServiceAccounts(approverPolicyNamespace).Get(ctx, approverPolicyServiceAccountName, metav1.GetOptions{})
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "ServiceAccount %s/%s must not exist when ApproverPolicyManager feature gate is disabled", approverPolicyNamespace, approverPolicyServiceAccountName)

			apm, err := approverPolicyManagerClient().Get(ctx, "cluster", metav1.GetOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			st := apm.Status
			if len(st.Conditions) == 0 {
				st.Conditions = nil
			}
			g.Expect(st).To(Equal(v1alpha1.ApproverPolicyManagerStatus{}), "ApproverPolicyManager status must remain unset when controller is disabled")
		}, lowTimeout, fastPollInterval).Should(Succeed())
	})
})

// findSignersApproveRule returns the rule granting "approve" on cert-manager.io/signers, or nil.
func findSignersApproveRule(rules []rbacv1.PolicyRule) *rbacv1.PolicyRule {
	for i, rule := range rules {
		hasGroup := false
		for _, g := range rule.APIGroups {
			if g == "cert-manager.io" {
				hasGroup = true
				break
			}
		}
		if !hasGroup {
			continue
		}
		hasResource := false
		for _, r := range rule.Resources {
			if r == "signers" {
				hasResource = true
				break
			}
		}
		if !hasResource {
			continue
		}
		for _, v := range rule.Verbs {
			if v == "approve" {
				return &rules[i]
			}
		}
	}
	return nil
}
