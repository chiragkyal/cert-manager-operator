//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/test/library"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// =============================================================================
// CONSTANTS
// =============================================================================

const (
	trustManagerDeploymentName = "trust-manager"
	trustManagerCRName         = "cluster"
	trustManagerLabel          = "trustmanager.openshift.io/managed-by=trust-manager-controller"
)

// =============================================================================
// SCHEMA DEFINITIONS
// =============================================================================

var trustManagerSchema = schema.GroupVersionResource{
	Group:    "operator.openshift.io",
	Version:  "v1alpha1",
	Resource: "trustmanagers",
}

var bundleSchema = schema.GroupVersionResource{
	Group:    "trust.cert-manager.io",
	Version:  "v1alpha1",
	Resource: "bundles",
}

// =============================================================================
// TEMPLATE CONFIG
// =============================================================================

// TrustManagerConfig holds template values for TrustManager YAML templates
type TrustManagerConfig struct {
	TrustNamespace            string
	SecretTargetsPolicy       string
	AuthorizedSecrets         string // comma-separated list
	FilterExpiredCertificates string
	DefaultCAPackagePolicy    string
	LogLevel                  int32
	LogFormat                 string
}

// BundleConfig holds template values for Bundle YAML templates
type BundleConfig struct {
	Name           string
	TargetKey      string
	NamespaceLabel string
	NamespaceValue string
	SourceType     string // "configMap", "secret", "inLine", "useDefaultCAs"
	SourceName     string
	SourceKey      string
	InlineCA       string
}

// =============================================================================
// TRUST MANAGER E2E TESTS
// =============================================================================

var _ = Describe("TrustManager", Ordered, Label("Feature:TrustManager"), func() {
	ctx := context.TODO()
	var clientset *kubernetes.Clientset

	// ==========================================================================
	// HELPER FUNCTIONS
	// ==========================================================================

	// waitForTrustManagerReady polls until TrustManager deployment is available and CR is ready
	waitForTrustManagerReady := func() v1alpha1.TrustManagerStatus {
		By("poll till trust-manager deployment is available")
		err := pollTillDeploymentAvailable(ctx, clientset, operandNamespace, trustManagerDeploymentName)
		Expect(err).Should(BeNil(), "trust-manager deployment should become available")

		By("poll till TrustManager object is ready")
		status, err := pollTillTrustManagerAvailable(ctx, loader, trustManagerCRName)
		Expect(err).Should(BeNil(), "TrustManager should become ready")

		return status
	}

	// verifyManagedResourceExists checks if a managed resource exists
	verifyManagedResourceExists := func(namespace, resourceType, name string) {
		By(fmt.Sprintf("verifying %s %s/%s exists", resourceType, namespace, name))
		Eventually(func() bool {
			switch resourceType {
			case "Deployment":
				_, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
				return err == nil
			case "ServiceAccount":
				_, err := clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
				return err == nil
			case "Service":
				_, err := clientset.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
				return err == nil
			case "ConfigMap":
				_, err := clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
				return err == nil
			case "ClusterRole":
				_, err := clientset.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
				return err == nil
			case "ClusterRoleBinding":
				_, err := clientset.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
				return err == nil
			default:
				return false
			}
		}, lowTimeout, fastPollInterval).Should(BeTrue(), fmt.Sprintf("%s %s/%s should exist", resourceType, namespace, name))
	}

	// verifyDeploymentHasArg checks if deployment has specific argument
	verifyDeploymentHasArg := func(argSubstring string, shouldExist bool) {
		By(fmt.Sprintf("verifying deployment %s arg containing '%s'", map[bool]string{true: "has", false: "does not have"}[shouldExist], argSubstring))
		Eventually(func() bool {
			deployment, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			if err != nil {
				return false
			}
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "trust-manager" {
					for _, arg := range container.Args {
						if containsSubstring(arg, argSubstring) {
							return shouldExist
						}
					}
				}
			}
			return !shouldExist
		}, lowTimeout, fastPollInterval).Should(BeTrue())
	}

	// verifyDeploymentHasVolume checks if deployment has specific volume
	verifyDeploymentHasVolume := func(volumeName string, shouldExist bool) {
		By(fmt.Sprintf("verifying deployment %s volume '%s'", map[bool]string{true: "has", false: "does not have"}[shouldExist], volumeName))
		Eventually(func() bool {
			deployment, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			if err != nil {
				return false
			}
			for _, volume := range deployment.Spec.Template.Spec.Volumes {
				if volume.Name == volumeName {
					return shouldExist
				}
			}
			return !shouldExist
		}, lowTimeout, fastPollInterval).Should(BeTrue())
	}

	// cleanupTrustManagerCR deletes TrustManager CR and waits for cleanup
	cleanupTrustManagerCR := func() {
		By("deleting TrustManager CR")
		trustManagerClient := loader.DynamicClient.Resource(trustManagerSchema)
		err := trustManagerClient.Delete(ctx, trustManagerCRName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			Fail(fmt.Sprintf("failed to delete TrustManager CR: %v", err))
		}

		By("waiting for TrustManager CR to be deleted")
		Eventually(func() bool {
			_, err := trustManagerClient.Get(ctx, trustManagerCRName, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}, highTimeout, slowPollInterval).Should(BeTrue(), "TrustManager CR should be deleted")

		By("waiting for trust-manager deployment to be deleted")
		Eventually(func() bool {
			_, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}, highTimeout, slowPollInterval).Should(BeTrue(), "trust-manager deployment should be deleted")
	}

	// ==========================================================================
	// SETUP / TEARDOWN
	// ==========================================================================

	BeforeAll(func() {
		var err error
		clientset, err = kubernetes.NewForConfig(cfg)
		Expect(err).Should(BeNil())

		By("increase operator log verbosity")
		err = patchSubscriptionWithEnvVars(ctx, loader, map[string]string{
			"OPERATOR_LOG_LEVEL": "5",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	BeforeEach(func() {
		By("waiting for operator status to become available")
		err := VerifyHealthyOperatorConditions(certmanageroperatorclient.OperatorV1alpha1())
		Expect(err).NotTo(HaveOccurred(), "Operator is expected to be available")
	})

	AfterEach(func() {
		By("cleaning up TrustManager CR if it exists")
		cleanupTrustManagerCR()

		By("cleaning up cluster-scoped RBAC resources")
		clientset.RbacV1().ClusterRoles().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{
			LabelSelector: trustManagerLabel,
		})
		clientset.RbacV1().ClusterRoleBindings().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{
			LabelSelector: trustManagerLabel,
		})
	})

	// ==========================================================================
	// TEST: BASIC DEPLOYMENT
	// ==========================================================================

	Context("Basic Deployment", func() {
		It("should deploy trust-manager with default configuration", func() {
			By("creating TrustManager CR with default settings")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace: "cert-manager",
					LogLevel:       1,
					LogFormat:      "text",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_basic_template.yaml"), "")

			status := waitForTrustManagerReady()
			log.Printf("TrustManager status: %+v", status)

			By("verifying all managed resources exist")
			verifyManagedResourceExists(operandNamespace, "Deployment", trustManagerDeploymentName)
			verifyManagedResourceExists(operandNamespace, "ServiceAccount", "trust-manager")
			verifyManagedResourceExists(operandNamespace, "Service", "trust-manager")
			verifyManagedResourceExists(operandNamespace, "Service", "trust-manager-metrics")

			By("verifying status fields are populated")
			Expect(status.TrustManagerImage).ShouldNot(BeEmpty())
			Expect(status.TrustNamespace).Should(Equal("cert-manager"))
		})

		It("should reconcile deployment when manually deleted", func() {
			By("creating TrustManager CR")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace: "cert-manager",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_basic_template.yaml"), "")

			waitForTrustManagerReady()

			By("manually deleting the deployment")
			err := clientset.AppsV1().Deployments(operandNamespace).Delete(ctx, trustManagerDeploymentName, metav1.DeleteOptions{})
			Expect(err).Should(BeNil())

			By("verifying deployment is recreated by controller")
			err = pollTillDeploymentAvailable(ctx, clientset, operandNamespace, trustManagerDeploymentName)
			Expect(err).Should(BeNil(), "deployment should be recreated")
		})

		It("should restore labels when manually modified on ConfigMap", func() {
			By("creating TrustManager CR with DefaultCAPackage enabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:         "cert-manager",
					DefaultCAPackagePolicy: "Enabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_default_ca_template.yaml"), "")

			waitForTrustManagerReady()

			By("waiting for default CA package ConfigMap to be created")
			err := pollTillConfigMapAvailable(ctx, clientset, operandNamespace, "trust-manager-default-ca-package")
			Expect(err).Should(BeNil())

			By("modifying labels on the ConfigMap")
			cm, err := clientset.CoreV1().ConfigMaps(operandNamespace).Get(ctx, "trust-manager-default-ca-package", metav1.GetOptions{})
			Expect(err).Should(BeNil())

			// Remove a required label
			delete(cm.Labels, "trustmanager.openshift.io/managed-by")
			_, err = clientset.CoreV1().ConfigMaps(operandNamespace).Update(ctx, cm, metav1.UpdateOptions{})
			Expect(err).Should(BeNil())

			By("verifying controller restores the label")
			Eventually(func() bool {
				cm, err := clientset.CoreV1().ConfigMaps(operandNamespace).Get(ctx, "trust-manager-default-ca-package", metav1.GetOptions{})
				if err != nil {
					return false
				}
				_, hasLabel := cm.Labels["trustmanager.openshift.io/managed-by"]
				return hasLabel
			}, lowTimeout, fastPollInterval).Should(BeTrue(), "controller should restore the label")
		})
	})

	// ==========================================================================
	// TEST: SECRET TARGETS CONFIGURATION
	// ==========================================================================

	Context("SecretTargets Configuration", func() {
		It("should deploy with secretTargets.policy=Disabled (default)", func() {
			By("creating TrustManager CR with secretTargets disabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:      "cert-manager",
					SecretTargetsPolicy: "Disabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_secret_targets_template.yaml"), "")

			status := waitForTrustManagerReady()

			By("verifying status shows secretTargets is disabled")
			Expect(string(status.SecretTargetsPolicy)).Should(Equal("Disabled"))

			By("verifying deployment does not have --secret-targets-enabled arg")
			verifyDeploymentHasArg("--secret-targets-enabled=true", false)
		})

		It("should deploy with secretTargets.policy=All", func() {
			By("creating TrustManager CR with secretTargets.policy=All")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:      "cert-manager",
					SecretTargetsPolicy: "All",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_secret_targets_template.yaml"), "")

			status := waitForTrustManagerReady()

			By("verifying status shows secretTargets policy")
			Expect(string(status.SecretTargetsPolicy)).Should(Equal("All"))

			By("verifying deployment has --secret-targets-enabled=true arg")
			verifyDeploymentHasArg("--secret-targets-enabled=true", true)
		})

		It("should deploy with secretTargets.policy=Specific and authorizedSecrets", func() {
			By("creating TrustManager CR with specific authorized secrets")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:      "cert-manager",
					SecretTargetsPolicy: "Specific",
					AuthorizedSecrets:   "my-secret-1,my-secret-2",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_secret_targets_specific_template.yaml"), "")

			status := waitForTrustManagerReady()

			By("verifying status shows secretTargets policy")
			Expect(string(status.SecretTargetsPolicy)).Should(Equal("Specific"))

			By("verifying deployment has --secret-targets-enabled=true arg")
			verifyDeploymentHasArg("--secret-targets-enabled=true", true)

			By("verifying ClusterRole has specific secrets permissions")
			Eventually(func() bool {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, "trust-manager", metav1.GetOptions{})
				if err != nil {
					return false
				}
				for _, rule := range cr.Rules {
					if containsString(rule.Resources, "secrets") {
						// Should have specific resourceNames
						return len(rule.ResourceNames) > 0
					}
				}
				return false
			}, lowTimeout, fastPollInterval).Should(BeTrue(), "ClusterRole should have specific secret permissions")
		})
	})

	// ==========================================================================
	// TEST: DEFAULT CA PACKAGE
	// ==========================================================================

	Context("DefaultCAPackage Feature", func() {
		It("should deploy without default CA package when policy=Disabled", func() {
			By("creating TrustManager CR with DefaultCAPackage disabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:         "cert-manager",
					DefaultCAPackagePolicy: "Disabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_default_ca_template.yaml"), "")

			status := waitForTrustManagerReady()

			By("verifying status shows defaultCAPackage is disabled")
			Expect(string(status.DefaultCAPackagePolicy)).Should(Equal("Disabled"))

			By("verifying deployment does not have --default-package-location arg")
			verifyDeploymentHasArg("--default-package-location", false)

			By("verifying packages volume does not exist")
			verifyDeploymentHasVolume("packages", false)
		})

		It("should deploy with default CA package when policy=Enabled", func() {
			By("creating TrustManager CR with DefaultCAPackage enabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:         "cert-manager",
					DefaultCAPackagePolicy: "Enabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_default_ca_template.yaml"), "")

			status := waitForTrustManagerReady()

			By("verifying status shows defaultCAPackage is enabled")
			Expect(string(status.DefaultCAPackagePolicy)).Should(Equal("Enabled"))

			By("verifying injection ConfigMap is created with CNO label")
			Eventually(func() bool {
				cm, err := clientset.CoreV1().ConfigMaps(operandNamespace).Get(ctx, "trust-manager-default-ca-injection", metav1.GetOptions{})
				if err != nil {
					return false
				}
				// Check for CNO injection label
				return cm.Labels["config.openshift.io/inject-trusted-cabundle"] == "true"
			}, lowTimeout, fastPollInterval).Should(BeTrue(), "injection ConfigMap should have CNO label")

			By("verifying deployment has --default-package-location arg")
			verifyDeploymentHasArg("--default-package-location", true)

			By("verifying packages volume exists")
			verifyDeploymentHasVolume("packages", true)
		})

		It("should clean up CA package ConfigMaps when feature is disabled", func() {
			By("creating TrustManager CR with DefaultCAPackage enabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:         "cert-manager",
					DefaultCAPackagePolicy: "Enabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_default_ca_template.yaml"), "")

			waitForTrustManagerReady()

			By("waiting for injection ConfigMap to be created")
			err := pollTillConfigMapAvailable(ctx, clientset, operandNamespace, "trust-manager-default-ca-injection")
			Expect(err).Should(BeNil())

			By("updating TrustManager CR to disable DefaultCAPackage")
			trustManagerClient := loader.DynamicClient.Resource(trustManagerSchema)
			tm, err := trustManagerClient.Get(ctx, trustManagerCRName, metav1.GetOptions{})
			Expect(err).Should(BeNil())

			// Update the spec to disable DefaultCAPackage
			unstructured.SetNestedField(tm.Object, "Disabled", "spec", "trustManagerConfig", "defaultCAPackage", "policy")
			_, err = trustManagerClient.Update(ctx, tm, metav1.UpdateOptions{})
			Expect(err).Should(BeNil())

			By("verifying injection ConfigMap is deleted")
			Eventually(func() bool {
				_, err := clientset.CoreV1().ConfigMaps(operandNamespace).Get(ctx, "trust-manager-default-ca-injection", metav1.GetOptions{})
				return apierrors.IsNotFound(err)
			}, lowTimeout, fastPollInterval).Should(BeTrue(), "injection ConfigMap should be deleted")

			By("verifying packages volume is removed from deployment")
			verifyDeploymentHasVolume("packages", false)
		})
	})

	// ==========================================================================
	// TEST: FILTER EXPIRED CERTIFICATES
	// ==========================================================================

	Context("FilterExpiredCertificates Configuration", func() {
		It("should deploy with filterExpiredCertificates=Disabled (default)", func() {
			By("creating TrustManager CR with filterExpiredCertificates disabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:            "cert-manager",
					FilterExpiredCertificates: "Disabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_filter_expired_template.yaml"), "")

			waitForTrustManagerReady()

			By("verifying deployment does not have --filter-expired-certificates arg")
			verifyDeploymentHasArg("--filter-expired-certificates", false)
		})

		It("should deploy with filterExpiredCertificates=Enabled", func() {
			By("creating TrustManager CR with filterExpiredCertificates enabled")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace:            "cert-manager",
					FilterExpiredCertificates: "Enabled",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_filter_expired_template.yaml"), "")

			waitForTrustManagerReady()

			By("verifying deployment has --filter-expired-certificates=true arg")
			verifyDeploymentHasArg("--filter-expired-certificates=true", true)
		})
	})

	// ==========================================================================
	// TEST: CUSTOM TRUST NAMESPACE
	// ==========================================================================

	Context("Custom TrustNamespace", func() {
		var customNamespace *corev1.Namespace

		BeforeEach(func() {
			By("creating custom trust namespace")
			customNamespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "custom-trust-ns-",
				},
			}
			var err error
			customNamespace, err = clientset.CoreV1().Namespaces().Create(ctx, customNamespace, metav1.CreateOptions{})
			Expect(err).Should(BeNil())
		})

		AfterEach(func() {
			if customNamespace != nil {
				By("deleting custom trust namespace")
				clientset.CoreV1().Namespaces().Delete(ctx, customNamespace.Name, metav1.DeleteOptions{})
			}
		})

		It("should configure trust-manager with custom trust namespace", func() {
			By("creating TrustManager CR with custom trustNamespace")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace: customNamespace.Name,
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_basic_template.yaml"), "")

			status := waitForTrustManagerReady()

			By("verifying status shows custom trust namespace")
			Expect(status.TrustNamespace).Should(Equal(customNamespace.Name))

			By("verifying deployment has --trust-namespace arg with custom namespace")
			Eventually(func() bool {
				deployment, err := clientset.AppsV1().Deployments(operandNamespace).Get(ctx, trustManagerDeploymentName, metav1.GetOptions{})
				if err != nil {
					return false
				}
				for _, container := range deployment.Spec.Template.Spec.Containers {
					if container.Name == "trust-manager" {
						for _, arg := range container.Args {
							if arg == fmt.Sprintf("--trust-namespace=%s", customNamespace.Name) {
								return true
							}
						}
					}
				}
				return false
			}, lowTimeout, fastPollInterval).Should(BeTrue())

			By("verifying Role is created in custom trust namespace")
			Eventually(func() bool {
				_, err := clientset.RbacV1().Roles(customNamespace.Name).Get(ctx, "trust-manager", metav1.GetOptions{})
				return err == nil
			}, lowTimeout, fastPollInterval).Should(BeTrue(), "Role should exist in custom trust namespace")
		})
	})

	// ==========================================================================
	// TEST: STATUS CONDITIONS
	// ==========================================================================

	Context("Status Conditions", func() {
		It("should update status conditions correctly", func() {
			By("creating TrustManager CR")
			loader.CreateFromFile(AssetFunc(testassets.ReadFile).WithTemplateValues(
				TrustManagerConfig{
					TrustNamespace: "cert-manager",
				},
			), filepath.Join("testdata", "trustmanager", "trustmanager_basic_template.yaml"), "")

			By("verifying Ready condition becomes True")
			Eventually(func() bool {
				status, err := getTrustManagerStatus(ctx, loader)
				if err != nil {
					return false
				}
				for _, cond := range status.Conditions {
					if cond.Type == v1alpha1.Ready && cond.Status == metav1.ConditionTrue {
						return true
					}
				}
				return false
			}, highTimeout, slowPollInterval).Should(BeTrue(), "Ready condition should be True")

			By("verifying Degraded condition is False")
			Eventually(func() bool {
				status, err := getTrustManagerStatus(ctx, loader)
				if err != nil {
					return false
				}
				for _, cond := range status.Conditions {
					if cond.Type == v1alpha1.Degraded && cond.Status == metav1.ConditionFalse {
						return true
					}
				}
				return false
			}, lowTimeout, fastPollInterval).Should(BeTrue(), "Degraded condition should be False")
		})
	})

	// ==========================================================================
	// TEST: SINGLETON ENFORCEMENT
	// ==========================================================================

	Context("Singleton Enforcement", func() {
		It("should reject TrustManager CR with name other than 'cluster'", func() {
			By("attempting to create TrustManager CR with invalid name")
			trustManagerClient := loader.DynamicClient.Resource(trustManagerSchema)

			invalidTM := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "operator.openshift.io/v1alpha1",
					"kind":       "TrustManager",
					"metadata": map[string]interface{}{
						"name": "invalid-name",
					},
					"spec": map[string]interface{}{
						"trustManagerConfig": map[string]interface{}{
							"trustNamespace": "cert-manager",
						},
					},
				},
			}

			_, err := trustManagerClient.Create(ctx, invalidTM, metav1.CreateOptions{})
			Expect(err).Should(HaveOccurred(), "should reject TrustManager with name other than 'cluster'")
			Expect(err.Error()).Should(ContainSubstring("cluster"), "error should mention singleton requirement")
		})
	})
})

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// pollTillTrustManagerAvailable polls the TrustManager object and returns its status when ready
func pollTillTrustManagerAvailable(ctx context.Context, loader library.DynamicResourceLoader, name string) (v1alpha1.TrustManagerStatus, error) {
	var status v1alpha1.TrustManagerStatus
	trustManagerClient := loader.DynamicClient.Resource(trustManagerSchema)

	err := wait.PollUntilContextTimeout(ctx, slowPollInterval, highTimeout, true, func(context.Context) (bool, error) {
		tm, err := trustManagerClient.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}

		statusMap, found, err := unstructured.NestedMap(tm.Object, "status")
		if err != nil {
			return false, fmt.Errorf("failed to extract status from TrustManager: %w", err)
		}
		if !found {
			return false, nil
		}

		err = runtime.DefaultUnstructuredConverter.FromUnstructured(statusMap, &status)
		if err != nil {
			return false, fmt.Errorf("failed to convert status to TrustManagerStatus: %w", err)
		}

		// Check if required fields are populated
		if library.IsEmptyString(status.TrustManagerImage) || library.IsEmptyString(status.TrustNamespace) {
			return false, nil
		}

		// Check Ready condition
		for _, cond := range status.Conditions {
			if cond.Type == v1alpha1.Ready {
				return cond.Status == metav1.ConditionTrue, nil
			}
		}

		return false, nil
	})

	return status, err
}

// getTrustManagerStatus fetches the current TrustManager status
func getTrustManagerStatus(ctx context.Context, loader library.DynamicResourceLoader) (v1alpha1.TrustManagerStatus, error) {
	var status v1alpha1.TrustManagerStatus
	trustManagerClient := loader.DynamicClient.Resource(trustManagerSchema)

	tm, err := trustManagerClient.Get(ctx, trustManagerCRName, metav1.GetOptions{})
	if err != nil {
		return status, err
	}

	statusMap, found, err := unstructured.NestedMap(tm.Object, "status")
	if err != nil {
		return status, fmt.Errorf("failed to extract status from TrustManager: %w", err)
	}
	if !found {
		return status, fmt.Errorf("status not found")
	}

	err = runtime.DefaultUnstructuredConverter.FromUnstructured(statusMap, &status)
	return status, err
}

// containsSubstring checks if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// containsString checks if a slice contains a string
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

