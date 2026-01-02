package trustmanager

import (
	"context"
	"fmt"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	"github.com/go-logr/logr/testr"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
	"github.com/openshift/cert-manager-operator/test/library"
)

// =============================================================================
// TEST CONSTANTS
// =============================================================================

const (
	testTrustManagerName = "cluster" // Singleton name
	testImage            = "quay.io/jetstack/trust-manager:v0.20.2"
)

var (
	testError = fmt.Errorf("test client error")
)

// =============================================================================
// TEST FIXTURES
// =============================================================================

// testReconciler creates a Reconciler with fake dependencies for testing.
func testReconciler(t *testing.T) *Reconciler {
	return &Reconciler{
		ctx:           context.Background(),
		eventRecorder: record.NewFakeRecorder(100),
		log:           testr.New(t),
		scheme:        library.Scheme,
	}
}

// testTrustManager creates a TrustManager CR for testing.
func testTrustManager() *v1alpha1.TrustManager {
	return &v1alpha1.TrustManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: testTrustManagerName,
		},
		Spec: v1alpha1.TrustManagerSpec{
			TrustManagerConfig: v1alpha1.TrustManagerConfig{
				LogLevel:       1,
				LogFormat:      "text",
				TrustNamespace: "cert-manager",
				// SecretTargets and FilterExpiredCertificates use default policy (Disabled)
			},
			ControllerConfig: v1alpha1.TrustManagerControllerConfig{
				Labels: map[string]string{
					"user-label1": "test-value1",
					"user-label2": "test-value2",
				},
			},
		},
	}
}

// testTrustManagerWithSecretTargets creates a TrustManager with secretTargets enabled.
func testTrustManagerWithSecretTargets() *v1alpha1.TrustManager {
	tm := testTrustManager()
	tm.Spec.TrustManagerConfig.SecretTargets = v1alpha1.SecretTargetsConfig{
		Policy:            v1alpha1.SecretTargetsPolicySpecific,
		AuthorizedSecrets: []string{"my-secret-1", "my-secret-2"},
	}
	return tm
}

// testTrustManagerWithSecretTargetsAll creates a TrustManager with all secrets access.
func testTrustManagerWithSecretTargetsAll() *v1alpha1.TrustManager {
	tm := testTrustManager()
	tm.Spec.TrustManagerConfig.SecretTargets = v1alpha1.SecretTargetsConfig{
		Policy: v1alpha1.SecretTargetsPolicyAll,
	}
	return tm
}

// =============================================================================
// RESOURCE FIXTURES
// =============================================================================

// testServiceAccount creates a ServiceAccount for testing.
func testServiceAccount() *corev1.ServiceAccount {
	sa := decodeServiceAccountObjBytes(assets.MustAsset(serviceAccountAssetName))
	sa.SetNamespace(operandNamespace)
	sa.SetLabels(controllerDefaultResourceLabels)
	return sa
}

// testClusterRole creates a ClusterRole for testing.
func testClusterRole() *rbacv1.ClusterRole {
	cr := decodeClusterRoleObjBytes(assets.MustAsset(clusterRoleAssetName))
	cr.SetLabels(controllerDefaultResourceLabels)
	return cr
}

// testClusterRoleBinding creates a ClusterRoleBinding for testing.
func testClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	crb := decodeClusterRoleBindingObjBytes(assets.MustAsset(clusterRoleBindingAssetName))
	crb.SetLabels(controllerDefaultResourceLabels)
	// Fix subject namespace
	for i := range crb.Subjects {
		if crb.Subjects[i].Kind == "ServiceAccount" {
			crb.Subjects[i].Namespace = operandNamespace
		}
	}
	return crb
}

// testRole creates a Role for testing.
func testRole() *rbacv1.Role {
	role := decodeRoleObjBytes(assets.MustAsset(roleAssetName))
	role.SetNamespace(operandNamespace)
	role.SetLabels(controllerDefaultResourceLabels)
	return role
}

// testRoleBinding creates a RoleBinding for testing.
func testRoleBinding() *rbacv1.RoleBinding {
	rb := decodeRoleBindingObjBytes(assets.MustAsset(roleBindingAssetName))
	rb.SetNamespace(operandNamespace)
	rb.SetLabels(controllerDefaultResourceLabels)
	// Fix subject namespace
	for i := range rb.Subjects {
		if rb.Subjects[i].Kind == "ServiceAccount" {
			rb.Subjects[i].Namespace = operandNamespace
		}
	}
	return rb
}

// testRoleLeaderElection creates the leader election Role for testing.
func testRoleLeaderElection() *rbacv1.Role {
	role := decodeRoleObjBytes(assets.MustAsset(roleLeaderElectionAssetName))
	role.SetNamespace(operandNamespace)
	role.SetLabels(controllerDefaultResourceLabels)
	return role
}

// testRoleBindingLeaderElection creates the leader election RoleBinding for testing.
func testRoleBindingLeaderElection() *rbacv1.RoleBinding {
	rb := decodeRoleBindingObjBytes(assets.MustAsset(roleBindingLeaderElectionAssetName))
	rb.SetNamespace(operandNamespace)
	rb.SetLabels(controllerDefaultResourceLabels)
	for i := range rb.Subjects {
		if rb.Subjects[i].Kind == "ServiceAccount" {
			rb.Subjects[i].Namespace = operandNamespace
		}
	}
	return rb
}

// testService creates the webhook Service for testing.
func testService() *corev1.Service {
	svc := decodeServiceObjBytes(assets.MustAsset(serviceAssetName))
	svc.SetNamespace(operandNamespace)
	svc.SetLabels(controllerDefaultResourceLabels)
	return svc
}

// testMetricsService creates the metrics Service for testing.
func testMetricsService() *corev1.Service {
	svc := decodeServiceObjBytes(assets.MustAsset(metricsServiceAssetName))
	svc.SetNamespace(operandNamespace)
	svc.SetLabels(controllerDefaultResourceLabels)
	return svc
}

// testIssuer creates an Issuer for testing.
func testIssuer() *certmanagerv1.Issuer {
	issuer := decodeIssuerObjBytes(assets.MustAsset(issuerAssetName))
	issuer.SetNamespace(operandNamespace)
	issuer.SetLabels(controllerDefaultResourceLabels)
	return issuer
}

// testCertificate creates a Certificate for testing.
func testCertificate() *certmanagerv1.Certificate {
	cert := decodeCertificateObjBytes(assets.MustAsset(certificateAssetName))
	cert.SetNamespace(operandNamespace)
	cert.SetLabels(controllerDefaultResourceLabels)
	// Update DNS names for cert-manager namespace
	cert.Spec.CommonName = fmt.Sprintf("%s.%s.svc", trustManagerCommonName, operandNamespace)
	cert.Spec.DNSNames = []string{
		fmt.Sprintf("%s.%s.svc", trustManagerCommonName, operandNamespace),
	}
	return cert
}

// testDeployment creates a Deployment for testing.
func testDeployment() *appsv1.Deployment {
	deploy := decodeDeploymentObjBytes(assets.MustAsset(deploymentAssetName))
	deploy.SetNamespace(operandNamespace)
	deploy.SetLabels(controllerDefaultResourceLabels)
	deploy.Spec.Template.Labels = controllerDefaultResourceLabels
	// Set image
	for i := range deploy.Spec.Template.Spec.Containers {
		if deploy.Spec.Template.Spec.Containers[i].Name == trustManagerContainerName {
			deploy.Spec.Template.Spec.Containers[i].Image = testImage
		}
	}
	return deploy
}

// testValidatingWebhookConfiguration creates a ValidatingWebhookConfiguration for testing.
func testValidatingWebhookConfiguration() *admissionregistrationv1.ValidatingWebhookConfiguration {
	webhook := decodeValidatingWebhookConfigurationObjBytes(assets.MustAsset(validatingWebhookAssetName))
	webhook.SetLabels(controllerDefaultResourceLabels)
	// Update webhook service namespace
	for i := range webhook.Webhooks {
		if webhook.Webhooks[i].ClientConfig.Service != nil {
			webhook.Webhooks[i].ClientConfig.Service.Namespace = operandNamespace
		}
	}
	// Set CA injection annotation
	annotations := webhook.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["cert-manager.io/inject-ca-from"] = fmt.Sprintf("%s/%s", operandNamespace, trustManagerCommonName)
	webhook.SetAnnotations(annotations)
	return webhook
}

// =============================================================================
// LABEL HELPERS
// =============================================================================

// testResourceLabels returns the expected labels for test resources.
func testResourceLabels() map[string]string {
	labels := make(map[string]string)
	for k, v := range controllerDefaultResourceLabels {
		labels[k] = v
	}
	return labels
}

// testResourceLabelsWithUser returns labels including user-specified ones.
func testResourceLabelsWithUser() map[string]string {
	labels := testResourceLabels()
	labels["user-label1"] = "test-value1"
	labels["user-label2"] = "test-value2"
	return labels
}
