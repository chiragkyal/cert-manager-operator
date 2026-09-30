package approverpolicy

import (
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	// approverPolicyCommonName is the name commonly used for naming resources.
	approverPolicyCommonName = "cert-manager-approver-policy"

	// ControllerName is the name of the controller used in logs and events.
	ControllerName = approverPolicyCommonName + "-controller"

	// finalizer name for approverpolicymanagers.openshift.operator.io resource.
	finalizer = "approverpolicymanager.openshift.operator.io/" + ControllerName

	// defaultRequeueTime is the default reconcile requeue time.
	defaultRequeueTime = time.Second * 30

	// approverPolicyManagerObjectName is the name of the ApproverPolicyManager
	// resource created by the user. The CRD enforces name to be `cluster`.
	approverPolicyManagerObjectName = "cluster"

	// approverPolicyImageNameEnvVarName is the environment variable key name
	// containing the image name of approver-policy as value.
	approverPolicyImageNameEnvVarName = "RELATED_IMAGE_APPROVER_POLICY"

	// approverPolicyImageVersionEnvVarName is the environment variable key name
	// containing the image version of approver-policy as value.
	approverPolicyImageVersionEnvVarName = "APPROVERPOLICY_OPERAND_IMAGE_VERSION"

	// operandNamespace is the namespace where the approver-policy operand is deployed.
	operandNamespace = "cert-manager"

	// fieldOwner is the field manager name used for Server-Side Apply operations.
	// All resource reconcilers should use this to identify ownership of fields.
	fieldOwner = "approver-policy-controller"

	// approverPolicyContainerName is the name of the approver-policy container in the deployment.
	approverPolicyContainerName = approverPolicyCommonName

	// roleBindingSubjectKind is the kind used in RBAC binding subjects.
	roleBindingSubjectKind = "ServiceAccount"

	// webhookTLSSecretName is the Secret used by approver-policy to store its
	// self-managed webhook CA/leaf certificates.
	webhookTLSSecretName = approverPolicyCommonName + "-tls"
)

// Resource names used for creating resources and cross-referencing between them.
// These must be set explicitly on each resource's .metadata.name and on every
// field in other resources that references them.
const (
	approverPolicyServiceAccountName = approverPolicyCommonName
	approverPolicyDeploymentName     = approverPolicyCommonName

	approverPolicyServiceName        = approverPolicyCommonName
	approverPolicyMetricsServiceName = approverPolicyCommonName + "-metrics"

	approverPolicyClusterRoleName        = approverPolicyCommonName
	approverPolicyClusterRoleBindingName = approverPolicyCommonName

	approverPolicyRoleName        = approverPolicyCommonName
	approverPolicyRoleBindingName = approverPolicyCommonName

	approverPolicyWebhookConfigName = approverPolicyCommonName
)

var (
	approverPolicyConfigFieldPath   = field.NewPath("spec", "approverPolicyConfig")
	controllerConfigFieldPath       = field.NewPath("spec", "controllerConfig")
	controllerDefaultResourceLabels = map[string]string{
		"app":                          approverPolicyCommonName,
		"app.kubernetes.io/name":       approverPolicyCommonName,
		"app.kubernetes.io/instance":   approverPolicyCommonName,
		"app.kubernetes.io/version":    os.Getenv(approverPolicyImageVersionEnvVarName),
		"app.kubernetes.io/managed-by": "cert-manager-operator",
		"app.kubernetes.io/part-of":    "cert-manager-operator",
	}
)

// asset names are the files present in the root bindata/ dir. Which are then loaded
// and made available by the pkg/operator/assets package.
const (
	serviceAccountAssetName = "approver-policy/resources/serviceaccount_cert-manager-approver-policy.yml"

	deploymentAssetName = "approver-policy/resources/deployment_cert-manager-approver-policy.yml"

	serviceAssetName        = "approver-policy/resources/service_cert-manager-approver-policy.yml"
	metricsServiceAssetName = "approver-policy/resources/service_cert-manager-approver-policy-metrics.yml"

	clusterRoleAssetName        = "approver-policy/resources/clusterrole_cert-manager-approver-policy.yml"
	clusterRoleBindingAssetName = "approver-policy/resources/clusterrolebinding_cert-manager-approver-policy.yml"

	roleAssetName        = "approver-policy/resources/role_cert-manager-approver-policy.yml"
	roleBindingAssetName = "approver-policy/resources/rolebinding_cert-manager-approver-policy.yml"

	secretAssetName = "approver-policy/resources/secret_cert-manager-approver-policy-tls.yml"

	validatingWebhookConfigAssetName = "approver-policy/resources/validatingwebhookconfiguration_cert-manager-approver-policy.yml"
)
