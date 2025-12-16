package trustmanager

import (
	"os"
	"time"
)

// =============================================================================
// NAMING CONSTANTS
// =============================================================================
// These constants define the names used throughout the controller for naming
// Kubernetes resources, labels, and other identifiers.
const (
	// trustManagerCommonName is the base name used for naming resources.
	// This matches the upstream trust-manager naming convention.
	trustManagerCommonName = "trust-manager"

	// ControllerName is the name of the controller used in logs, events, and metrics.
	// Following the pattern: <component>-controller
	ControllerName = trustManagerCommonName + "-controller"

	// operandNamespace is the namespace where trust-manager operand will be deployed.
	// This is hardcoded to cert-manager namespace as per design decision.
	operandNamespace = "cert-manager"
)

// =============================================================================
// SINGLETON PATTERN
// =============================================================================
// TrustManager is a cluster-scoped singleton - only one instance is allowed
// and it must be named "cluster".
const (
	// trustManagerObjectName is the required name for the TrustManager CR.
	// The controller only reconciles TrustManager resources with this exact name.
	// This is enforced by:
	// 1. CRD validation (XValidation rule in types)
	// 2. Controller logic (early return if name doesn't match)
	trustManagerObjectName = "cluster"
)

// =============================================================================
// ANNOTATIONS
// =============================================================================
// Annotations are used to track controller processing state and provide
// metadata about the reconciliation.
const (
	// controllerProcessedAnnotation is added to TrustManager CR after successful
	// reconciliation. This helps track which resources have been processed.
	controllerProcessedAnnotation = "operator.openshift.io/trust-manager-processed"
)

// =============================================================================
// FINALIZERS
// =============================================================================
// Finalizers ensure cleanup happens before resource deletion.
// When a resource with a finalizer is deleted, Kubernetes sets DeletionTimestamp
// but doesn't actually delete until all finalizers are removed.
const (
	// finalizer prevents TrustManager deletion until cleanup completes.
	// Format: <domain>/<controller-name>
	// The cleanup process removes all created resources (Deployment, RBAC, etc.)
	finalizer = "trustmanager.openshift.operator.io/" + ControllerName
)

// =============================================================================
// TIMING CONSTANTS
// =============================================================================
const (
	// defaultRequeueTime is how long to wait before reconciling again
	// after a successful reconciliation or recoverable error.
	// 30 seconds is a reasonable default that balances responsiveness
	// with avoiding excessive API calls.
	defaultRequeueTime = time.Second * 30
)

// =============================================================================
// CONTAINER CONFIGURATION
// =============================================================================
const (
	// trustManagerContainerName is the name of the container in the Deployment.
	// This must match what's in the bindata deployment manifest.
	trustManagerContainerName = trustManagerCommonName
)

// =============================================================================
// ENVIRONMENT VARIABLES
// =============================================================================
// Environment variables are used to inject configuration at runtime,
// particularly for image references in disconnected/air-gapped environments.
const (
	// trustManagerImageNameEnvVarName is the env var containing the full image reference.
	// Format: registry/repository:tag (e.g., quay.io/jetstack/trust-manager:v0.20.3)
	// This follows the OLM "related images" pattern for disconnected installs.
	trustManagerImageNameEnvVarName = "RELATED_IMAGE_TRUST_MANAGER"

	// trustManagerImageVersionEnvVarName is the env var containing just the version.
	// Used for labeling resources with the operand version.
	trustManagerImageVersionEnvVarName = "TRUST_MANAGER_OPERAND_IMAGE_VERSION"
)

// =============================================================================
// LABELS
// =============================================================================
// Labels are used for:
// 1. Resource identification and querying
// 2. Triggering reconciliation when labeled resources change
// 3. Filtering resources in watches and caches
const (
	// requestEnqueueLabelKey is the label used to identify resources that should
	// trigger a reconciliation of the TrustManager CR when they change.
	// All resources created by this controller get this label.
	requestEnqueueLabelKey = "trustmanager.openshift.operator.io/managed-by"

	// requestEnqueueLabelValue is the value for the managed-by label.
	// Format: <controller-name>
	requestEnqueueLabelValue = ControllerName
)

// =============================================================================
// DEFAULT LABELS
// =============================================================================
// These labels are applied to ALL resources created by the controller.
// They follow Kubernetes recommended labels conventions.
// See: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
var (
	// controllerDefaultResourceLabels are the standard labels applied to all
	// resources created by the trust-manager controller.
	controllerDefaultResourceLabels = map[string]string{
		// Legacy app label for backwards compatibility
		"app": trustManagerCommonName,

		// Kubernetes recommended labels
		"app.kubernetes.io/name":       trustManagerCommonName,
		"app.kubernetes.io/instance":   trustManagerCommonName,
		"app.kubernetes.io/version":    os.Getenv(trustManagerImageVersionEnvVarName),
		"app.kubernetes.io/component":  "trust-distribution",
		"app.kubernetes.io/managed-by": "cert-manager-operator",
		"app.kubernetes.io/part-of":    "cert-manager",

		// Controller tracking label - used for watch filtering
		requestEnqueueLabelKey: requestEnqueueLabelValue,
	}
)

// =============================================================================
// BINDATA ASSET PATHS
// =============================================================================
// These constants define the paths to the pre-packaged Kubernetes manifests
// embedded in the operator binary. The manifests are generated from the
// upstream trust-manager Helm chart.
//
// Asset loading works like this:
// 1. Helm chart is templated at build time (hack/update-trust-manager-manifests.sh)
// 2. Manifests are embedded into binary using go-bindata
// 3. At runtime, assets are loaded and modified (labels, images, etc.)
// 4. Modified resources are applied to the cluster
const (
	// Deployment and identity
	deploymentAssetName     = "trust-manager/resources/deployment_trust-manager.yml"
	serviceAccountAssetName = "trust-manager/resources/serviceaccount_trust-manager.yml"

	// RBAC - Cluster-scoped
	clusterRoleAssetName        = "trust-manager/resources/clusterrole_trust-manager.yml"
	clusterRoleBindingAssetName = "trust-manager/resources/clusterrolebinding_trust-manager.yml"

	// RBAC - Namespace-scoped
	roleAssetName               = "trust-manager/resources/role_trust-manager.yml"
	roleLeaderElectionAssetName = "trust-manager/resources/role_trust-manager:leaderelection.yml"
	roleBindingAssetName        = "trust-manager/resources/rolebinding_trust-manager.yml"
	roleBindingLeaderElectionAssetName = "trust-manager/resources/rolebinding_trust-manager:leaderelection.yml"

	// Services
	serviceAssetName        = "trust-manager/resources/service_trust-manager.yml"
	metricsServiceAssetName = "trust-manager/resources/service_trust-manager-metrics.yml"

	// Certificate management (for webhook TLS)
	issuerAssetName      = "trust-manager/resources/issuer_trust-manager.yml"
	certificateAssetName = "trust-manager/resources/certificate_trust-manager.yml"

	// Webhook
	validatingWebhookAssetName = "trust-manager/resources/validatingwebhookconfiguration_trust-manager.yml"
)

// =============================================================================
// COMMAND LINE ARGUMENTS
// =============================================================================
// These are the command-line arguments passed to the trust-manager container.
// They are derived from the TrustManagerConfig spec.
const (
	// argLogLevel sets the logging verbosity (1-5)
	argLogLevel = "--log-level"

	// argLogFormat sets the log output format ("text" or "json")
	argLogFormat = "--log-format"

	// argTrustNamespace sets the namespace where trust sources are read from
	argTrustNamespace = "--trust-namespace"

	// argSecretTargetsEnabled enables writing trust bundles to Secrets
	argSecretTargetsEnabled = "--secret-targets-enabled"

	// argFilterExpiredCertificates enables filtering of expired certs from bundles
	argFilterExpiredCertificates = "--filter-expired-certificates"
)

