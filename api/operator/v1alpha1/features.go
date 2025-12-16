package v1alpha1

import (
	"k8s.io/component-base/featuregate"
)

var (
	// FeatureIstioCSR enables the controller for istiocsr.operator.openshift.io resource,
	// which extends cert-manager-operator to deploy and manage the istio-csr agent.
	// OpenShift Service Mesh facilitates the integration and istio-csr is an agent that
	// allows Istio workload and control plane components to be secured using cert-manager.
	//
	// For more details,
	// https://github.com/openshift/enhancements/blob/master/enhancements/cert-manager/istio-csr-controller.md
	FeatureIstioCSR featuregate.Feature = "IstioCSR"

	// FeatureTrustManager enables the controller for trustmanagers.operator.openshift.io resource,
	// which extends cert-manager-operator to deploy and manage the trust-manager operand.
	// trust-manager is a Kubernetes operator that distributes trust bundles (CA certificates)
	// across a cluster, complementing cert-manager's certificate issuance capabilities.
	//
	// When enabled, users can create a TrustManager CR (cluster-scoped singleton named "cluster")
	// to deploy trust-manager in the cert-manager namespace. trust-manager then watches for
	// Bundle CRs to distribute CA certificates to ConfigMaps and optionally Secrets.
	//
	// Key features:
	// - Distribute CA bundles from ConfigMaps, Secrets, or system trust stores
	// - Target ConfigMaps and optionally Secrets across namespaces
	// - Filter expired certificates from bundles
	// - Namespace-scoped distribution via label selectors
	FeatureTrustManager featuregate.Feature = "TrustManager"
)

// OperatorFeatureGates defines the feature gates available in the cert-manager-operator.
// Each feature gate controls whether a specific controller is enabled.
//
// Feature Gate States:
// - Alpha: Experimental, disabled by default, may change or be removed
// - Beta: More stable, may be enabled by default, API may still change
// - GA: Production-ready, enabled by default, API is stable
var OperatorFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	// IstioCSR is GA and enabled by default
	FeatureIstioCSR: {Default: true, PreRelease: featuregate.GA},

	// TrustManager starts as Beta, enabled by default
	// This allows early adopters to use it while we gather feedback
	FeatureTrustManager: {Default: true, PreRelease: featuregate.Beta},
}
