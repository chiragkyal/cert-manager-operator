package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// =============================================================================
// REGISTRATION
// =============================================================================
// init() registers the TrustManager types with the scheme builder.
// This is essential for:
// 1. The controller-runtime to recognize these types
// 2. The API server to know how to serialize/deserialize them
// 3. Client code generation to work properly
func init() {
	SchemeBuilder.Register(&TrustManager{}, &TrustManagerList{})
}

// =============================================================================
// LIST TYPE
// =============================================================================
// TrustManagerList contains a list of TrustManager resources.
// Every CRD needs a List type for the API to return multiple resources.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type TrustManagerList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard list's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata"`
	Items           []TrustManager `json:"items"`
}

// =============================================================================
// MAIN CRD TYPE
// =============================================================================
// TrustManager is the Schema for the trustmanagers API.
//
// TrustManager is a **cluster-scoped singleton** resource. The operator only
// reconciles the TrustManager resource named "cluster". Any other TrustManager
// resources will be ignored. The trust-manager operand is always deployed in
// the cert-manager namespace.
//
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=trustmanagers,scope=Cluster,categories={cert-manager-operator}
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:metadata:labels={"app.kubernetes.io/name=trustmanager", "app.kubernetes.io/part-of=cert-manager-operator"}
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'cluster'",message="TrustManager is a singleton, .metadata.name must be 'cluster'"
// +operator-sdk:csv:customresourcedefinitions:displayName="TrustManager"
type TrustManager struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec is the specification of the desired behavior of the TrustManager.
	// +kubebuilder:validation:Required
	// +required
	Spec TrustManagerSpec `json:"spec"`

	// status is the most recently observed status of the TrustManager.
	// +kubebuilder:validation:Optional
	// +optional
	Status TrustManagerStatus `json:"status,omitempty"`
}

// =============================================================================
// SPEC - What the user configures
// =============================================================================
// TrustManagerSpec defines the desired state of TrustManager.
// Note: trust-manager operand is always deployed in the cert-manager namespace.
type TrustManagerSpec struct {
	// trustManagerConfig configures the trust-manager operand's behavior.
	// +kubebuilder:validation:Required
	// +required
	TrustManagerConfig TrustManagerConfig `json:"trustManagerConfig"`

	// controllerConfig configures the operator's behavior for resource creation.
	// +kubebuilder:validation:Optional
	// +optional
	ControllerConfig TrustManagerControllerConfig `json:"controllerConfig,omitempty"`
}

// =============================================================================
// TRUST MANAGER CONFIG - Core configuration for trust-manager
// =============================================================================
// TrustManagerConfig configures the trust-manager operand's behavior.
type TrustManagerConfig struct {
	// logLevel configures the verbosity of trust-manager logging.
	// Follows Kubernetes logging guidelines:
	// 1 = Normal, 2 = Verbose, 3 = Very Verbose, 4-5 = Debug
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum:=1
	// +kubebuilder:validation:Maximum:=5
	// +kubebuilder:validation:Optional
	// +optional
	LogLevel int32 `json:"logLevel,omitempty"`

	// logFormat specifies the output format for trust-manager logging.
	// Supported formats are "text" and "json".
	// +kubebuilder:validation:Enum:="text";"json"
	// +kubebuilder:default:="text"
	// +kubebuilder:validation:Optional
	// +optional
	LogFormat string `json:"logFormat,omitempty"`

	// trustNamespace is the namespace where trust-manager looks for trust sources
	// (ConfigMaps and Secrets containing CA certificates).
	// Defaults to "cert-manager" if not specified.
	// This field can have a maximum of 63 characters.
	// +kubebuilder:default:="cert-manager"
	// +kubebuilder:validation:MinLength:=1
	// +kubebuilder:validation:MaxLength:=63
	// +kubebuilder:validation:Optional
	// +optional
	TrustNamespace string `json:"trustNamespace,omitempty"`

	// secretTargets configures whether trust-manager can write trust bundles to Secrets.
	// +kubebuilder:validation:Optional
	// +optional
	SecretTargets SecretTargetsConfig `json:"secretTargets,omitempty"`

	// filterExpiredCertificates controls whether trust-manager filters out
	// expired certificates from trust bundles before distributing them.
	// When set to "Enabled", expired certificates are removed from bundles.
	// When set to "Disabled", expired certificates are included (default behavior).
	// +kubebuilder:default:="Disabled"
	// +kubebuilder:validation:Optional
	// +optional
	FilterExpiredCertificates FilterExpiredCertificatesPolicy `json:"filterExpiredCertificates,omitempty"`

	// defaultCAPackage configures the default CA package for trust-manager.
	// When enabled, the operator will use OpenShift's trusted CA bundle injection mechanism.
	// +kubebuilder:validation:Optional
	// +optional
	DefaultCAPackage DefaultCAPackageConfig `json:"defaultCAPackage,omitempty"`

	// resources defines the compute resource requirements for the trust-manager pod.
	// ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
	// +kubebuilder:validation:Optional
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// affinity defines scheduling constraints for the trust-manager pod.
	// ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// tolerations allows the trust-manager pod to be scheduled on tainted nodes.
	// This field can have a maximum of 50 entries.
	// ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
	// +listType=atomic
	// +kubebuilder:validation:MinItems:=0
	// +kubebuilder:validation:MaxItems:=50
	// +kubebuilder:validation:Optional
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// nodeSelector restricts which nodes the trust-manager pod can be scheduled on.
	// This field can have a maximum of 50 entries.
	// ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
	// +mapType=atomic
	// +kubebuilder:validation:MinProperties:=0
	// +kubebuilder:validation:MaxProperties:=50
	// +kubebuilder:validation:Optional
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// =============================================================================
// SECRET TARGETS CONFIG - Controls secret write permissions
// =============================================================================
// SecretTargetsConfig configures whether and how trust-manager can write
// trust bundles to Secrets.
//
// +kubebuilder:validation:XValidation:rule="self.policy != 'Specific' || (has(self.authorizedSecrets) && size(self.authorizedSecrets) > 0)",message="authorizedSecrets must not be empty when policy is Specific"
// +kubebuilder:validation:XValidation:rule="self.policy == 'Specific' || !has(self.authorizedSecrets) || size(self.authorizedSecrets) == 0",message="authorizedSecrets must be empty when policy is not Specific"
type SecretTargetsConfig struct {
	// policy controls whether and how trust-manager can write trust bundles to Secrets.
	// Allowed values are "Disabled", "All", or "Specific".
	// "Disabled" means trust-manager cannot write trust bundles to Secrets (default behavior).
	// "All" grants trust-manager permission to create and update ALL secrets across all namespaces.
	// "Specific" grants trust-manager permission to create and update only the secrets listed in authorizedSecrets.
	// +kubebuilder:default:="Disabled"
	// +kubebuilder:validation:Optional
	// +optional
	Policy SecretTargetsPolicy `json:"policy,omitempty"`

	// authorizedSecrets is a list of specific secret names that trust-manager
	// is authorized to create and update. This field is only valid when policy is "Specific".
	// This field can have a maximum of 100 entries.
	// Each entry must be a valid secret name (1-253 characters).
	// +listType=set
	// +kubebuilder:validation:MinItems:=0
	// +kubebuilder:validation:MaxItems:=100
	// +kubebuilder:validation:items:MinLength:=1
	// +kubebuilder:validation:items:MaxLength:=253
	// +kubebuilder:validation:Optional
	// +optional
	AuthorizedSecrets []string `json:"authorizedSecrets,omitempty"`
}

// =============================================================================
// DEFAULT CA PACKAGE CONFIG - OpenShift trusted CA integration
// =============================================================================
// DefaultCAPackageConfig configures the default CA package feature for trust-manager.
type DefaultCAPackageConfig struct {
	// policy controls whether the default CA package feature is enabled.
	// When set to "Enabled", the operator will inject OpenShift's trusted CA bundle
	// into trust-manager, enabling the "useDefaultCAs: true" source in Bundle resources.
	// When set to "Disabled", no default CA package is configured and Bundles cannot use useDefaultCAs (default behavior).
	// +kubebuilder:default:="Disabled"
	// +kubebuilder:validation:Optional
	// +optional
	Policy DefaultCAPackagePolicy `json:"policy,omitempty"`
}

// =============================================================================
// CONTROLLER CONFIG - Operator behavior settings
// =============================================================================
// TrustManagerControllerConfig configures the operator's behavior for
// creating trust-manager resources.
type TrustManagerControllerConfig struct {
	// labels to apply to all resources created for the trust-manager deployment.
	// These labels are in addition to the default labels added by the operator.
	// This field can have a maximum of 20 entries.
	// +mapType=granular
	// +kubebuilder:validation:MinProperties:=0
	// +kubebuilder:validation:MaxProperties:=20
	// +kubebuilder:validation:Optional
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations to apply to all resources created for the trust-manager deployment.
	// This field can have a maximum of 20 entries.
	// +mapType=granular
	// +kubebuilder:validation:MinProperties:=0
	// +kubebuilder:validation:MaxProperties:=20
	// +kubebuilder:validation:Optional
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// =============================================================================
// ENUM TYPE DEFINITIONS
// =============================================================================

// FilterExpiredCertificatesPolicy defines the policy for filtering expired certificates.
// +kubebuilder:validation:Enum:=Enabled;Disabled
type FilterExpiredCertificatesPolicy string

const (
	// FilterExpiredCertificatesPolicyEnabled filters out expired certificates from bundles.
	FilterExpiredCertificatesPolicyEnabled FilterExpiredCertificatesPolicy = "Enabled"
	// FilterExpiredCertificatesPolicyDisabled includes expired certificates in bundles.
	FilterExpiredCertificatesPolicyDisabled FilterExpiredCertificatesPolicy = "Disabled"
)

// SecretTargetsPolicy defines the policy for writing trust bundles to Secrets.
// +kubebuilder:validation:Enum:=Disabled;All;Specific
type SecretTargetsPolicy string

const (
	// SecretTargetsPolicyDisabled means trust-manager cannot write trust bundles to Secrets.
	SecretTargetsPolicyDisabled SecretTargetsPolicy = "Disabled"
	// SecretTargetsPolicyAll grants trust-manager permission to write to ALL secrets.
	SecretTargetsPolicyAll SecretTargetsPolicy = "All"
	// SecretTargetsPolicySpecific grants trust-manager permission to write to specific secrets only.
	SecretTargetsPolicySpecific SecretTargetsPolicy = "Specific"
)

// DefaultCAPackagePolicy defines the policy for the default CA package feature.
// +kubebuilder:validation:Enum:=Enabled;Disabled
type DefaultCAPackagePolicy string

const (
	// DefaultCAPackagePolicyEnabled enables the default CA package feature.
	DefaultCAPackagePolicyEnabled DefaultCAPackagePolicy = "Enabled"
	// DefaultCAPackagePolicyDisabled disables the default CA package feature.
	DefaultCAPackagePolicyDisabled DefaultCAPackagePolicy = "Disabled"
)

// =============================================================================
// STATUS - What the operator reports back
// =============================================================================
// TrustManagerStatus defines the observed state of TrustManager.
// The status is updated by the operator during each reconciliation.
type TrustManagerStatus struct {
	// conditions holds information about the current state of the trust-manager deployment.
	// Standard conditions include:
	// - Ready: True when trust-manager is fully operational
	// - Degraded: True when there's an issue affecting functionality
	// - Progressing: True when changes are being applied
	ConditionalStatus `json:",inline,omitempty"`

	// trustManagerImage is the container image (name:tag) used for trust-manager.
	// This is populated from the RELATED_IMAGE_TRUST_MANAGER environment variable.
	TrustManagerImage string `json:"trustManagerImage,omitempty"`

	// trustNamespace is the namespace where trust-manager looks for trust sources.
	// This reflects the actual configured trust namespace from the spec.
	TrustNamespace string `json:"trustNamespace,omitempty"`

	// secretTargetsPolicy indicates the current policy for secret targets.
	SecretTargetsPolicy SecretTargetsPolicy `json:"secretTargetsPolicy,omitempty"`

	// defaultCAPackagePolicy indicates the current policy for the default CA package feature.
	DefaultCAPackagePolicy DefaultCAPackagePolicy `json:"defaultCAPackagePolicy,omitempty"`
}
