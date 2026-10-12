package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

func init() {
	SchemeBuilder.Register(&ApproverPolicyManager{}, &ApproverPolicyManagerList{})
}

// ApproverPolicyManagerList contains a list of ApproverPolicyManager resources.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type ApproverPolicyManagerList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard list's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata"`
	Items           []ApproverPolicyManager `json:"items"`
}

// ApproverPolicyManager describes the configuration and status of the managed approver-policy deployment.
// The name must be cluster, allowing only one instance per cluster.
// The approver-policy operand is deployed in the cert-manager namespace.
//
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=approverpolicymanagers,scope=Cluster,categories={cert-manager-operator,approver-policy},shortName=approverpolicymanager;apm
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].message"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:metadata:labels={"app.kubernetes.io/name=approverpolicymanager", "app.kubernetes.io/part-of=cert-manager-operator"}
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'cluster'",message="ApproverPolicyManager is a singleton, .metadata.name must be 'cluster'"
// +operator-sdk:csv:customresourcedefinitions:displayName="ApproverPolicyManager"
type ApproverPolicyManager struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +required
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec is the desired configuration of the ApproverPolicyManager.
	// +kubebuilder:validation:Required
	// +required
	Spec ApproverPolicyManagerSpec `json:"spec"`

	// status is the most recently observed status of the ApproverPolicyManager.
	// +kubebuilder:validation:Optional
	// +optional
	Status ApproverPolicyManagerStatus `json:"status,omitempty"`
}

// ApproverPolicyManagerSpec defines the desired state of ApproverPolicyManager.
type ApproverPolicyManagerSpec struct {
	// approverPolicyConfig configures the approver-policy operand's behavior.
	// +kubebuilder:validation:Required
	// +required
	ApproverPolicyConfig ApproverPolicyConfig `json:"approverPolicyConfig"`
}

// ApproverPolicyConfig configures the approver-policy operand's behavior.
type ApproverPolicyConfig struct {
	// logLevel configures the verbosity of approver-policy logging.
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum:=1
	// +kubebuilder:validation:Maximum:=5
	// +kubebuilder:validation:Optional
	// +optional
	LogLevel int32 `json:"logLevel,omitempty"`

	// logFormat specifies the output format for approver-policy logging.
	// Supported formats are text and json.
	// +kubebuilder:validation:Enum:="text";"json"
	// +kubebuilder:default:="text"
	// +kubebuilder:validation:Optional
	// +optional
	LogFormat string `json:"logFormat,omitempty"`
}

// ApproverPolicyManagerStatus defines the observed state of ApproverPolicyManager.
type ApproverPolicyManagerStatus struct {
	ConditionalStatus `json:",inline,omitempty"`

	// approverPolicyImage is the image used by the managed approver-policy deployment.
	// +kubebuilder:validation:Optional
	// +optional
	ApproverPolicyImage string `json:"approverPolicyImage,omitempty"`
}
