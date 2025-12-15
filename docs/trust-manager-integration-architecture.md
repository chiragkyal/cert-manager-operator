# Trust-Manager Integration Architecture

## Document Information

| Field       | Value                      |
| ----------- | -------------------------- |
| **Version** | 1.3                        |
| **Date**    | December 2024              |
| **Status**  | Draft                      |
| **Authors** | Cert-Manager Operator Team |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Goals and Non-Goals](#2-goals-and-non-goals)
3. [Background](#3-background)
4. [Architecture Overview](#4-architecture-overview)
5. [Component Design](#5-component-design)
6. [API Design](#6-api-design)
7. [Controller Design](#7-controller-design)
8. [Resource Lifecycle](#8-resource-lifecycle)
9. [Data Flow](#9-data-flow)
10. [Integration Points](#10-integration-points)
11. [Security Considerations](#11-security-considerations)
12. [Deployment Topology](#12-deployment-topology)
13. [Implementation Phases](#13-implementation-phases)
14. [Testing Strategy](#14-testing-strategy)
15. [Operational Considerations](#15-operational-considerations)

---

## 1. Executive Summary

This document describes the architecture for integrating [trust-manager](https://github.com/cert-manager/trust-manager) as a managed operand within the cert-manager-operator. Trust-manager is an operator for distributing trust bundles (CA certificates) across a Kubernetes cluster, complementing cert-manager's certificate issuance capabilities.

**Key Design Decision:** The `TrustManager` CRD is a **cluster-scoped singleton** resource. The operator only reconciles a `TrustManager` resource with the name `cluster`. This ensures a single, consistent trust-manager deployment across the entire Kubernetes cluster. The trust-manager operand is always deployed in the `cert-manager` namespace alongside cert-manager itself.

The integration follows the established pattern used for IstioCSR integration, leveraging:
- A dedicated Custom Resource Definition (CRD) `TrustManager` (cluster-scoped, singleton named `cluster`)
- A controller-runtime based reconciliation controller
- Pre-packaged Kubernetes manifests (bindata)
- Feature flag-based enablement

---

## 2. Goals and Non-Goals

### 2.1 Goals

| ID  | Goal                                                                         |
| --- | ---------------------------------------------------------------------------- |
| G1  | Enable lifecycle management of trust-manager through cert-manager-operator   |
| G2  | Provide a declarative API (`TrustManager` CRD) for configuring trust-manager |
| G3  | Support automated deployment, upgrade, and removal of trust-manager          |
| G4  | Maintain consistency with existing IstioCSR integration patterns             |
| G5  | Enable distribution of CA trust bundles via `Bundle` CRD                     |
| G6  | Support both ConfigMap and Secret targets for trust bundles                  |
| G7  | Provide feature flag for optional enablement                                 |

### 2.2 Non-Goals

| ID  | Non-Goal                                                                    |
| --- | --------------------------------------------------------------------------- |
| NG1 | Managing external trust-manager installations not deployed by this operator |
| NG2 | Providing a GUI or web interface for trust-manager configuration            |
| NG3 | Automatic migration from standalone trust-manager installations             |
| NG4 | Multi-cluster trust-manager federation                                      |
| NG5 | Custom trust-manager image builds                                           |

---

## 3. Background

### 3.1 What is Trust-Manager?

Trust-manager is a Kubernetes operator that:
- Aggregates CA certificates from multiple sources into "trust bundles"
- Distributes these bundles across namespaces as ConfigMaps or Secrets
- Provides a `Bundle` CRD for declarative trust bundle management
- Includes default CA packages (e.g., Debian CA certificates)

### 3.2 Why Integrate with Cert-Manager-Operator?

```
┌─────────────────────────────────────────────────────────────────┐
│                    Certificate Lifecycle                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────┐    ┌──────────────────┐                  │
│   │   cert-manager   │    │  trust-manager   │                  │
│   │                  │    │                  │                  │
│   │  Issues certs    │───▶│  Distributes     │                  │
│   │  from CA         │    │  CA trust        │                  │
│   └──────────────────┘    └──────────────────┘                  │
│           │                        │                             │
│           │    Managed by          │                             │
│           ▼                        ▼                             │
│   ┌─────────────────────────────────────────────┐               │
│   │         cert-manager-operator               │               │
│   │                                             │               │
│   │  • Unified lifecycle management             │               │
│   │  • Consistent configuration                 │               │
│   │  • Single operational interface             │               │
│   └─────────────────────────────────────────────┘               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Existing Integration Pattern (IstioCSR Reference)

The IstioCSR integration provides the template for trust-manager:

```
cert-manager-operator/
├── api/operator/v1alpha1/
│   ├── istiocsr_types.go          # CRD types
│   └── features.go                 # Feature gates
├── pkg/controller/istiocsr/
│   ├── controller.go              # Main reconciler
│   ├── constants.go               # Constants and asset names
│   ├── install_istiocsr.go        # Orchestration logic
│   ├── deployments.go             # Deployment management
│   ├── rbacs.go                   # RBAC resources
│   ├── services.go                # Service resources
│   ├── serviceaccounts.go         # ServiceAccount resources
│   ├── certificates.go            # Certificate resources
│   └── networkpolicies.go         # NetworkPolicy resources
├── bindata/istio-csr/             # Pre-packaged manifests
└── config/crd/bases/
    └── operator.openshift.io_istiocsrs.yaml
```

---

## 4. Architecture Overview

### 4.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Cluster                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                     cert-manager-operator Namespace                     │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                  cert-manager-operator Pod                       │   │ │
│  │  │                                                                  │   │ │
│  │  │  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │   │ │
│  │  │  │ CertManager      │  │ IstioCSR         │  │ TrustManager  │  │   │ │
│  │  │  │ Controller       │  │ Controller       │  │ Controller    │  │   │ │
│  │  │  │                  │  │                  │  │ (NEW)         │  │   │ │
│  │  │  └────────┬─────────┘  └────────┬─────────┘  └───────┬───────┘  │   │ │
│  │  │           │                     │                     │          │   │ │
│  │  └───────────┼─────────────────────┼─────────────────────┼──────────┘   │ │
│  │              │                     │                     │              │ │
│  └──────────────┼─────────────────────┼─────────────────────┼──────────────┘ │
│                 │                     │                     │                │
│                 ▼                     ▼                                      │
│  ┌────────────────────────────────────────────────┐ ┌──────────────────────┐ │
│  │ cert-manager Namespace                         │ │ istio-csr            │ │
│  │                                                │ │ Namespace            │ │
│  │ • cert-manager Controller   • trust-manager   │ │                      │ │
│  │ • Webhook                   • ValidatingWebhk │ │ • istio-csr          │ │
│  │ • CAInjector                • Certificate     │ │   Deployment         │ │
│  │                             • RBAC            │ │ • Certificate        │ │
│  │                                                │ │ • RBAC               │ │
│  └────────────────────────────────────────────────┘ └──────────────────────┘ │
│                                                              │               │
│                                                              ▼               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         All Namespaces                                 │  │
│  │                                                                        │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │   │ ConfigMap   │  │ ConfigMap   │  │ Secret      │  │ ConfigMap   │  │  │
│  │   │ trust-bundle│  │ trust-bundle│  │ trust-bundle│  │ trust-bundle│  │  │
│  │   │ (ns: app-1) │  │ (ns: app-2) │  │ (ns: app-3) │  │ (ns: app-n) │  │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Component Interaction Diagram

```
                                    User
                                      │
                                      │ kubectl apply
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Kubernetes API Server                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────┐  │
│  │ TrustManager CR     │    │ Bundle CR           │    │ Target          │  │
│  │ (Cluster-scoped)    │    │ (trust.cert-manager │    │ ConfigMaps/     │  │
│  │ name: "cluster"     │    │  .io/v1alpha1)      │    │ Secrets         │  │
│  └──────────┬──────────┘    └──────────┬──────────┘    └────────▲────────┘  │
│             │                          │                        │           │
└─────────────┼──────────────────────────┼────────────────────────┼───────────┘
              │                          │                        │
              │ Watch                    │ Watch                  │ Create/Update
              ▼                          ▼                        │
┌─────────────────────────────┐  ┌─────────────────────────────┐  │
│ TrustManager Controller     │  │ trust-manager               │  │
│ (cert-manager-operator)     │  │ (Operand)                   │──┘
│                             │  │                             │
│ Reconciles:                 │  │ Reconciles:                 │
│ • Deployment                │  │ • Bundle → ConfigMap        │
│ • ServiceAccount            │  │ • Bundle → Secret           │
│ • ClusterRole(Binding)      │  │                             │
│ • Role(Binding)             │  │                             │
│ • Service                   │  │                             │
│ • Certificate               │  │                             │
│ • ValidatingWebhook         │  │                             │
└─────────────────────────────┘  └─────────────────────────────┘
              │                          ▲
              │ Creates/Manages          │
              └──────────────────────────┘
```

---

## 5. Component Design

### 5.1 Directory Structure

```
cert-manager-operator/
├── api/operator/v1alpha1/
│   ├── trustmanager_types.go           # TrustManager CRD types
│   ├── trustmanager_types_test.go      # Type tests
│   ├── features.go                     # Feature gate (add TrustManager)
│   └── zz_generated.deepcopy.go        # Auto-generated
│
├── pkg/controller/trustmanager/
│   ├── controller.go                   # Main reconciler & SetupWithManager
│   ├── controller_test.go              # Controller tests
│   ├── client.go                       # Client wrapper with retry logic
│   ├── constants.go                    # Constants, asset names, labels
│   ├── errors.go                       # Error types (Irrecoverable, etc.)
│   ├── utils.go                        # Utility functions
│   ├── install_trustmanager.go         # Main reconciliation orchestration
│   ├── install_trustmanager_test.go    # Orchestration tests
│   ├── deployments.go                  # Deployment reconciliation
│   ├── deployments_test.go             # Deployment tests
│   ├── rbacs.go                        # ClusterRole, Role, Bindings
│   ├── rbacs_test.go                   # RBAC tests
│   ├── serviceaccounts.go              # ServiceAccount reconciliation
│   ├── serviceaccounts_test.go         # ServiceAccount tests
│   ├── services.go                     # Service reconciliation
│   ├── services_test.go                # Service tests
│   ├── certificates.go                 # Certificate & Issuer reconciliation
│   ├── certificates_test.go            # Certificate tests
│   ├── webhooks.go                     # ValidatingWebhookConfiguration
│   ├── webhooks_test.go                # Webhook tests
│   ├── networkpolicies.go              # NetworkPolicy (optional)
│   └── fakes/
│       └── fake_ctrl_client.go         # Fake client for testing
│
├── bindata/trust-manager/
│   └── resources/
│       ├── deployment_trust-manager.yml
│       ├── serviceaccount_trust-manager.yml
│       ├── clusterrole_trust-manager.yml
│       ├── clusterrolebinding_trust-manager.yml
│       ├── role_trust-manager.yml
│       ├── role_trust-manager:leaderelection.yml
│       ├── rolebinding_trust-manager.yml
│       ├── rolebinding_trust-manager:leaderelection.yml
│       ├── service_trust-manager.yml
│       ├── service_trust-manager-metrics.yml
│       ├── certificate_trust-manager.yml
│       ├── issuer_trust-manager.yml
│       └── validatingwebhookconfiguration_trust-manager.yml
│
├── config/crd/bases/
│   ├── operator.openshift.io_trustmanagers.yaml          # Generated CRD
│   └── customresourcedefinition_bundles.trust.cert-manager.io.yml
│
├── bundle/manifests/
│   └── operator.openshift.io_trustmanagers.yaml          # Bundle CRD
│
└── hack/
    └── update-trust-manager-manifests.sh                 # Manifest update script
```

### 5.2 Component Descriptions

#### 5.2.1 TrustManager Controller

| Aspect        | Description                                                                      |
| ------------- | -------------------------------------------------------------------------------- |
| **Purpose**   | Reconciles TrustManager CR to deploy and manage trust-manager operand            |
| **Framework** | controller-runtime (sigs.k8s.io/controller-runtime)                              |
| **Watches**   | TrustManager CR, Deployment, ServiceAccount, RBAC, Service, Certificate, Webhook |
| **Manages**   | All Kubernetes resources needed for trust-manager operation                      |

#### 5.2.2 Bindata Assets

Pre-packaged Kubernetes manifests extracted from upstream trust-manager Helm chart:

| Asset                                              | Purpose                             |
| -------------------------------------------------- | ----------------------------------- |
| `deployment_trust-manager.yml`                     | trust-manager Pod specification     |
| `serviceaccount_trust-manager.yml`                 | Pod identity                        |
| `clusterrole_trust-manager.yml`                    | Cluster-wide permissions            |
| `clusterrolebinding_trust-manager.yml`             | Binds ClusterRole to ServiceAccount |
| `role_trust-manager.yml`                           | Namespace-scoped permissions        |
| `role_trust-manager:leaderelection.yml`            | Leader election permissions         |
| `rolebinding_trust-manager.yml`                    | Binds Role to ServiceAccount        |
| `rolebinding_trust-manager:leaderelection.yml`     | Leader election binding             |
| `service_trust-manager.yml`                        | Webhook service                     |
| `service_trust-manager-metrics.yml`                | Metrics service                     |
| `certificate_trust-manager.yml`                    | Webhook TLS certificate             |
| `issuer_trust-manager.yml`                         | Self-signed issuer for webhook cert |
| `validatingwebhookconfiguration_trust-manager.yml` | Bundle validation webhook           |

#### 5.2.3 Bundle CRD (Upstream)

The `Bundle` CRD from trust-manager is included but not directly managed:

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: example-bundle
spec:
  sources:
    - useDefaultCAs: true
    - configMap:
        name: my-ca
        key: ca.crt
  target:
    configMap:
      key: "ca-bundle.crt"
    namespaceSelector:
      matchLabels:
        trust-bundle: enabled
```

---

## 6. API Design

### 6.0 Configuration Options Summary

The following table summarizes the key configuration options exposed by the TrustManager CRD:

> **Note:** TrustManager is a **cluster-scoped singleton**. The resource name must be `cluster`. The trust-manager operand is always deployed in the `cert-manager` namespace.

| Configuration              | Path                                                         | Type      | Default          | Description                                               |
| -------------------------- | ------------------------------------------------------------ | --------- | ---------------- | --------------------------------------------------------- |
| **Log Level**              | `spec.trustManagerConfig.logLevel`                           | int (1-5) | `1`              | Kubernetes logging verbosity level                        |
| **Log Format**             | `spec.trustManagerConfig.logFormat`                          | enum      | `"text"`         | Log output format: `"text"` or `"json"`                   |
| **Trust Namespace**        | `spec.trustManagerConfig.trustNamespace`                     | string    | `"cert-manager"` | Namespace where trust-manager looks for trust sources     |
| **Secret Targets Enabled** | `spec.trustManagerConfig.secretTargets.enabled`              | bool      | `false`          | Enable writing trust bundles to Secrets                   |
| **Authorized Secrets All** | `spec.trustManagerConfig.secretTargets.authorizedSecretsAll` | bool      | `false`          | ⚠️ Grant access to ALL secrets (use with caution!)         |
| **Authorized Secrets**     | `spec.trustManagerConfig.secretTargets.authorizedSecrets`    | []string  | `[]`             | List of specific secret names that can be used as targets |
| **Filter Expired Certs**   | `spec.trustManagerConfig.filterExpiredCertificates`          | bool      | `false`          | Filter expired certificates from trust bundles            |
| **Common Labels**          | `spec.controllerConfig.commonLabels`                         | map       | `{}`             | Labels applied to all created resources                   |
| **Common Annotations**     | `spec.controllerConfig.commonAnnotations`                    | map       | `{}`             | Annotations applied to all created resources              |

#### SecretTargets RBAC Impact

| secretTargets Configuration                   | RBAC Generated                                    |
| --------------------------------------------- | ------------------------------------------------- |
| `enabled: false`                              | No secret access                                  |
| `enabled: true`, `authorizedSecretsAll: true` | Full read/write to ALL secrets                    |
| `enabled: true`, `authorizedSecrets: [list]`  | Read all secrets; write only to specified secrets |
| `enabled: true`, no secrets specified         | Read-only access to secrets in trust namespace    |

### 6.1 TrustManager CRD

```yaml
apiVersion: operator.openshift.io/v1alpha1
kind: TrustManager
metadata:
  name: cluster                    # Singleton - must be "cluster" (cluster-scoped)
spec:
  # trust-manager operand is always deployed in the cert-manager namespace
  
  trustManagerConfig:
    # Logging configuration
    logLevel: 1                    # 1-5, default: 1
    logFormat: "text"              # "text" or "json", default: "text"
    
    # Trust source namespace - where trust-manager looks for trust sources
    trustNamespace: "cert-manager"
    
    # Secret targets configuration
    # Enables writing trust bundles to Kubernetes Secrets as targets
    secretTargets:
      enabled: true
      # If true, grants read/write permission to ALL secrets across the cluster
      # Use with caution! If set, ignores the authorizedSecrets list.
      authorizedSecretsAll: false
      # List of secret names which trust-manager is permitted to read/write
      # across all namespaces. These are the only allowable Secrets for targets.
      authorizedSecrets:
        - "my-trust-bundle"
        - "another-bundle"
    
    # Filter expired certificates from the trust bundle
    filterExpiredCertificates: false
    
    # Pod scheduling
    resources:
      requests:
        cpu: "50m"
        memory: "64Mi"
      limits:
        cpu: "100m"
        memory: "128Mi"
    
    nodeSelector:
      kubernetes.io/os: linux
    
    tolerations: []
    
    affinity: {}
  
  controllerConfig:
    # Labels applied to all resources created by the operator
    commonLabels:
      environment: production
      team: platform
    
    # Annotations applied to all resources created by the operator
    commonAnnotations:
      owner: cert-manager-team

status:
  conditions:
    - type: Ready
      status: "True"
      reason: ReconciliationSuccessful
      message: "trust-manager deployed successfully in cert-manager namespace"
    - type: Degraded
      status: "False"
      reason: Ready
      message: ""
  
  trustManagerImage: "quay.io/jetstack/trust-manager:v0.20.3"
  serviceAccount: "trust-manager"
  clusterRole: "trust-manager"
  clusterRoleBinding: "trust-manager"
  secretTargetsEnabled: true
```

### 6.2 Type Definitions

```go
// TrustManager is the Schema for the trustmanagers API.
// TrustManager is a cluster-scoped singleton resource. The operator only reconciles
// the TrustManager resource named "cluster". Any other TrustManager resources will be ignored.
//
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=trustmanagers,scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SecretTargets",type="string",JSONPath=".spec.trustManagerConfig.secretTargets.enabled"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'cluster'",message="TrustManager is a singleton, .metadata.name must be 'cluster'"
// +operator-sdk:csv:customresourcedefinitions:displayName="TrustManager"
type TrustManager struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   TrustManagerSpec   `json:"spec"`
    Status TrustManagerStatus `json:"status,omitempty"`
}

// TrustManagerSpec defines the desired state
// Note: trust-manager operand is always deployed in the cert-manager namespace
type TrustManagerSpec struct {
    // TrustManagerConfig configures trust-manager behavior
    // +kubebuilder:validation:Required
    // +required
    TrustManagerConfig TrustManagerConfig `json:"trustManagerConfig"`

    // ControllerConfig configures operator behavior for resource creation
    // +kubebuilder:validation:Optional
    // +optional
    ControllerConfig *TrustManagerControllerConfig `json:"controllerConfig,omitempty"`
}

// TrustManagerConfig configures the trust-manager operand
type TrustManagerConfig struct {
    // logLevel supports a value range as per Kubernetes logging guidelines (1-5).
    // Higher values are more verbose.
    // +kubebuilder:default:=1
    // +kubebuilder:validation:Minimum:=1
    // +kubebuilder:validation:Maximum:=5
    // +kubebuilder:validation:Optional
    // +optional
    LogLevel int32 `json:"logLevel,omitempty"`

    // logFormat specifies the output format for trust-manager logging.
    // Supported log formats are "text" and "json".
    // +kubebuilder:default:="text"
    // +kubebuilder:validation:Enum:="text";"json"
    // +kubebuilder:validation:Optional
    // +optional
    LogFormat string `json:"logFormat,omitempty"`

    // trustNamespace is the namespace used as the trust source.
    // trust-manager will look for trust sources (ConfigMaps, Secrets) in this namespace.
    // Note: The namespace MUST exist before installing trust-manager.
    // +kubebuilder:default:="cert-manager"
    // +kubebuilder:validation:MinLength:=1
    // +kubebuilder:validation:MaxLength:=63
    // +kubebuilder:validation:Optional
    // +optional
    TrustNamespace string `json:"trustNamespace,omitempty"`

    // secretTargets configures writing trust bundles to Kubernetes Secrets.
    // When enabled, the operator will create appropriate RBAC rules based on the configuration.
    // +kubebuilder:validation:Optional
    // +optional
    SecretTargets *SecretTargetsConfig `json:"secretTargets,omitempty"`

    // filterExpiredCertificates controls whether expired certificates are filtered
    // from the trust bundle. When enabled, only valid (non-expired) certificates
    // will be included in the distributed trust bundles.
    // +kubebuilder:default:=false
    // +kubebuilder:validation:Optional
    // +optional
    FilterExpiredCertificates bool `json:"filterExpiredCertificates,omitempty"`

    // resources defines the compute resource requirements for the trust-manager container.
    // ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
    // +kubebuilder:validation:Optional
    // +optional
    Resources corev1.ResourceRequirements `json:"resources,omitempty"`

    // affinity defines scheduling affinity rules for the trust-manager pod.
    // ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/
    // +kubebuilder:validation:Optional
    // +optional
    Affinity *corev1.Affinity `json:"affinity,omitempty"`

    // tolerations defines pod tolerations for the trust-manager pod.
    // ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
    // +listType=atomic
    // +kubebuilder:validation:MaxItems:=50
    // +kubebuilder:validation:Optional
    // +optional
    Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

    // nodeSelector defines scheduling constraints using node labels.
    // ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
    // +mapType=atomic
    // +kubebuilder:validation:MaxProperties:=50
    // +kubebuilder:validation:Optional
    // +optional
    NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// SecretTargetsConfig configures trust-manager's ability to write trust bundles to Secrets.
// When secretTargets is enabled, the operator dynamically generates RBAC rules based on
// the authorizedSecretsAll and authorizedSecrets configuration.
//
// RBAC Generation Logic:
// - If authorizedSecretsAll=true: ClusterRole grants full read/write access to all secrets
// - If authorizedSecrets list is provided: ClusterRole grants read access to all secrets,
//   but write/patch/delete only for the specified secret resourceNames
// - If neither is set (enabled=true but no secrets configured): Only read access for
//   secrets in the trust namespace (for use as sources)
//
// +kubebuilder:validation:XValidation:rule="!self.authorizedSecretsAll || size(self.authorizedSecrets) == 0",message="authorizedSecrets must be empty when authorizedSecretsAll is true"
type SecretTargetsConfig struct {
    // enabled controls whether trust-manager can write trust bundles to Kubernetes Secrets.
    // When enabled, trust-manager can only write to secrets explicitly allowed via
    // authorizedSecrets or authorizedSecretsAll.
    // Note: Enabling secret targets grants trust-manager read access to all secrets in the cluster.
    // +kubebuilder:default:=false
    // +kubebuilder:validation:Required
    // +required
    Enabled bool `json:"enabled"`

    // authorizedSecretsAll grants read/write permission to ALL secrets across the cluster.
    // WARNING: Use with caution! This provides broad access to cluster secrets.
    // If set to true, the authorizedSecrets list is ignored.
    // +kubebuilder:default:=false
    // +kubebuilder:validation:Optional
    // +optional
    AuthorizedSecretsAll bool `json:"authorizedSecretsAll,omitempty"`

    // authorizedSecrets is a list of secret names which trust-manager is permitted
    // to read and write across all namespaces. These are the ONLY allowable Secrets
    // that can be used as targets.
    // If the list is empty (and authorizedSecretsAll is false), trust-manager cannot
    // write to secrets and can only read secrets in the trust namespace for use as sources.
    // +listType=set
    // +kubebuilder:validation:MaxItems:=100
    // +kubebuilder:validation:items:MinLength:=1
    // +kubebuilder:validation:items:MaxLength:=253
    // +kubebuilder:validation:Optional
    // +optional
    AuthorizedSecrets []string `json:"authorizedSecrets,omitempty"`
}

// TrustManagerControllerConfig configures the operator controller behavior
type TrustManagerControllerConfig struct {
    // commonLabels are labels applied to ALL resources created by the operator
    // for the trust-manager deployment (Deployment, ServiceAccount, RBAC, Services, etc.)
    // +mapType=granular
    // +kubebuilder:validation:MaxProperties:=20
    // +kubebuilder:validation:Optional
    // +optional
    CommonLabels map[string]string `json:"commonLabels,omitempty"`

    // commonAnnotations are annotations applied to ALL resources created by the operator.
    // Note: These annotations are NOT added to CRDs.
    // +mapType=granular
    // +kubebuilder:validation:MaxProperties:=20
    // +kubebuilder:validation:Optional
    // +optional
    CommonAnnotations map[string]string `json:"commonAnnotations,omitempty"`
}

// TrustManagerStatus defines the observed state
type TrustManagerStatus struct {
    // conditions holds information about the current state of the trust-manager deployment.
    ConditionalStatus `json:",inline,omitempty"`

    // trustManagerImage is the name of the image and tag used for deploying trust-manager.
    TrustManagerImage string `json:"trustManagerImage,omitempty"`

    // serviceAccount is the name of the ServiceAccount created by the controller.
    ServiceAccount string `json:"serviceAccount,omitempty"`

    // clusterRole is the name of the ClusterRole created by the controller.
    ClusterRole string `json:"clusterRole,omitempty"`

    // clusterRoleBinding is the name of the ClusterRoleBinding created by the controller.
    ClusterRoleBinding string `json:"clusterRoleBinding,omitempty"`

    // secretTargetsEnabled indicates whether secret targets feature is currently enabled.
    SecretTargetsEnabled bool `json:"secretTargetsEnabled,omitempty"`
}
```

### 6.3 Validation Rules

| Field                                                     | Validation                      | Description                                                       |
| --------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------- |
| `metadata.name`                                           | Must be "cluster"               | Enforces cluster-scoped singleton pattern                         |
| `spec.trustManagerConfig.logLevel`                        | Integer 1-5                     | Kubernetes logging verbosity level                                |
| `spec.trustManagerConfig.logFormat`                       | Enum: "text", "json"            | Log output format                                                 |
| `spec.trustManagerConfig.trustNamespace`                  | 1-63 chars, valid namespace     | Source namespace for trust bundles                                |
| `spec.trustManagerConfig.secretTargets.authorizedSecrets` | Max 100 items, each 1-253 chars | List of allowed secret names                                      |
| `spec.trustManagerConfig.secretTargets`                   | XValidation rule                | authorizedSecrets must be empty when authorizedSecretsAll is true |
| `spec.trustManagerConfig.tolerations`                     | Max 50 items                    | Pod tolerations list                                              |
| `spec.trustManagerConfig.nodeSelector`                    | Max 50 properties               | Node selector map                                                 |
| `spec.controllerConfig.commonLabels`                      | Max 20 properties               | Labels for all resources                                          |
| `spec.controllerConfig.commonAnnotations`                 | Max 20 properties               | Annotations for all resources                                     |

### 6.4 SecretTargets RBAC Generation

The operator dynamically generates RBAC rules based on `secretTargets` configuration:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SecretTargets RBAC Generation Logic                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Scenario 1: secretTargets.enabled = false (default)                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ClusterRole Rules:                                                     │ │
│  │  - ConfigMaps: get, list, create, patch, watch, delete                 │ │
│  │  - Events: create, patch                                               │ │
│  │  - NO Secret access (except in trust namespace for sources)            │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Scenario 2: secretTargets.enabled = true, authorizedSecretsAll = true     │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ClusterRole Rules:                                                     │ │
│  │  - ConfigMaps: get, list, create, patch, watch, delete                 │ │
│  │  - Events: create, patch                                               │ │
│  │  - Secrets: get, list, create, patch, watch, delete (ALL secrets)     │ │
│  │                                                                         │ │
│  │  ⚠️  WARNING: This grants access to ALL secrets cluster-wide!          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Scenario 3: secretTargets.enabled = true, authorizedSecrets = [list]      │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ClusterRole Rules:                                                     │ │
│  │  - ConfigMaps: get, list, create, patch, watch, delete                 │ │
│  │  - Events: create, patch                                               │ │
│  │  - Secrets (read): get, list, watch (ALL secrets for reading sources) │ │
│  │  - Secrets (write): create, patch, delete                              │ │
│  │    resourceNames:                                                       │ │
│  │      - "my-trust-bundle"        # Only these specific secrets         │ │
│  │      - "another-bundle"         # can be written to                   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Scenario 4: secretTargets.enabled = true, but empty authorizedSecrets     │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ClusterRole Rules:                                                     │ │
│  │  - ConfigMaps: get, list, create, patch, watch, delete                 │ │
│  │  - Events: create, patch                                               │ │
│  │  - Secrets: get, list, watch (read-only, for sources in trust ns)     │ │
│  │  - NO write access to secrets as targets                               │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.5 RBAC Template Generation

The controller generates ClusterRole rules dynamically:

```go
// generateSecretRBACRules generates RBAC rules based on secretTargets configuration
func generateSecretRBACRules(config *SecretTargetsConfig) []rbacv1.PolicyRule {
    rules := []rbacv1.PolicyRule{}
    
    if config == nil || !config.Enabled {
        // No secret access when disabled
        return rules
    }
    
    if config.AuthorizedSecretsAll {
        // Full access to all secrets
        rules = append(rules, rbacv1.PolicyRule{
            APIGroups: []string{""},
            Resources: []string{"secrets"},
            Verbs:     []string{"get", "list", "create", "patch", "watch", "delete"},
        })
    } else if len(config.AuthorizedSecrets) > 0 {
        // Read access to all secrets (for sources)
        rules = append(rules, rbacv1.PolicyRule{
            APIGroups: []string{""},
            Resources: []string{"secrets"},
            Verbs:     []string{"get", "list", "watch"},
        })
        // Write access only to specified secrets
        rules = append(rules, rbacv1.PolicyRule{
            APIGroups:     []string{""},
            Resources:     []string{"secrets"},
            Verbs:         []string{"create", "patch", "delete"},
            ResourceNames: config.AuthorizedSecrets,
        })
    } else {
        // Read-only access (for sources in trust namespace)
        rules = append(rules, rbacv1.PolicyRule{
            APIGroups: []string{""},
            Resources: []string{"secrets"},
            Verbs:     []string{"get", "list", "watch"},
        })
    }
    
    return rules
}
```

---

## 7. Controller Design

### 7.1 Reconciliation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Reconciliation Flow                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐                                                            │
│  │ Event Queue │ ◀── TrustManager CR changes (cluster-scoped, name="cluster")│
│  │             │ ◀── Owned resource changes (Deployment, Service, etc.)     │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│         ▼                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Reconcile()                                   │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │  1. Validate Request Name                                           │   │
│  │     │                                                                │   │
│  │     ├── Name != "cluster" ──▶ Log warning, Return (skip)            │   │
│  │     │                                                                │   │
│  │     └── Name == "cluster" ──▶ Continue                              │   │
│  │                                                                      │   │
│  │  2. Fetch TrustManager CR                                           │   │
│  │     │                                                                │   │
│  │     ├── Not Found ──▶ Return (deleted, no action)                   │   │
│  │     │                                                                │   │
│  │     └── Found ──▶ Continue                                          │   │
│  │                                                                      │   │
│  │  3. Check DeletionTimestamp                                         │   │
│  │     │                                                                │   │
│  │     ├── Set ──▶ Run cleanUp() ──▶ Remove Finalizer ──▶ Return      │   │
│  │     │                                                                │   │
│  │     └── Not Set ──▶ Continue                                        │   │
│  │                                                                      │   │
│  │  4. Add Finalizer (if missing)                                      │   │
│  │                                                                      │   │
│  │  5. processReconcileRequest()                                       │   │
│  │     │                                                                │   │
│  │     └──▶ reconcileTrustManagerDeployment()                          │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.1.1 Singleton Validation

The controller enforces the singleton pattern by only processing the TrustManager CR named `cluster`:

```go
// Constants
const (
    trustManagerObjectName = "cluster"
    // trust-manager operand is always deployed in cert-manager namespace
    operandNamespace = "cert-manager"
)

func (r *TrustManagerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    // Only reconcile the singleton named "cluster"
    if req.Name != trustManagerObjectName {
        r.log.Info("ignoring TrustManager with invalid name, only 'cluster' is supported",
            "name", req.Name)
        return ctrl.Result{}, nil
    }

    // Fetch the TrustManager CR (cluster-scoped, no namespace)
    trustManager := &v1alpha1.TrustManager{}
    if err := r.client.Get(ctx, types.NamespacedName{Name: req.Name}, trustManager); err != nil {
        if apierrors.IsNotFound(err) {
            return ctrl.Result{}, nil
        }
        return ctrl.Result{}, err
    }

    // Continue with reconciliation...
    // All namespaced resources are created in cert-manager namespace
    
    // ... rest of reconciliation logic
}
```

### 7.2 Sub-Reconciliation Order

```
reconcileTrustManagerDeployment()
│
├── 1. createOrApplyServiceAccounts()
│   └── Creates: ServiceAccount (trust-manager)
│       └── Applies: commonLabels, commonAnnotations
│
├── 2. createOrApplyRBACResource()
│   │
│   ├── 2a. Generate ClusterRole (DYNAMIC based on secretTargets)
│   │   ┌────────────────────────────────────────────────────────────┐
│   │   │ Base Rules (always included):                              │
│   │   │ - trust.cert-manager.io/bundles: get, list, watch         │
│   │   │ - trust.cert-manager.io/bundles/finalizers: update        │
│   │   │ - trust.cert-manager.io/bundles/status: patch             │
│   │   │ - namespaces: get, list, watch                            │
│   │   │ - configmaps: get, list, create, patch, watch, delete     │
│   │   │ - events: create, patch                                    │
│   │   │                                                            │
│   │   │ Conditional Rules (based on secretTargets config):        │
│   │   │ ┌────────────────────────────────────────────────────────┐│
│   │   │ │ IF secretTargets.enabled = false:                      ││
│   │   │ │   → No secret rules added                              ││
│   │   │ │                                                         ││
│   │   │ │ IF secretTargets.authorizedSecretsAll = true:          ││
│   │   │ │   → secrets: [get,list,create,patch,watch,delete]      ││
│   │   │ │                                                         ││
│   │   │ │ IF secretTargets.authorizedSecrets = ["a","b"]:        ││
│   │   │ │   → secrets: [get,list,watch] (read all)               ││
│   │   │ │   → secrets: [create,patch,delete]                     ││
│   │   │ │     resourceNames: ["a","b"] (write restricted)        ││
│   │   │ │                                                         ││
│   │   │ │ IF secretTargets.enabled but no secrets configured:    ││
│   │   │ │   → secrets: [get,list,watch] (read-only)              ││
│   │   │ └────────────────────────────────────────────────────────┘│
│   │   └────────────────────────────────────────────────────────────┘
│   │
│   ├── 2b. Creates: ClusterRoleBinding (trust-manager)
│   ├── 2c. Creates: Role (trust-manager) - namespace-scoped
│   ├── 2d. Creates: Role (trust-manager:leaderelection)
│   ├── 2e. Creates: RoleBinding (trust-manager)
│   └── 2f. Creates: RoleBinding (trust-manager:leaderelection)
│       └── All apply: commonLabels, commonAnnotations
│
├── 3. createOrApplyServices()
│   ├── Creates: Service (trust-manager) - webhook
│   └── Creates: Service (trust-manager-metrics) - metrics
│       └── Applies: commonLabels, commonAnnotations
│
├── 4. createOrApplyIssuer()
│   └── Creates: Issuer (trust-manager) - self-signed for webhook cert
│       └── Applies: commonLabels, commonAnnotations
│
├── 5. createOrApplyCertificates()
│   └── Creates: Certificate (trust-manager) - webhook TLS
│       └── Applies: commonLabels, commonAnnotations
│
├── 6. createOrApplyDeployments()
│   └── Creates: Deployment (trust-manager)
│       ├── Applies: commonLabels, commonAnnotations
│       ├── Updates image from RELATED_IMAGE_TRUST_MANAGER env
│       ├── Updates args based on TrustManagerConfig:
│       │   ├── --log-format=<logFormat>
│       │   ├── --log-level=<logLevel>
│       │   ├── --trust-namespace=<trustNamespace>
│       │   ├── --secret-targets-enabled=<secretTargets.enabled>
│       │   └── --filter-expired-certificates=<filterExpiredCertificates>
│       ├── Updates resources, affinity, tolerations, nodeSelector
│       └── Updates status with image info
│
├── 7. createOrApplyValidatingWebhook()
│   └── Creates: ValidatingWebhookConfiguration (trust-manager)
│       └── Applies: commonLabels, commonAnnotations
│
└── 8. addProcessedAnnotation()
    └── Marks TrustManager CR as processed
```

### 7.3 Resource Creation Pattern

Each resource reconciliation follows this pattern:

```go
func (r *Reconciler) createOrApply<Resource>(
    trustManager *v1alpha1.TrustManager,
    resourceLabels map[string]string,
    createRecon bool,
) error {
    // 1. Generate desired state from bindata
    desired, err := r.get<Resource>Object(trustManager, resourceLabels)
    if err != nil {
        return fmt.Errorf("failed to generate: %w", err)
    }

    // 2. Check if resource exists
    fetched := &<ResourceType>{}
    exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
    if err != nil {
        return FromClientError(err, "failed to check existence")
    }

    // 3. Handle first-time creation warning
    if exist && createRecon {
        r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning,
            "ResourceAlreadyExists", "resource already exists")
    }

    // 4. Update if changed
    if exist && hasObjectChanged(desired, fetched) {
        r.log.V(1).Info("resource modified, updating to desired state")
        if err := r.UpdateWithRetry(r.ctx, desired); err != nil {
            return FromClientError(err, "failed to update")
        }
        r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal,
            "Reconciled", "resource reconciled")
    }

    // 5. Create if not exists
    if !exist {
        if err := r.Create(r.ctx, desired); err != nil {
            return FromClientError(err, "failed to create")
        }
        r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal,
            "Reconciled", "resource created")
    }

    return nil
}
```

### 7.4 Watch Configuration

```go
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
    // Map function to convert watched objects to reconcile requests
    // Map function for cluster-scoped singleton
    mapFunc := func(ctx context.Context, obj client.Object) []reconcile.Request {
        if obj.GetLabels()[requestEnqueueLabelKey] == requestEnqueueLabelValue {
            // TrustManager is cluster-scoped, no namespace in request
            return []reconcile.Request{{
                NamespacedName: types.NamespacedName{
                    Name: trustManagerObjectName, // Always "cluster"
                },
            }}
        }
        return nil
    }

    return ctrl.NewControllerManagedBy(mgr).
        // Primary watch on TrustManager CR
        For(&v1alpha1.TrustManager{},
            builder.WithPredicates(predicate.GenerationChangedPredicate{})).
        Named(ControllerName).
        
        // Secondary watches on managed resources
        Watches(&appsv1.Deployment{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&corev1.ServiceAccount{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&rbacv1.ClusterRole{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&rbacv1.ClusterRoleBinding{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&rbacv1.Role{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&rbacv1.RoleBinding{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&corev1.Service{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&certmanagerv1.Certificate{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&certmanagerv1.Issuer{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Watches(&admissionregistrationv1.ValidatingWebhookConfiguration{},
            handler.EnqueueRequestsFromMapFunc(mapFunc),
            withPredicates...).
        Complete(r)
}
```

### 7.5 Cache Configuration

```go
func NewCacheBuilder(config *rest.Config, opts cache.Options) (cache.Cache, error) {
    // Label selector for managed resources
    labelReq, _ := labels.NewRequirement("app", selection.Equals, []string{"trust-manager"})
    selector := labels.NewSelector().Add(*labelReq)

    opts.ByObject = map[client.Object]cache.ByObject{
        // Always cache TrustManager CR
        &v1alpha1.TrustManager{}: {},
        
        // Cache managed resources with label selector
        &appsv1.Deployment{}:                   {Label: selector},
        &corev1.ServiceAccount{}:               {Label: selector},
        &corev1.Service{}:                      {Label: selector},
        &rbacv1.ClusterRole{}:                  {Label: selector},
        &rbacv1.ClusterRoleBinding{}:           {Label: selector},
        &rbacv1.Role{}:                         {Label: selector},
        &rbacv1.RoleBinding{}:                  {Label: selector},
        &certmanagerv1.Certificate{}:           {Label: selector},
        &certmanagerv1.Issuer{}:                {Label: selector},
        &networkingv1.NetworkPolicy{}:          {Label: selector},
        &admissionregistrationv1.ValidatingWebhookConfiguration{}: {Label: selector},
    }

    return cache.New(config, opts)
}
```

---

## 8. Resource Lifecycle

### 8.1 Creation Sequence

```
User creates TrustManager CR (cluster-scoped, name="cluster")
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Controller Reconciliation                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 1: Identity & Permissions                                    │
│  ┌───────────────────┐                                              │
│  │ ServiceAccount    │──────────────────────────────────────────┐   │
│  └───────────────────┘                                          │   │
│           │                                                      │   │
│           ▼                                                      │   │
│  ┌───────────────────┐    ┌───────────────────┐                 │   │
│  │ ClusterRole       │    │ ClusterRoleBinding │◀────────────────┤   │
│  └───────────────────┘    └───────────────────┘                 │   │
│           │                                                      │   │
│           ▼                                                      │   │
│  ┌───────────────────┐    ┌───────────────────┐                 │   │
│  │ Role (ns-scoped)  │    │ RoleBinding       │◀────────────────┘   │
│  └───────────────────┘    └───────────────────┘                     │
│                                                                      │
│  Phase 2: Networking                                                │
│  ┌───────────────────┐    ┌───────────────────┐                     │
│  │ Service (webhook) │    │ Service (metrics) │                     │
│  └───────────────────┘    └───────────────────┘                     │
│                                                                      │
│  Phase 3: TLS                                                       │
│  ┌───────────────────┐                                              │
│  │ Issuer (self-sign)│                                              │
│  └─────────┬─────────┘                                              │
│            │                                                         │
│            ▼                                                         │
│  ┌───────────────────┐    ┌───────────────────┐                     │
│  │ Certificate       │───▶│ Secret (TLS)      │ (created by         │
│  └───────────────────┘    └───────────────────┘  cert-manager)      │
│                                   │                                  │
│  Phase 4: Workload                │                                  │
│  ┌───────────────────┐            │                                  │
│  │ Deployment        │◀───────────┘ (mounts TLS secret)             │
│  └───────────────────┘                                              │
│                                                                      │
│  Phase 5: Admission Control                                         │
│  ┌───────────────────────────────┐                                  │
│  │ ValidatingWebhookConfiguration│                                  │
│  └───────────────────────────────┘                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Update Handling

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Update Scenarios                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Scenario 1: TrustManager CR Updated                                │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ User modifies spec.trustManagerConfig                       │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Controller detects generation change                        │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Full reconciliation runs                                     │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Deployment updated with new args/resources                   │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Rolling update of trust-manager pods                         │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Scenario 2: Managed Resource Drifts                                │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ External actor modifies Deployment                          │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Controller watch triggers reconcile                          │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ hasObjectChanged() returns true                              │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Resource restored to desired state                           │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Event: "Reconciled - resource reconciled back to desired"   │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Scenario 3: Image Update (Operator Upgrade)                        │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ Operator deployment updated with new RELATED_IMAGE_*       │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Any TrustManager reconciliation will pick up new image       │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Deployment updated with new image                            │    │
│  │         │                                                    │    │
│  │         ▼                                                    │    │
│  │ Status updated with new trustManagerImage                    │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.3 Deletion Sequence

```
User deletes TrustManager CR
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Deletion Handling                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DeletionTimestamp is set on TrustManager CR                     │
│         │                                                            │
│         ▼                                                            │
│  2. Controller detects deletion in reconcile loop                   │
│         │                                                            │
│         ▼                                                            │
│  3. cleanUp() is called                                             │
│     ┌────────────────────────────────────────────────────────┐     │
│     │ • Log deletion event                                    │     │
│     │ • Emit warning event for user awareness                 │     │
│     │ • (Optional) Delete cluster-scoped resources:           │     │
│     │   - ClusterRole                                         │     │
│     │   - ClusterRoleBinding                                  │     │
│     │   - ValidatingWebhookConfiguration                      │     │
│     │ • Namespace-scoped resources deleted by GC              │     │
│     └────────────────────────────────────────────────────────┘     │
│         │                                                            │
│         ▼                                                            │
│  4. Remove finalizer from TrustManager CR                           │
│         │                                                            │
│         ▼                                                            │
│  5. TrustManager CR is garbage collected                            │
│         │                                                            │
│         ▼                                                            │
│  6. Namespace-scoped resources garbage collected (ownerRef)         │
│     • Deployment                                                     │
│     • ServiceAccount                                                 │
│     • Role, RoleBinding                                             │
│     • Service                                                        │
│     • Certificate, Issuer                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Data Flow

### 9.1 Configuration Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Configuration Data Flow                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────┐                                      │
│  │ TrustManager CR                   │                                      │
│  │                                   │                                      │
│  │ spec:                             │                                      │
│  │   trustManagerConfig:             │                                      │
│  │     logLevel: 2                   │──────────────┐                       │
│  │     logFormat: json               │              │                       │
│  │     trustNamespace: cert-manager  │              │                       │
│  │     filterExpiredCertificates: true              │                       │
│  │     secretTargets:                │              │                       │
│  │       enabled: true               │              │                       │
│  │       authorizedSecretsAll: false │              │                       │
│  │       authorizedSecrets:          │              │                       │
│  │         - "my-bundle"             │              │                       │
│  │         - "prod-bundle"           │              │                       │
│  │     resources: {...}              │              │                       │
│  │   controllerConfig:               │              │                       │
│  │     commonLabels:                 │              │                       │
│  │       team: platform              │              │                       │
│  │     commonAnnotations:            │              │                       │
│  │       owner: cert-team            │              │                       │
│  └───────────────────────────────────┘              │                       │
│                                                     │                       │
│                                                     ▼                       │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                      Controller Processing                             │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  1. RBAC Generation (based on secretTargets):                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │ │
│  │  │ generateSecretRBACRules(secretTargets):                          │  │ │
│  │  │                                                                  │  │ │
│  │  │ IF authorizedSecretsAll == true:                                │  │ │
│  │  │   → secrets: [get,list,create,patch,watch,delete] (ALL)         │  │ │
│  │  │                                                                  │  │ │
│  │  │ ELSE IF authorizedSecrets has items:                            │  │ │
│  │  │   → secrets: [get,list,watch] (ALL - for reading sources)       │  │ │
│  │  │   → secrets: [create,patch,delete]                              │  │ │
│  │  │     resourceNames: ["my-bundle", "prod-bundle"]  ◀── RESTRICTED │  │ │
│  │  │                                                                  │  │ │
│  │  │ ELSE (enabled but no secrets specified):                        │  │ │
│  │  │   → secrets: [get,list,watch] (read-only for sources)           │  │ │
│  │  └─────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                        │ │
│  │  2. Deployment Generation:                                            │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │ │
│  │  │ getDeploymentObject():                                           │  │ │
│  │  │                                                                  │  │ │
│  │  │ a. Load base deployment from bindata                            │  │ │
│  │  │ b. Apply commonLabels and commonAnnotations                     │  │ │
│  │  │ c. Update container args:                                       │  │ │
│  │  │    args := []string{                                            │  │ │
│  │  │      "--log-format=json",                   ◀── logFormat       │  │ │
│  │  │      "--log-level=2",                       ◀── logLevel        │  │ │
│  │  │      "--trust-namespace=cert-manager",      ◀── trustNamespace  │  │ │
│  │  │      "--secret-targets-enabled=true",       ◀── secretTargets   │  │ │
│  │  │      "--filter-expired-certificates=true",  ◀── filterExpired   │  │ │
│  │  │      ...                                                         │  │ │
│  │  │    }                                                             │  │ │
│  │  │ d. Update image from RELATED_IMAGE_TRUST_MANAGER                │  │ │
│  │  │ e. Update resources, affinity, tolerations, nodeSelector        │  │ │
│  │  └─────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                        │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                          │                                  │
│                                          ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Kubernetes API Server                           │   │
│  │                                                                      │   │
│  │  Resources created with commonLabels & commonAnnotations:           │   │
│  │                                                                      │   │
│  │  ClusterRole (dynamically generated):                               │   │
│  │  rules:                                                              │   │
│  │  - apiGroups: [""]                                                  │   │
│  │    resources: ["configmaps"]                                        │   │
│  │    verbs: ["get","list","create","patch","watch","delete"]          │   │
│  │  - apiGroups: [""]                                                  │   │
│  │    resources: ["secrets"]                                           │   │
│  │    verbs: ["get","list","watch"]                                    │   │
│  │  - apiGroups: [""]                                                  │   │
│  │    resources: ["secrets"]                                           │   │
│  │    verbs: ["create","patch","delete"]                               │   │
│  │    resourceNames: ["my-bundle","prod-bundle"]  # ← Limited access   │   │
│  │                                                                      │   │
│  │  Deployment:                                                         │   │
│  │  metadata:                                                           │   │
│  │    labels:                                                           │   │
│  │      team: platform               # ← from commonLabels             │   │
│  │    annotations:                                                      │   │
│  │      owner: cert-team             # ← from commonAnnotations        │   │
│  │  spec:                                                               │   │
│  │    template:                                                         │   │
│  │      spec:                                                           │   │
│  │        containers:                                                   │   │
│  │        - name: trust-manager                                         │   │
│  │          args:                                                       │   │
│  │          - "--log-level=2"                                          │   │
│  │          - "--log-format=json"                                      │   │
│  │          - "--trust-namespace=cert-manager"                         │   │
│  │          - "--secret-targets-enabled=true"                          │   │
│  │          - "--filter-expired-certificates=true"                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Trust Bundle Distribution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Trust Bundle Distribution Flow                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Trust Sources                                   │  │
│  │                                                                        │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │  │
│  │  │ Default CAs     │  │ ConfigMap       │  │ Secret              │   │  │
│  │  │ (Debian pkg)    │  │ (custom CA)     │  │ (private CA)        │   │  │
│  │  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘   │  │
│  │           │                    │                       │              │  │
│  └───────────┼────────────────────┼───────────────────────┼──────────────┘  │
│              │                    │                       │                  │
│              └────────────────────┼───────────────────────┘                  │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         Bundle CR                                      │  │
│  │  apiVersion: trust.cert-manager.io/v1alpha1                           │  │
│  │  kind: Bundle                                                          │  │
│  │  metadata:                                                             │  │
│  │    name: public-bundle                                                 │  │
│  │  spec:                                                                 │  │
│  │    sources:                                                            │  │
│  │      - useDefaultCAs: true                                            │  │
│  │      - configMap: {name: my-ca, key: ca.crt}                          │  │
│  │    target:                                                             │  │
│  │      configMap: {key: ca-bundle.crt}                                  │  │
│  │      namespaceSelector:                                               │  │
│  │        matchLabels: {trust: enabled}                                  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                   │                                          │
│                                   │ Watched by                               │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    trust-manager Controller                            │  │
│  │                                                                        │  │
│  │  1. Aggregates certificates from all sources                          │  │
│  │  2. Validates PEM format                                              │  │
│  │  3. Identifies target namespaces (selector)                           │  │
│  │  4. Creates/updates ConfigMaps in each namespace                      │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                   │                                          │
│                                   │ Creates                                  │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Target Namespaces                                   │  │
│  │                                                                        │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │  │
│  │  │ namespace: app1 │  │ namespace: app2 │  │ namespace: app3     │   │  │
│  │  │ labels:         │  │ labels:         │  │ labels:             │   │  │
│  │  │   trust: enabled│  │   trust: enabled│  │   trust: enabled    │   │  │
│  │  │                 │  │                 │  │                     │   │  │
│  │  │ ConfigMap:      │  │ ConfigMap:      │  │ ConfigMap:          │   │  │
│  │  │  public-bundle  │  │  public-bundle  │  │  public-bundle      │   │  │
│  │  │  data:          │  │  data:          │  │  data:              │   │  │
│  │  │   ca-bundle.crt │  │   ca-bundle.crt │  │   ca-bundle.crt     │   │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘   │  │
│  │                                                                        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Integration Points

### 10.1 Cert-Manager Integration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Cert-Manager Integration                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  trust-manager requires cert-manager for webhook TLS:                       │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Dependency Chain                                  │   │
│  │                                                                      │   │
│  │  cert-manager-operator                                              │   │
│  │         │                                                            │   │
│  │         │ deploys                                                    │   │
│  │         ▼                                                            │   │
│  │  ┌─────────────────┐                                                │   │
│  │  │ cert-manager    │◀───────────────────────────────────────┐       │   │
│  │  │ (controller,    │                                         │       │   │
│  │  │  webhook,       │         Issues certificates             │       │   │
│  │  │  cainjector)    │                                         │       │   │
│  │  └─────────────────┘                                         │       │   │
│  │                                                              │       │   │
│  │  TrustManager controller                                     │       │   │
│  │         │                                                    │       │   │
│  │         │ deploys                                            │       │   │
│  │         ▼                                                    │       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │ trust-manager namespace                                     │   │   │
│  │  │                                                             │   │   │
│  │  │  ┌───────────────┐    ┌───────────────┐                    │   │   │
│  │  │  │ Issuer        │───▶│ Certificate   │────────────────────┼───┘   │
│  │  │  │ (self-signed) │    │ (trust-manager│                    │       │
│  │  │  └───────────────┘    │  -tls)        │                    │       │
│  │  │                       └───────┬───────┘                    │       │
│  │  │                               │                            │       │
│  │  │                               │ creates                    │       │
│  │  │                               ▼                            │       │
│  │  │                       ┌───────────────┐                    │       │
│  │  │                       │ Secret        │                    │       │
│  │  │                       │ (trust-manager│                    │       │
│  │  │                       │  -tls)        │                    │       │
│  │  │                       └───────┬───────┘                    │       │
│  │  │                               │                            │       │
│  │  │                               │ mounted                    │       │
│  │  │                               ▼                            │       │
│  │  │                       ┌───────────────┐                    │       │
│  │  │                       │ Deployment    │                    │       │
│  │  │                       │ (trust-manager│                    │       │
│  │  │                       │  pod)         │                    │       │
│  │  │                       └───────────────┘                    │       │
│  │  │                                                             │       │
│  │  └─────────────────────────────────────────────────────────────┘       │
│  │                                                                         │
│  └─────────────────────────────────────────────────────────────────────────┘
│                                                                              │
│  Prerequisite: cert-manager must be installed before TrustManager CR        │
│                can be successfully reconciled.                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Feature Gate Integration

```go
// pkg/operator/starter.go

func RunOperator(ctx context.Context, cc *controllercmd.ControllerContext) error {
    // ... existing setup ...

    // Parse feature flags
    err = features.SetupWithFlagValue(UnsupportedAddonFeatures)
    if err != nil {
        return fmt.Errorf("failed to parse addon features: %w", err)
    }

    // Conditionally start controllers based on feature gates
    if features.DefaultFeatureGate.Enabled(v1alpha1.FeatureIstioCSR) {
        // Start IstioCSR controller
    }

    if features.DefaultFeatureGate.Enabled(v1alpha1.FeatureTrustManager) {
        // Start TrustManager controller
        manager, err := NewTrustManagerControllerManager()
        if err != nil {
            return fmt.Errorf("failed to create trust-manager controller: %w", err)
        }
        if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
            return fmt.Errorf("failed to start trust-manager controller: %w", err)
        }
    }

    <-ctx.Done()
    return nil
}
```

### 10.3 Operator Deployment Integration

```yaml
# Operator Deployment with trust-manager related images
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-operator
spec:
  template:
    spec:
      containers:
      - name: operator
        env:
        # Existing images
        - name: RELATED_IMAGE_CERT_MANAGER_CONTROLLER
          value: quay.io/jetstack/cert-manager-controller:v1.14.0
        - name: RELATED_IMAGE_CERT_MANAGER_WEBHOOK
          value: quay.io/jetstack/cert-manager-webhook:v1.14.0
        - name: RELATED_IMAGE_CERT_MANAGER_CAINJECTOR
          value: quay.io/jetstack/cert-manager-cainjector:v1.14.0
        
        # IstioCSR images
        - name: RELATED_IMAGE_CERT_MANAGER_ISTIOCSR
          value: quay.io/jetstack/cert-manager-istio-csr:v0.8.1
        
        # Trust-manager images (NEW)
        - name: RELATED_IMAGE_TRUST_MANAGER
          value: quay.io/jetstack/trust-manager:v0.20.3
        - name: RELATED_IMAGE_TRUST_PKG_DEBIAN
          value: quay.io/jetstack/trust-pkg-debian-bookworm:20230311-deb12u1.2
        - name: TRUSTMANAGER_OPERAND_IMAGE_VERSION
          value: v0.20.3
```

---

## 11. Security Considerations

### 11.1 RBAC Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RBAC Architecture                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              cert-manager-operator ServiceAccount                    │   │
│  │                                                                      │   │
│  │  Permissions needed to manage trust-manager:                        │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────┐    │   │
│  │  │ ClusterRole: cert-manager-operator                          │    │   │
│  │  │                                                             │    │   │
│  │  │ # TrustManager CR management                                │    │   │
│  │  │ - apiGroups: [operator.openshift.io]                       │    │   │
│  │  │   resources: [trustmanagers, trustmanagers/status]         │    │   │
│  │  │   verbs: [get, list, watch, update, patch]                 │    │   │
│  │  │                                                             │    │   │
│  │  │ # Managed resource creation                                 │    │   │
│  │  │ - apiGroups: [apps]                                        │    │   │
│  │  │   resources: [deployments]                                  │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [""]                                          │    │   │
│  │  │   resources: [serviceaccounts, services]                   │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [rbac.authorization.k8s.io]                   │    │   │
│  │  │   resources: [clusterroles, clusterrolebindings,           │    │   │
│  │  │               roles, rolebindings]                          │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [cert-manager.io]                             │    │   │
│  │  │   resources: [certificates, issuers]                       │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [admissionregistration.k8s.io]                │    │   │
│  │  │   resources: [validatingwebhookconfigurations]             │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [networking.k8s.io]                           │    │   │
│  │  │   resources: [networkpolicies]                             │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  └────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              trust-manager ServiceAccount                            │   │
│  │                                                                      │   │
│  │  Permissions for trust-manager operand:                             │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────┐    │   │
│  │  │ ClusterRole: trust-manager                                  │    │   │
│  │  │                                                             │    │   │
│  │  │ # Bundle management                                         │    │   │
│  │  │ - apiGroups: [trust.cert-manager.io]                       │    │   │
│  │  │   resources: [bundles]                                      │    │   │
│  │  │   verbs: [get, list, watch]                                │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [trust.cert-manager.io]                       │    │   │
│  │  │   resources: [bundles/status]                              │    │   │
│  │  │   verbs: [get, update, patch]                              │    │   │
│  │  │                                                             │    │   │
│  │  │ # ConfigMap/Secret distribution                            │    │   │
│  │  │ - apiGroups: [""]                                          │    │   │
│  │  │   resources: [configmaps, secrets]                         │    │   │
│  │  │   verbs: [get, list, watch, create, update, patch, delete] │    │   │
│  │  │                                                             │    │   │
│  │  │ # Namespace listing for selectors                          │    │   │
│  │  │ - apiGroups: [""]                                          │    │   │
│  │  │   resources: [namespaces]                                  │    │   │
│  │  │   verbs: [get, list, watch]                                │    │   │
│  │  │                                                             │    │   │
│  │  │ # Events                                                    │    │   │
│  │  │ - apiGroups: [""]                                          │    │   │
│  │  │   resources: [events]                                      │    │   │
│  │  │   verbs: [create, patch]                                   │    │   │
│  │  └────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────┐    │   │
│  │  │ Role: trust-manager:leaderelection                          │    │   │
│  │  │                                                             │    │   │
│  │  │ - apiGroups: [coordination.k8s.io]                         │    │   │
│  │  │   resources: [leases]                                       │    │   │
│  │  │   verbs: [get, create, update, patch]                      │    │   │
│  │  └────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Pod Security

```yaml
# trust-manager deployment security context
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: trust-manager
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          capabilities:
            drop:
              - ALL
          seccompProfile:
            type: RuntimeDefault
```

### 11.3 Network Policies (Optional)

```yaml
# Deny-all base policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: trust-manager-deny-all
  namespace: trust-manager
spec:
  podSelector:
    matchLabels:
      app: trust-manager
  policyTypes:
    - Ingress
    - Egress

---
# Allow webhook ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: trust-manager-allow-webhook
  namespace: trust-manager
spec:
  podSelector:
    matchLabels:
      app: trust-manager
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - port: 6443
          protocol: TCP

---
# Allow API server egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: trust-manager-allow-api-server
  namespace: trust-manager
spec:
  podSelector:
    matchLabels:
      app: trust-manager
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: <API_SERVER_CIDR>
      ports:
        - port: 6443
          protocol: TCP
```

---

## 12. Deployment Topology

### 12.1 Single Cluster Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Cluster                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Control Plane Nodes                                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                                                                         │ │
│  │  API Server ◀──────────────────────────────────────┐                   │ │
│  │      ▲                                              │                   │ │
│  │      │                                              │                   │ │
│  └──────┼──────────────────────────────────────────────┼───────────────────┘ │
│         │                                              │                     │
│         │ Watch/CRUD                                   │ Webhook calls       │
│         │                                              │                     │
│  Worker Nodes                                          │                     │
│  ┌────────────────────────────────────────────────────┼───────────────────┐ │
│  │                                                    │                    │ │
│  │  ┌─────────────────────────────────────────────────┴───────────────┐   │ │
│  │  │                   cert-manager-operator namespace                │   │ │
│  │  │                                                                  │   │ │
│  │  │  ┌────────────────────────────────────────────────────────────┐ │   │ │
│  │  │  │            cert-manager-operator Pod                        │ │   │ │
│  │  │  │                                                             │ │   │ │
│  │  │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │ │   │ │
│  │  │  │  │ CertManager │ │ IstioCSR    │ │ TrustManager        │  │ │   │ │
│  │  │  │  │ Controller  │ │ Controller  │ │ Controller          │  │ │   │ │
│  │  │  │  └─────────────┘ └─────────────┘ └─────────────────────┘  │ │   │ │
│  │  │  │                                                             │ │   │ │
│  │  │  └────────────────────────────────────────────────────────────┘ │   │ │
│  │  │                                                                  │   │ │
│  │  └──────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                          │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │ │
│  │  │                     cert-manager namespace                        │   │ │
│  │  │                                                                   │   │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │   │ │
│  │  │  │ controller  │  │ webhook     │  │ cainjector              │  │   │ │
│  │  │  │ Pod         │  │ Pod         │  │ Pod                     │  │   │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │   │ │
│  │  │                                                                   │   │ │
│  │  └───────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                          │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │ │
│  │  │                     trust-manager namespace                       │   │ │
│  │  │                                                                   │   │ │
│  │  │  ┌─────────────────────────────────────────────────────────────┐ │   │ │
│  │  │  │                   trust-manager Pod                          │ │   │ │
│  │  │  │                                                              │ │   │ │
│  │  │  │  ┌──────────────────┐  ┌───────────────────────────────┐   │ │   │ │
│  │  │  │  │ init: trust-pkg  │  │ container: trust-manager      │   │ │   │ │
│  │  │  │  │ (debian CA pkg)  │  │                               │   │ │   │ │
│  │  │  │  └──────────────────┘  │ - watches Bundle CRs          │   │ │   │ │
│  │  │  │                        │ - distributes to namespaces   │   │ │   │ │
│  │  │  │                        │ - webhook server (6443)       │   │ │   │ │
│  │  │  │                        │ - metrics server (9402)       │   │ │   │ │
│  │  │  │                        └───────────────────────────────┘   │ │   │ │
│  │  │  │                                                              │ │   │ │
│  │  │  └─────────────────────────────────────────────────────────────┘ │   │ │
│  │  │                                                                   │   │ │
│  │  └───────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.2 Resource Requirements

| Component            | CPU Request | CPU Limit | Memory Request | Memory Limit |
| -------------------- | ----------- | --------- | -------------- | ------------ |
| trust-manager        | 50m         | 100m      | 64Mi           | 128Mi        |
| trust-manager (init) | 10m         | 50m       | 32Mi           | 64Mi         |

---

## 13. Implementation Phases

### Phase 1: Foundation (Week 1-2)

| Task | Description                                                  | Status |
| ---- | ------------------------------------------------------------ | ------ |
| 1.1  | Create `TrustManager` types in `api/operator/v1alpha1/`      | 🔲      |
| 1.2  | Add `FeatureTrustManager` feature gate                       | 🔲      |
| 1.3  | Generate deepcopy and CRD manifests                          | 🔲      |
| 1.4  | Create controller skeleton in `pkg/controller/trustmanager/` | 🔲      |

### Phase 2: Controller Implementation (Week 3-4)

| Task | Description                                         | Status |
| ---- | --------------------------------------------------- | ------ |
| 2.1  | Implement `controller.go` with cache and watches    | 🔲      |
| 2.2  | Implement `client.go` with retry logic              | 🔲      |
| 2.3  | Implement `serviceaccounts.go`                      | 🔲      |
| 2.4  | Implement `rbacs.go` (ClusterRole, Role, Bindings)  | 🔲      |
| 2.5  | Implement `services.go`                             | 🔲      |
| 2.6  | Implement `certificates.go` (Issuer + Certificate)  | 🔲      |
| 2.7  | Implement `deployments.go` with image/args handling | 🔲      |
| 2.8  | Implement `webhooks.go`                             | 🔲      |

### Phase 3: Integration (Week 5)

| Task | Description                                  | Status |
| ---- | -------------------------------------------- | ------ |
| 3.1  | Update `pkg/operator/setup_manager.go`       | 🔲      |
| 3.2  | Regenerate bindata with trust-manager assets | 🔲      |
| 3.3  | Update operator RBAC                         | 🔲      |
| 3.4  | Add related images to deployment             | 🔲      |
| 3.5  | Generate typed clients                       | 🔲      |

### Phase 4: Bundle & Documentation (Week 6)

| Task | Description                       | Status |
| ---- | --------------------------------- | ------ |
| 4.1  | Update bundle manifests           | 🔲      |
| 4.2  | Update CSV with TrustManager CRD  | 🔲      |
| 4.3  | Add Bundle CRD to operator bundle | 🔲      |
| 4.4  | Create user documentation         | 🔲      |

### Phase 5: Testing (Week 7-8)

| Task | Description                              | Status |
| ---- | ---------------------------------------- | ------ |
| 5.1  | Unit tests for all controller components | 🔲      |
| 5.2  | Integration tests                        | 🔲      |
| 5.3  | E2E tests                                | 🔲      |
| 5.4  | Upgrade/downgrade testing                | 🔲      |

---

## 14. Testing Strategy

### 14.1 Unit Tests

```go
// Example: deployments_test.go
func TestGetDeploymentObject(t *testing.T) {
    tests := []struct {
        name          string
        trustManager  *v1alpha1.TrustManager
        expectedArgs  []string
        expectedImage string
    }{
        {
            name: "default configuration",
            trustManager: &v1alpha1.TrustManager{
                Spec: v1alpha1.TrustManagerSpec{
                    TrustManagerConfig: v1alpha1.TrustManagerConfig{
                        LogLevel:             1,
                        LogFormat:            "text",
                        TrustNamespace:       "cert-manager",
                        SecretTargetsEnabled: true,
                    },
                },
            },
            expectedArgs: []string{
                "--log-level=1",
                "--log-format=text",
                "--trust-namespace=cert-manager",
                "--secret-targets-enabled=true",
            },
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### 14.2 Integration Tests

```go
// Example: controller_test.go
func TestTrustManagerReconciliation(t *testing.T) {
    ctx := context.Background()
    
    // Setup test environment with envtest
    testEnv := &envtest.Environment{
        CRDDirectoryPaths: []string{
            filepath.Join("..", "..", "..", "config", "crd", "bases"),
        },
    }
    
    // Create TrustManager CR
    trustManager := &v1alpha1.TrustManager{
        ObjectMeta: metav1.ObjectMeta{
            Name: "cluster",  // Cluster-scoped singleton, must be "cluster"
        },
        Spec: v1alpha1.TrustManagerSpec{
            // Operand deployed in cert-manager namespace (hardcoded)
            TrustManagerConfig: v1alpha1.TrustManagerConfig{
                LogLevel: 2,
            },
        },
    }
    
    // Reconcile - cluster-scoped, no namespace in request
    result, err := reconciler.Reconcile(ctx, ctrl.Request{
        NamespacedName: types.NamespacedName{
            Name: "cluster",
        },
    })
    
    // Verify resources created
    assert.NoError(t, err)
    assert.False(t, result.Requeue)
    
    // Verify Deployment
    deployment := &appsv1.Deployment{}
    err = k8sClient.Get(ctx, types.NamespacedName{
        Name:      "trust-manager",
        Namespace: "test-namespace",
    }, deployment)
    assert.NoError(t, err)
    assert.Contains(t, deployment.Spec.Template.Spec.Containers[0].Args, "--log-level=2")
}
```

### 14.3 E2E Tests

```go
// Example: e2e_test.go
func TestTrustManagerE2E(t *testing.T) {
    // 1. Create TrustManager CR
    trustManager := &v1alpha1.TrustManager{...}
    err := k8sClient.Create(ctx, trustManager)
    require.NoError(t, err)
    
    // 2. Wait for Ready condition
    Eventually(func() bool {
        tm := &v1alpha1.TrustManager{}
        k8sClient.Get(ctx, client.ObjectKeyFromObject(trustManager), tm)
        return meta.IsStatusConditionTrue(tm.Status.Conditions, "Ready")
    }, timeout, interval).Should(BeTrue())
    
    // 3. Create Bundle
    bundle := &trustv1alpha1.Bundle{...}
    err = k8sClient.Create(ctx, bundle)
    require.NoError(t, err)
    
    // 4. Verify ConfigMap distributed
    Eventually(func() bool {
        cm := &corev1.ConfigMap{}
        err := k8sClient.Get(ctx, types.NamespacedName{
            Name:      bundle.Name,
            Namespace: "target-namespace",
        }, cm)
        return err == nil && cm.Data["ca-bundle.crt"] != ""
    }, timeout, interval).Should(BeTrue())
    
    // 5. Cleanup
    k8sClient.Delete(ctx, trustManager)
}
```

---

## 15. Operational Considerations

### 15.1 Monitoring

| Metric                                      | Description                           |
| ------------------------------------------- | ------------------------------------- |
| `trust_manager_bundle_synced_count`         | Number of successfully synced bundles |
| `trust_manager_bundle_sync_errors`          | Number of bundle sync errors          |
| `trust_manager_target_update_count`         | Number of ConfigMap/Secret updates    |
| `controller_runtime_reconcile_total`        | Total reconciliations by controller   |
| `controller_runtime_reconcile_errors_total` | Reconciliation errors                 |

### 15.2 Logging

```
# Operator logs (cluster-scoped, no namespace in request)
{"level":"info","controller":"trust-manager-controller","msg":"reconciling","request":"cluster"}
{"level":"info","controller":"trust-manager-controller","msg":"deployment updated","namespace":"cert-manager","name":"trust-manager"}

# trust-manager operand logs  
{"level":"info","msg":"syncing bundle","bundle":"public-bundle"}
{"level":"info","msg":"updated target","target":"configmap/public-bundle","namespace":"app-1"}
```

### 15.3 Troubleshooting Guide

| Symptom                             | Possible Cause              | Resolution                 |
| ----------------------------------- | --------------------------- | -------------------------- |
| TrustManager stuck in "Progressing" | cert-manager not installed  | Install cert-manager first |
| Certificate not issued              | Issuer not ready            | Check cert-manager logs    |
| Bundle not syncing                  | Namespace selector mismatch | Verify namespace labels    |
| Webhook failures                    | TLS secret not mounted      | Check Certificate status   |

### 15.4 Upgrade Path

```
v0.20.x → v0.21.x (Example)

1. Update RELATED_IMAGE_TRUST_MANAGER in operator deployment
2. Operator detects image change on next reconciliation
3. Deployment updated with new image
4. Rolling update of trust-manager pods
5. Status updated with new image version
```

---

## Appendix A: Reference Links

- [trust-manager GitHub](https://github.com/cert-manager/trust-manager)
- [trust-manager Documentation](https://cert-manager.io/docs/projects/trust-manager/)
- [cert-manager Operator](https://github.com/openshift/cert-manager-operator)
- [Kubernetes Operator Pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
- [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime)

---

## Appendix B: Glossary

| Term                     | Definition                                                                     |
| ------------------------ | ------------------------------------------------------------------------------ |
| **Bundle**               | trust-manager CRD that defines trust sources and distribution targets          |
| **Trust Source**         | Origin of CA certificates (ConfigMap, Secret, default CAs)                     |
| **Trust Target**         | Destination for distributed CA bundle (ConfigMap or Secret)                    |
| **Operand**              | The software managed by an operator (trust-manager in this case)               |
| **Bindata**              | Pre-packaged Kubernetes manifests embedded in the operator binary              |
| **Feature Gate**         | Toggle for enabling/disabling optional features                                |
| **Cluster-Scoped**       | A Kubernetes resource that exists at the cluster level, not within a namespace |
| **Singleton**            | A resource pattern where only one instance with a specific name is allowed     |
| **authorizedSecrets**    | List of specific secret names that trust-manager can write to                  |
| **authorizedSecretsAll** | Flag to grant trust-manager write access to all secrets                        |

---

## Appendix C: Usage Examples

### C.1 Basic TrustManager Installation (ConfigMap targets only)

```yaml
# Minimal configuration - only ConfigMap targets, no secret access
# TrustManager is cluster-scoped, name MUST be "cluster"
# trust-manager operand is deployed in cert-manager namespace
apiVersion: operator.openshift.io/v1alpha1
kind: TrustManager
metadata:
  name: cluster                    # Must be "cluster" - singleton
spec:
  trustManagerConfig:
    logLevel: 1
    logFormat: text
    trustNamespace: cert-manager
```

### C.2 TrustManager with Secret Targets (Specific Secrets)

```yaml
# Enable secret targets with specific authorized secrets
# trust-manager can only write to "app-trust-bundle" and "prod-ca-bundle" secrets
# trust-manager operand is deployed in cert-manager namespace
apiVersion: operator.openshift.io/v1alpha1
kind: TrustManager
metadata:
  name: cluster                    # Must be "cluster" - singleton
spec:
  trustManagerConfig:
    logLevel: 2
    logFormat: json
    trustNamespace: cert-manager
    
    # Enable secret targets with restricted access
    secretTargets:
      enabled: true
      authorizedSecretsAll: false
      authorizedSecrets:
        - "app-trust-bundle"
        - "prod-ca-bundle"
        - "staging-ca-bundle"
    
    # Filter out expired certificates
    filterExpiredCertificates: true
    
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 100m
        memory: 128Mi
  
  controllerConfig:
    commonLabels:
      app.kubernetes.io/part-of: security-infrastructure
      team: platform-security
    commonAnnotations:
      owner: security-team@company.com
```

### C.3 TrustManager with Full Secret Access (Use with Caution!)

```yaml
# ⚠️ WARNING: Grants access to ALL secrets cluster-wide
# Only use this when you need to write to dynamically-named secrets
# trust-manager operand is deployed in cert-manager namespace
apiVersion: operator.openshift.io/v1alpha1
kind: TrustManager
metadata:
  name: cluster                    # Must be "cluster" - singleton
spec:
  trustManagerConfig:
    logLevel: 1
    logFormat: text
    trustNamespace: cert-manager
    
    # Full secret access - USE WITH CAUTION!
    secretTargets:
      enabled: true
      authorizedSecretsAll: true  # Grants access to ALL secrets
    
    filterExpiredCertificates: true
```

### C.4 TrustManager with Custom Scheduling

```yaml
# Advanced scheduling configuration
# trust-manager operand is deployed in cert-manager namespace
apiVersion: operator.openshift.io/v1alpha1
kind: TrustManager
metadata:
  name: cluster                    # Must be "cluster" - singleton
spec:
  trustManagerConfig:
    logLevel: 1
    logFormat: text
    trustNamespace: cert-manager
    
    secretTargets:
      enabled: true
      authorizedSecrets:
        - "my-trust-bundle"
    
    # Schedule only on specific nodes
    nodeSelector:
      kubernetes.io/os: linux
      node-role.kubernetes.io/infra: ""
    
    # Tolerate infra node taints
    tolerations:
      - key: "node-role.kubernetes.io/infra"
        operator: "Exists"
        effect: "NoSchedule"
    
    # Pod anti-affinity for HA
    affinity:
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: trust-manager
              topologyKey: kubernetes.io/hostname
    
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 200m
        memory: 256Mi
```

### C.5 Creating a Bundle (After TrustManager is Installed)

```yaml
# Bundle using default CAs (Debian package)
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: public-trust-bundle
spec:
  sources:
    - useDefaultCAs: true
  target:
    configMap:
      key: "ca-certificates.crt"
    namespaceSelector:
      matchLabels:
        trust-bundle.cert-manager.io/enabled: "true"
---
# Bundle with custom CA from ConfigMap
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: internal-ca-bundle
spec:
  sources:
    - configMap:
        name: "internal-ca"
        key: "ca.crt"
  target:
    configMap:
      key: "internal-ca.crt"
---
# Bundle targeting a Secret (requires secretTargets.enabled=true)
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: app-trust-bundle
spec:
  sources:
    - useDefaultCAs: true
    - configMap:
        name: "internal-ca"
        key: "ca.crt"
  target:
    secret:
      key: "ca-bundle.crt"
    namespaceSelector:
      matchLabels:
        needs-secret-trust: "true"
```

### C.6 Generated RBAC Examples

Based on the TrustManager configuration, the operator generates different ClusterRole rules:

**When `secretTargets.enabled=false` (default):**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trust-manager
rules:
  - apiGroups: ["trust.cert-manager.io"]
    resources: ["bundles"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["trust.cert-manager.io"]
    resources: ["bundles/finalizers"]
    verbs: ["update"]
  - apiGroups: ["trust.cert-manager.io"]
    resources: ["bundles/status"]
    verbs: ["patch"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "create", "patch", "watch", "delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
  # No secret rules - secrets not accessible
```

**When `secretTargets.authorizedSecrets=["my-bundle","prod-bundle"]`:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trust-manager
rules:
  # ... base rules ...
  # Read access to all secrets (for sources)
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
  # Write access ONLY to specified secrets
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create", "patch", "delete"]
    resourceNames:
      - "my-bundle"
      - "prod-bundle"
```

**When `secretTargets.authorizedSecretsAll=true`:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trust-manager
rules:
  # ... base rules ...
  # Full access to ALL secrets (use with caution!)
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "patch", "watch", "delete"]
```

---

## Document History

| Version | Date          | Author | Changes                                                                                |
| ------- | ------------- | ------ | -------------------------------------------------------------------------------------- |
| 1.0     | December 2024 | -      | Initial draft                                                                          |
| 1.1     | December 2024 | -      | Added secretTargets, filterExpiredCertificates, commonLabels/Annotations configuration |
| 1.2     | December 2024 | -      | Changed TrustManager to cluster-scoped singleton with name "cluster"                   |
| 1.3     | December 2024 | -      | Removed operandNamespace; trust-manager always deploys in cert-manager namespace       |

