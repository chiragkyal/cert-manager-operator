# Switching to approver-policy

Draft product documentation for the proposed `ApproverPolicyManager` feature.

approver-policy evaluates certificate requests against `CertificateRequestPolicy`
resources. When no policies exist, it neither approves nor denies requests. The
built-in cert-manager approver can continue approving requests for its supported
issuers until the operator disables it. Running both components during this
period does not create competing approval decisions from approver-policy.
See [approver-policy behavior](https://cert-manager.io/docs/policy/approval/approver-policy/).

Policy enforcement begins after the built-in approver has been disabled. An
`ApproverPolicyManager` reporting `Ready=True` indicates that the operand is
running; the operator still needs to complete the handoff. Wait for
`CertManager/cluster` to report `.status.autoApproverDisabled=true` before
creating policies or relying on them to control issuance.

The operator records `AutoApproverDisableRequested=True` in the CertManager
conditions before removing the built-in approver's approval permissions, then
updates the cert-manager Deployment and waits for the old approver-enabled pods
to terminate. It reports completion only after observing the rollout and
confirming that those permissions are absent. If a step fails, it retries
without restoring permissions already removed. A false or absent completion
value does not prove that default approval is still active; requests, including
trust-manager webhook certificate requests, can remain pending during the
transition. Inspect the CertManager status conditions for progress or errors.
Removing RBAC does not cancel approvals already in flight or guarantee immediate
authorization-cache propagation.

## First installation with no existing policies

Use this sequence with an operator version that provides `ApproverPolicyManager`
and with its feature gate enabled.

1. Check for existing policies:

   ```sh
   oc get certificaterequestpolicies.policy.cert-manager.io
   ```

   Continue with this procedure only if the command succeeds and reports no
   policies. If any policies exist, follow [Existing policies and reinstallation](#existing-policies-and-reinstallation).
   Keep policy-creating automation paused until step 4.

2. Create the cluster-scoped `ApproverPolicyManager` named `cluster`, with the
   configuration appropriate for your installation. A minimal configuration is:

   ```yaml
   apiVersion: operator.openshift.io/v1alpha1
   kind: ApproverPolicyManager
   metadata:
     name: cluster
   spec:
     approverPolicyConfig: {}
   ```

3. Wait for the operand to become ready, then wait for the operator to disable
   the built-in approver:

   ```sh
   oc wait --for=condition=Ready approverpolicymanagers.operator.openshift.io/cluster --timeout=300s
   oc wait --for=jsonpath='{.status.autoApproverDisabled}'=true certmanagers.operator.openshift.io/cluster --timeout=300s
   oc wait --for=condition=AutoApproverDegraded=false certmanagers.operator.openshift.io/cluster --timeout=300s
   oc wait --for=condition=AutoApproverProgressing=false certmanagers.operator.openshift.io/cluster --timeout=300s
   ```

   If any command fails or times out, inspect the `ApproverPolicyManager` and
   `CertManager` status before continuing. `Ready=True` alone is insufficient;
   a false or absent `autoApproverDisabled` value does not confirm the handoff.
   An already true completion value stays latched while the manager exists;
   also check the conditions to detect a later conflict or configuration drift.

4. Create your `CertificateRequestPolicy` resources and the RBAC bindings that
   allow requestors to use them. Resume policy-creating automation if applicable.

Before the disable transition starts, certificate issuance follows the existing
default approval behavior. Approval can stop before the operator reports
completion. After the built-in approver is disabled, requests without an
applicable policy remain pending, assuming no other approver acts on them. Plan
for this interruption to issuance and renewal while configuring policies. Once
applicable policies are ready and their RBAC bindings are in place, approver-policy
can evaluate pending and new requests.

## Restricting signer approval permissions

`spec.approverPolicyConfig.approveSignerNames` controls the operand's permission
to set `Approved` or `Denied` on requests for particular issuers. For example,
the [manager sample](../config/samples/tech-preview/operator.openshift.io_v1alpha1_approverpolicymanager.yaml)
restricts that permission to the `app-ca` Issuer in `example-apps`:

```yaml
spec:
  approverPolicyConfig:
    approveSignerNames:
      - issuers.cert-manager.io/example-apps.app-ca
```

Omitting the field or setting it to `[]` permits all signers, including external
issuers. An explicit list replaces that unrestricted scope. It accepts at most
50 unique, nonempty entries, each at most 825 characters. The operator reconciles
changes to the operand's approval ClusterRole; edit the manager configuration
instead of editing that role directly.

Signer names use the issuer resource's plural name and API group:

| Scope | Example |
|---|---|
| One namespaced Issuer | `issuers.cert-manager.io/example-apps.app-ca` |
| All built-in ClusterIssuers | `clusterissuers.cert-manager.io/*` |
| All issuers of an external type | `myissuers.my-example.io/*` |

The external example assumes an installed issuer resource named `myissuers` in
API group `my-example.io`; substitute your issuer's actual identifiers. These
permissions authorize both approval and denial. They do not grant a requestor
permission to use a policy. An approval or denial outside this scope is rejected
by the cert-manager webhook, even if a policy would permit it. See the upstream
[signer RBAC syntax](https://cert-manager.io/docs/usage/certificaterequest/#rbac-syntax).

## Creating and authorizing a policy

Complete the handoff checks above before applying workload policies. The
operator installs the policy API and operand; administrators create the policies
and their `use` bindings. The operator does not install a permissive workload
policy or bind all requestors automatically.

The [policy sample](../config/samples/tech-preview/policy.cert-manager.io_v1alpha1_certificaterequestpolicy.yaml)
assumes an existing namespace `example-apps` and an existing `app-ca` Issuer
there. It selects requests only when **both** the issuer reference and namespace
match. `namespace.matchLabels` can also select namespace labels; when names and
labels are supplied, both must match. An omitted namespace selector selects all
namespaces, and `issuerRef: {}` matches all issuer references.

The sample requires at least one DNS SAN, limits usages to the listed values,
and permits DNS names such as `web.example-apps.svc.cluster.local`. Its `*`
pattern is an allowed-value match, not a regular expression. The additional CEL
rule checks the request namespace: `self` is the individual DNS name, and `cr`
provides the CertificateRequest's `namespace` and `name`. Every supplied value
must pass every validation rule. Other name fields, such as common name, must
remain empty unless the policy explicitly permits them. `required: true`
requires a value; merely allowing a value does not require its presence.

The lifetime bounds are inclusive: the sample requires an explicit duration
between `1h` and `24h`, and an RSA key between 2048 and 4096 bits. Omitting a
constraint removes that bound; it does not supply a default or force an issuer
to issue the requested lifetime. These fields and their semantics follow the
shipped [v0.27.0 policy API](https://github.com/cert-manager/approver-policy/blob/v0.27.0/pkg/apis/policy/v1alpha1/types_certificaterequestpolicy.go).

Save the following as `example-policy-use.yaml`. It grants use of only
`example-policy`, for requests in `example-apps`, to the cert-manager controller
service account. This is the identity that creates requests for `Certificate`
resources in this installation.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: example-policy-use
rules:
  - apiGroups: [policy.cert-manager.io]
    resources: [certificaterequestpolicies]
    verbs: [use]
    resourceNames: [example-policy]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: example-policy-use
  namespace: example-apps
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: example-policy-use
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
```

Although the policy is cluster-scoped, approver-policy checks `use` in the
**request's namespace**, so this RoleBinding limits the grant to `example-apps`.
For directly submitted CertificateRequests, bind the actual requesting identity
instead. Authorization uses the request's recorded `spec.username`, `groups`,
`uid`, and `extra`, not the human who authored a parent Certificate. Inspect
these fields when troubleshooting; cert-manager manages them, and users must
not set or alter them.

From the repository root, apply the policy and binding and wait for readiness:

```sh
oc apply -f config/samples/tech-preview/policy.cert-manager.io_v1alpha1_certificaterequestpolicy.yaml
oc apply -f example-policy-use.yaml
oc wait --for=condition=Ready certificaterequestpolicies.policy.cert-manager.io/example-policy --timeout=300s
```

API acceptance of the YAML alone does not prove that the operand has validated
and reconciled the policy. Check `Ready=True`, the request's identity and issuer,
and the operand's signer permissions before relying on approval.

### Understanding request outcomes

An eligible policy matches the issuer and namespace selectors, is authorized
for the requestor through `use`, and reports `Ready=True`.

| Policy evaluation | Outcome |
|---|---|
| At least one eligible policy permits the request | Approved; another policy's rejection does not override that permission. |
| All eligible policies reject, with no matching policy still awaiting its first readiness result | Denied. |
| No eligible policy, or denial deferred while a matching policy has no readiness result yet | No approval decision; the request remains pending. |

These outcomes assume the operand can write the decision and no other approver
acts on the request. An evaluation error or denied status write is an error to
investigate, not a successful policy denial. Inspect request conditions and
events along with policy readiness:

```sh
oc get certificaterequests.cert-manager.io -n example-apps -o yaml
oc get certificaterequestpolicies.policy.cert-manager.io example-policy -o yaml
oc get events -n example-apps --field-selector involvedObject.kind=CertificateRequest
```

Once a request is approved or denied, approver-policy does not re-evaluate that
same request when policies change. A new issuance attempt needs a new
CertificateRequest. For a managed Certificate, its controller may create that
new request as part of retry or renewal; changing a policy does not reverse an
existing decision. Review all applicable policies and bindings: a broad policy
can permit a request that a more restrictive policy rejects. This behavior is
implemented by the shipped [policy evaluator](https://github.com/cert-manager/approver-policy/blob/v0.27.0/pkg/internal/approver/manager/review.go).

## Trust-manager webhook certificates

When TrustManager is enabled, the operator can manage a narrow approval policy
for its webhook certificate. The [TrustManager sample](../config/samples/tech-preview/operator.openshift.io_v1alpha1_trustmanager.yaml)
sets this integration to `Managed`, which is also the default when omitted:

```yaml
spec:
  trustManagerConfig:
    approverPolicy:
      managementState: Managed
```

| Configuration and handoff status | Integration behavior |
|---|---|
| `Managed`, `autoApproverDisabled=true` | Reconcile `trust-manager-policy` and its policy-use ClusterRole and ClusterRoleBinding. |
| `Managed`, completion false or absent | Remove only this TrustManager's managed integration resources. |
| `Managed`, completion cannot be read | Preserve integration resources and report the error in TrustManager status. |
| `Unmanaged` | Preserve existing integration resources; do not read completion, reconcile those resources, or react to integration events. |

The policy selects requests in `cert-manager` for the `trust-manager` Issuer
(`cert-manager.io`, kind `Issuer`). It requires common name and DNS name
`trust-manager.cert-manager.svc` and permits the webhook certificate's default
`digital signature` and `key encipherment` usages. This identity stays in
`cert-manager` even when `trustNamespace` is configured differently.

`trust-manager-policy-role` grants `use` of only `trust-manager-policy`.
`trust-manager-policy-binding` grants that role to service account
`cert-manager` in namespace `cert-manager`, which creates the webhook
CertificateRequests. It does not grant policy use to all users. The operator
refuses to adopt user-created resources with these reserved names; resolve the
name conflict or select `Unmanaged` and manage the integration yourself.

If you restrict `approveSignerNames`, include
`issuers.cert-manager.io/cert-manager.trust-manager` alongside your workload
signers. For example, extend the earlier `app-ca` configuration to:

```yaml
spec:
  approverPolicyConfig:
    approveSignerNames:
      - issuers.cert-manager.io/example-apps.app-ca
      - issuers.cert-manager.io/cert-manager.trust-manager
```

The operator does not expand your signer list automatically. A ready policy and
its `use` binding are insufficient if the operand cannot approve that signer.
Review other policies and bindings too: an overlapping policy that permits a
request can override another policy's rejection as described above.

TrustManager and ApproverPolicyManager may be installed in either order. The
integration responds to handoff completion and creates the policy before
reconciling the webhook Certificate; it does not wait for that Certificate to
become ready first. Initial issuance and renewal can remain pending during
handoff and until policy readiness, authorization, and signer permissions
converge. Check the existing handoff conditions and these resources:

```sh
oc get trustmanagers.operator.openshift.io cluster -o yaml
oc get certificaterequestpolicies.policy.cert-manager.io trust-manager-policy -o yaml
oc get clusterrole trust-manager-policy-role -o yaml
oc get clusterrolebinding trust-manager-policy-binding -o yaml
oc get certificates.cert-manager.io trust-manager -n cert-manager -o yaml
oc get certificaterequests.cert-manager.io -n cert-manager -o yaml
```

To take over management, set
`spec.trustManagerConfig.approverPolicy.managementState` to `Unmanaged`.
This leaves existing resources in place, including any permissions they grant;
it does not disable approval or remove a policy. You are then responsible for
the policies and bindings needed for webhook certificate issuance and renewal.
Setting it back to `Managed` reconciles the current completion value: true
ensures the resources, while false or absent removes only resources owned by
that TrustManager. Other trust-manager settings continue to reconcile in both
modes.

Deleting TrustManager retains its resources under the existing manual-cleanup
lifecycle. A recreated TrustManager does not take ownership of the previous
instance's integration resources automatically. Inspect retained resources and
choose explicit manual management or cleanup before re-enabling managed
integration. These rules do not change user policy ownership or trust-manager
SecretTargets permissions.

## Removing approver-policy

Keep the operator running and the `ApproverPolicyManager` feature gate enabled
until removal and default-approval restoration finish. Disabling the gate or
uninstalling the operator first prevents its cleanup finalizer from progressing.
If policy enforcement must remain continuous, arrange the maintenance window
described in [Existing policies and reinstallation](#existing-policies-and-reinstallation)
before starting removal, including handling already-pending requests.

Delete the manager and wait for its removal:

```sh
oc delete approverpolicymanagers.operator.openshift.io cluster --wait=false
oc wait --for=delete approverpolicymanagers.operator.openshift.io/cluster --timeout=300s
```

The `operator.openshift.io/approver-policy-cleanup` finalizer first removes the
owned Deployment using foreground deletion and waits for its blocking workload
dependents. It then removes the owned admission webhook configuration, services,
TLS Secret, service account and operand RBAC. The manager remains present until
the operator confirms that this inventory has gone. Objects with a different
owner are preserved, even if they reuse a managed resource name.

After the manager is gone, the CertManager controller restores default-approver
RBAC and its intended Deployment configuration. Wait for this second transition
as well. The following check requires `jq`; repeat it until it exits successfully,
and investigate status messages if it does not converge:

```sh
oc get certmanagers.operator.openshift.io cluster -o json | jq -e '
  (.status.autoApproverDisabled // false) == false and
  ([.status.conditions[]? | select(.type == "AutoApproverDisableRequested" and .status == "True")] | length) == 0 and
  ([.status.conditions[]? | select(.type == "AutoApproverProgressing" and .status == "False")] | length) == 1 and
  ([.status.conditions[]? | select(.type == "AutoApproverDegraded" and .status == "False")] | length) == 1'
oc rollout status deployment/cert-manager -n cert-manager --timeout=300s
```

The false completion value can be omitted from JSON. Inspect current controller
overrides too: restoration preserves your chosen `--controllers` selection, so
an explicit exclusion of `certificaterequests-approver` still disables default
approval. A missing completion field alone does not prove successful restoration.

If deletion is stuck, inspect the manager's `metadata.deletionTimestamp`,
`metadata.finalizers`, status reason/message and remaining operand resources.
The operator retains the finalizer and retries read, deletion and finalizer-write
failures, including after a restart. Resolve the reported permissions, resource
finalizers or workload termination problem. Do not force-remove the manager's
cleanup finalizer or recreate default-approver RBAC as a shortcut: that can
restore default approval before the policy controller has stopped.

User-created policies, the policy CRD, the `cert-manager` namespace and unrelated
operands are retained. Once default approval is restored, a `Managed`
TrustManager removes only its own integration policy and policy-use RBAC in
response to completion becoming false/absent. `Unmanaged` preserves these
resources. This does not change TrustManager's separate manual-cleanup lifecycle
when its own CR is deleted.

## Existing policies and reinstallation

The removal procedure preserves user-created
`CertificateRequestPolicy` resources and restores the built-in approver after
operand cleanup and confirmed manager removal.
Existing policies do not constrain the built-in approver.
Policies can therefore already exist when you reinstall approver-policy. They
can also be created by another administrator or automation during installation.

If an applicable policy is present when approver-policy starts, both approvers
can act on a request before the operator finishes disabling the built-in
approver. The built-in approver might approve a request that the policy would
reject. **Continuous policy enforcement is not guaranteed during this
transition.** Upstream also documents the [risk of running both approvers](https://cert-manager.io/docs/policy/approval/approver-policy/installation/).

If requests must remain subject to policy throughout a reinstallation, arrange a
maintenance window before deleting or recreating the `ApproverPolicyManager`.
Prevent certificate request creation, including automated renewals and direct
`CertificateRequest` submissions, and account for already-pending requests that
the built-in approver could approve. Pausing new submissions alone does not
protect requests that already exist. Do not perform the transition with live or
pending requests if your environment cannot tolerate default approval.

Wait for the operand to be ready and for `.status.autoApproverDisabled=true`
with `AutoApproverDegraded=False` and `AutoApproverProgressing=False` before
resuming request creation. Verify that the retained policies and their
RBAC bindings are suitable for those requests. Creating or restoring a policy
does not retroactively validate certificates already issued during default
approval.

This limitation describes installations and reinstallations in which the
built-in approver is active. A transient approver-policy pod restart after the
handoff does not re-enable it while the `ApproverPolicyManager` remains present.

## Handoff status and recovery

Inspect both resources when a wait command times out:

```sh
oc get approverpolicymanagers.operator.openshift.io cluster -o yaml
oc get certmanagers.operator.openshift.io cluster -o yaml
oc get events -n cert-manager-operator --field-selector involvedObject.kind=CertManager,involvedObject.name=cluster
```

| Signal | Meaning |
|---|---|
| Manager `Ready=True` | The approver-policy operand is ready; handoff may still be pending. |
| CertManager `AutoApproverDisableRequested=True` | Disable intent is recorded and retained across operator restarts and later operand readiness failures. |
| CertManager `AutoApproverProgressing=True`, reason `RolloutPending` | The intended cert-manager rollout or old-pod termination is not yet confirmed. |
| CertManager `AutoApproverDegraded=True` | A handoff step failed. Read the reason/message and correct the reported cause. |
| `autoApproverDisabled=true` | Initial handoff completed. This value remains true while the manager exists; current conditions report subsequent drift or failures. |
| Event `AutoApproverDisabled` / `AutoApproverEnabled` | The operator recorded completion of disablement / restoration. Use current status for recovery decisions. |

The operator retries incomplete transitions. Do not recreate the removed default
approver ClusterRole or ClusterRoleBinding to clear a handoff error. Readiness
loss, a deleting manager that is still present, and failed or uncertain API reads
do not permit restoration. Only a confirmed absence of the manager permits it;
the operator clears disable intent and completion after the desired default
RBAC and cert-manager configuration have converged. User controller overrides
still apply, so a false completion value alone does not prove active default
approval. Keep the feature gate enabled through supported removal; switching it
off is not an uninstall procedure.

### Conflicting controller overrides

While disable intent is recorded or completion is latched,
`spec.unsupportedConfigOverrides.controller.args` must not enable
`certificaterequests-approver`. For example, `--controllers=*` conflicts with
handoff. The operator blocks that Deployment update, keeps default approval
permissions removed, and reports `AutoApproverDegraded=True` with reason
`ControllerOverrideConflict`. Initial completion remains false or absent; an
already true value stays latched.

Remove the conflicting controller override or change its selection to exclude
the built-in approver, for example
`--controllers=*,-certificaterequests-approver`. Preserve any other intended
controller selections when editing the list. The operator does not silently
rewrite a conflicting override. Compatible selections and unrelated overrides,
including TLS arguments, retain their existing behavior.

After correcting the override, repeat the readiness, completion, and condition
checks above. Reconciliation resumes automatically; there is no need to delete
the manager or manually change its status.

## Troubleshooting pending and denied requests

Start with the current manager and CertManager status, then inspect the request.
The manager's `.status.approverPolicyImage` is the image last observed in its
Deployment. Compare it with the desired Deployment image and pod state when
investigating an image pull, scheduling or rollout problem.

| Observation | Next checks |
|---|---|
| Manager `Ready=False`, reason `Progressing`, `Degraded=False` | Read the Ready message for a missing namespace, rollout, webhook TLS or cleanup wait; inspect the named resource and pod events. |
| Manager `Ready=False`, reason `Failed`, `Degraded=True` | Read the Degraded message for invalid configuration, permissions or ownership conflicts. Correct the cause; installation errors of this class wait for a relevant change, while finalizer cleanup retries. |
| Manager `Ready=True` but handoff is incomplete | Follow [Handoff status and recovery](#handoff-status-and-recovery). Read the CertManager conditions; manager readiness alone does not establish policy enforcement. |
| Request has neither `Approved=True` nor `Denied=True` | Check policy readiness, both selectors, request identity and `use` authorization, signer permission, and operand logs. Missing eligibility leaves a request pending; API or decision-write errors can also prevent a decision. |
| Request has `Denied=True` | Read its condition reason/message and events. Compare requested names, usages, duration and key against every eligible policy, including required fields and CEL constraints. |
| Request has `Approved=True` but no certificate | Inspect issuer readiness and issuance errors. Approval alone does not guarantee successful signing. |

Use a request name from the affected namespace:

```sh
REQUEST_NAMESPACE=example-apps
REQUEST_NAME=example-request
oc get certificaterequests.cert-manager.io "$REQUEST_NAME" -n "$REQUEST_NAMESPACE" -o yaml
oc get events -n "$REQUEST_NAMESPACE" --field-selector "involvedObject.kind=CertificateRequest,involvedObject.name=$REQUEST_NAME"
oc get certificaterequestpolicies.policy.cert-manager.io -o yaml
oc get deployment cert-manager-approver-policy -n cert-manager -o yaml
oc get pods -n cert-manager -l app=cert-manager-approver-policy
```

Policy selection combines the issuer reference with the request namespace. A
policy must report `Ready=True`, and the request's recorded identity must be
allowed to `use` that policy in the request namespace. To reproduce that check,
an administrator authorized to create SubjectAccessReviews can run the following.
It copies the request's recorded user, groups, UID and extra attributes, rather
than substituting the administrator's identity:

```sh
POLICY_NAME=example-policy
oc get certificaterequests.cert-manager.io "$REQUEST_NAME" -n "$REQUEST_NAMESPACE" -o json |
  jq --arg policy "$POLICY_NAME" '{
    apiVersion: "authorization.k8s.io/v1", kind: "SubjectAccessReview",
    spec: {
      user: .spec.username, groups: (.spec.groups // []),
      uid: (.spec.uid // ""), extra: (.spec.extra // {}),
      resourceAttributes: {
        group: "policy.cert-manager.io", resource: "certificaterequestpolicies",
        name: $policy, namespace: .metadata.namespace, verb: "use"
      }
    }
  }' | oc create -f - -o yaml
```

Inspect `status.allowed`, `status.reason` and `status.evaluationError`. A successful
`use` check does not establish signer approval authority; check
`spec.approverPolicyConfig.approveSignerNames` and the operand's ClusterRole
separately. See [Restricting signer approval permissions](#restricting-signer-approval-permissions).

After correcting a denial, start a new issuance attempt through the owning
Certificate/controller or submit a new directly managed CertificateRequest with
a new name. Let cert-manager populate its identity fields. Verify the new
request's conditions and events; changing policy content does not reverse the
old request's terminal decision. Retain the old request's diagnostic evidence
while investigating.

## Logs and metrics

The supported logging settings are `spec.approverPolicyConfig.logLevel` (1–5,
default 1) and `logFormat` (`text` or `json`, default `text`). Change the manager
configuration so the operator reconciles these settings. For example:

```sh
oc patch approverpolicymanagers.operator.openshift.io cluster --type=merge \
  -p '{"spec":{"approverPolicyConfig":{"logLevel":3,"logFormat":"json"}}}'
oc rollout status deployment/cert-manager-approver-policy -n cert-manager --timeout=300s
oc logs deployment/cert-manager-approver-policy -n cert-manager -c cert-manager-approver-policy --since=10m
```

Correlate log entries with request namespace/name, policy name, and status/events.
Restore your usual log settings after diagnosis. For operator-side reconciliation
failures, inspect the operator pod logs in `cert-manager-operator` as well.

The operand exposes HTTP Prometheus metrics at `/metrics` on port `9402` through
Service `cert-manager-approver-policy-metrics` in `cert-manager`; its Service port
is named `metrics`. To inspect the endpoint locally, run:

```sh
oc port-forward -n cert-manager service/cert-manager-approver-policy-metrics 9402:9402
```

Then, in another terminal:

```sh
curl --fail --silent --show-error http://127.0.0.1:9402/metrics
```

The shipped v0.27.0 operand reports
`certmanager_approverpolicy_certificaterequests_approval`, a gauge labeled by
`namespace` and `status` (`approved`, `denied`, `unmatched`). It counts the
current CertificateRequest conditions, not historical decisions or certificates
issued. `unmatched` means neither approval nor denial is present; it is not
proof that no policy matches. The collector runs on the elected leader, and
requests removed from the API no longer contribute to these counts. See the
[pinned metric implementation](https://github.com/cert-manager/approver-policy/blob/v0.27.0/pkg/internal/metrics/metrics.go).

Configure scraping through your platform's monitoring configuration using this
Service and its `metrics` port. The [operand monitoring guide](operand_metrics.md)
describes the existing monitoring setup; its cert-manager selector must be
adapted for this separate Service. Installing ApproverPolicyManager does not
install a ServiceMonitor or an automated approval-transition alert. Use the
existing completion status and events for handoff diagnostics.
