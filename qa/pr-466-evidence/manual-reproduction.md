# Manual reproduction appendix

These instructions reproduce **F1 (five assertions about operator TLS policy adoption)** and **F2 (HTTP monitoring compatibility)** without invoking the QA Python drivers. The commands translate the recorded Python TLS probes into OpenSSL CLI probes; the **actual** results below come from the saved live run, not from a new execution of this appendix.

Run the blocks in order, in **one Bash session from the repository root**. If your shell is zsh, run `bash` first, before pasting the blocks below. Keep that session open so its variables and background processes remain available. Run F2 before changing TLS policy, then run the four F1 profile cases. Each F1 case can also be tested independently by starting a new baseline operator first.

Proceed only after setup/API commands succeed and the stated readiness checks pass. A deliberately rejected TLS probe is the exception; its alert is part of the expected test output.

### 1. Prerequisites and baseline operator

- An isolated OpenShift test cluster with `APIServer.spec.tlsAdherence` support and cluster-admin access. These tests change cluster-wide TLS policy; the recorded run experienced API timeouts during rollout.
- PR commit `b116f756e5333645814aeabfc0569933111bc5be`, or record the different commit being cross-checked.
- Operator CRDs, namespace and RBAC already installed, as in the tested development setup. See the repository [development setup](https://github.com/openshift/cert-manager-operator/blob/b116f756e5333645814aeabfc0569933111bc5be/harness-evals/harness-docs/CERT_MANAGER_OPERATOR_DEVELOPMENT.md) if starting from an unprepared cluster.
- Bash, `oc`, `jq`, `curl`, Go/Make for the local build, and **OpenSSL 3 with TLS 1.0–1.3 client support**. On macOS, select an OpenSSL 3 binary instead of the system LibreSSL binary.
- Stop any earlier local operator before starting this controlled baseline. Do not start another process over an occupied port 8443. Ports 8443, 28443, 19402–19404, 19443–19444 and 19091 must be available for this session.

Set your own kubeconfig path and OpenSSL executable. The kubeconfig is an input only; do not copy its contents into the evidence directory.

```bash
export KUBECONFIG=/absolute/path/to/new-cluster.kubeconfig
export OPENSSL=openssl
# macOS example, if needed:
# export OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl

mkdir -p qa
export RUN_DIR="$(mktemp -d "$PWD/qa/pr466-manual.XXXXXX")"
set -o pipefail
# Do not enable "set -e": some TLS probes intentionally fail.

git rev-parse HEAD | tee "$RUN_DIR/git-head.txt"
git diff --binary > "$RUN_DIR/local-changes.patch"
"$OPENSSL" version | tee "$RUN_DIR/openssl-version.txt"
oc whoami
oc get clusterversion version -o json > "$RUN_DIR/cluster-version.json"
oc get apiserver cluster -o json > "$RUN_DIR/apiserver-original.json"
oc -n cert-manager-operator get deployment cert-manager-operator-controller-manager \
  -o json > "$RUN_DIR/operator-deployment-original.json"
oc get clusteroperators
oc explain apiserver.spec.tlsAdherence
```

Expected: API reads work, the cluster is healthy, and the API supports `StrictAllComponents`. Resolve baseline availability problems before using TLS results to judge the feature.

Scale the installed operator down for the local run. Save its original replica count above so it can be restored later. Prepare a baseline with no explicit profile and Legacy adherence, then build and launch the PR:

```bash
oc -n cert-manager-operator scale deployment/cert-manager-operator-controller-manager --replicas=0
oc -n cert-manager-operator rollout status deployment/cert-manager-operator-controller-manager --timeout=180s
oc patch apiserver cluster --type=merge \
  -p '{"spec":{"tlsAdherence":"LegacyAdheringComponentsOnly","tlsSecurityProfile":null}}'

make build-operator

export RELATED_IMAGE_CERT_MANAGER_CONTROLLER=quay.io/jetstack/cert-manager-controller:v1.20.3
export RELATED_IMAGE_CERT_MANAGER_WEBHOOK=quay.io/jetstack/cert-manager-webhook:v1.20.3
export RELATED_IMAGE_CERT_MANAGER_CA_INJECTOR=quay.io/jetstack/cert-manager-cainjector:v1.20.3
export RELATED_IMAGE_CERT_MANAGER_ACMESOLVER=quay.io/jetstack/cert-manager-acmesolver:v1.20.3
export RELATED_IMAGE_CERT_MANAGER_ISTIOCSR=quay.io/jetstack/cert-manager-istio-csr:v0.16.0
export RELATED_IMAGE_CERT_MANAGER_TRUST_MANAGER=quay.io/jetstack/trust-manager:v0.20.3
export OPERATOR_NAME=cert-manager-operator
export OPERATOR_IMAGE_VERSION=1.20.0
export OPERAND_IMAGE_VERSION=1.20.0
export ISTIOCSR_OPERAND_IMAGE_VERSION=v0.16.0
export TRUSTMANAGER_OPERAND_IMAGE_VERSION=v0.20.3

if [[ -z "$(oc get certmanager cluster --ignore-not-found -o name)" ]]; then
  oc apply -f config/samples/operator.openshift.io_v1alpha1_certmanager.yaml
fi

./cert-manager-operator start \
  --config=./hack/local-run-config.yaml \
  --kubeconfig="$KUBECONFIG" --namespace=cert-manager-operator \
  --unsupported-addon-features=TrustManager=true \
  --listen=127.0.0.1:8443 > "$RUN_DIR/operator-baseline.log" 2>&1 &
LEADER_PID=$!
printf '%s\n' "$LEADER_PID" > "$RUN_DIR/operator-baseline.pid"

if [[ -z "$(oc get trustmanager cluster --ignore-not-found -o name)" ]]; then
  oc apply -f - <<'YAML'
apiVersion: operator.openshift.io/v1alpha1
kind: TrustManager
metadata:
  name: cluster
spec:
  trustManagerConfig: {}
YAML
fi

tail -n 30 "$RUN_DIR/operator-baseline.log"
oc -n cert-manager-operator get lease cert-manager-operator-lock -o json
oc -n cert-manager get deployments,pods
```

Allow startup to finish. Expected: this local process acquires the operator lease, all four operands appear and become ready, and no other operator takes leadership. Re-run the last three commands until that is true. Existing CertManager/TrustManager CRs should already use the normal managed configuration; the commands intentionally preserve their specs.

Define the following helpers once. `wait_operands` requires the desired TLS arguments **and** completed rollouts; a standalone `oc rollout status` can otherwise report success for the previous generation. The checks reflect the recorded one-replica-per-operand setup.

```bash
OPERANDS=(cert-manager cert-manager-cainjector cert-manager-webhook trust-manager)
FORWARD_PIDS=()
FOLLOWER_PID=
CASE=baseline

wait_operands() {
  local minimum="$1" attempt
  for attempt in {1..60}; do
    if oc --request-timeout=15s -n cert-manager get deployment "${OPERANDS[@]}" \
      -o json > "$RUN_DIR/$CASE-deployments.json"; then
      if jq -e --arg minimum "$minimum" '
        (.items | length == 4) and all(.items[];
          . as $d |
          .spec.template.spec.containers[0].args as $args |
          (if .metadata.name == "trust-manager" then ["--tls"]
           elif .metadata.name == "cert-manager-webhook" then ["--tls", "--metrics-tls"]
           else ["--metrics-tls"] end) as $prefixes |
          (.status.observedGeneration >= .metadata.generation) and
          (.status.replicas == 1) and (.status.updatedReplicas == 1) and
          (.status.readyReplicas == 1) and
          all($prefixes[]; . as $prefix |
            if $minimum == "baseline" then
              all($args[]; (startswith($prefix + "-min-version=") or
                            startswith($prefix + "-cipher-suites=")) | not)
            else
              (($args | index($prefix + "-min-version=" + $minimum)) != null) and
              (if $minimum == "VersionTLS13" then
                 all($args[]; startswith($prefix + "-cipher-suites=") | not)
               else any($args[]; startswith($prefix + "-cipher-suites=")) end)
            end)
        )' "$RUN_DIR/$CASE-deployments.json" > /dev/null; then
        return 0
      fi
    fi
    sleep 5
  done
  printf 'INCONCLUSIVE: API reads, desired arguments or rollout did not converge.\n'
  return 1
}

tls_probe() {
  local label="$1" port="$2" version="$3" suites="${4:-ALL}"
  "$OPENSSL" s_client -brief -connect "127.0.0.1:$port" \
    -servername localhost "$version" -cipher "$suites:@SECLEVEL=0" \
    < /dev/null 2>&1 | tee "$RUN_DIR/$CASE-$label-$port.log"
}

operator_fingerprint() {
  "$OPENSSL" s_client -connect 127.0.0.1:8443 -servername localhost \
    -tls1_3 -showcerts < /dev/null 2>/dev/null |
    "$OPENSSL" x509 -noout -fingerprint -sha256
}

verify_original() {
  kill -0 "$LEADER_PID" || return 1
  operator_fingerprint > "$RUN_DIR/$CASE-fingerprint-final.txt" || return 1
  cmp "$RUN_DIR/baseline-fingerprint.txt" "$RUN_DIR/$CASE-fingerprint-final.txt" || return 1
  oc -n cert-manager-operator get lease cert-manager-operator-lock -o json > "$RUN_DIR/$CASE-lease-final.json" || return 1
  jq -e --arg holder "$CASE_LEADER_HOLDER" '.spec.holderIdentity == $holder' "$RUN_DIR/$CASE-lease-final.json" || return 1
  jq '.spec | {holderIdentity, renewTime}' "$RUN_DIR/$CASE-lease-final.json"
  tail -n 30 "$RUN_DIR/operator-baseline.log"
}

stop_controls() {
  local pid
  for pid in ${FOLLOWER_PID:+"$FOLLOWER_PID"} "${FORWARD_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  FOLLOWER_PID=
  FORWARD_PIDS=()
}

start_controls() {
  local mapping deployment before after attempt port
  kill -0 "$LEADER_PID" || return 1
  before="$(oc -n cert-manager-operator get lease cert-manager-operator-lock \
    -o jsonpath='{.spec.holderIdentity}')" || return 1
  [[ -n "$before" ]] || return 1
  CASE_LEADER_HOLDER="$before"
  ./cert-manager-operator start \
    --config=./hack/local-run-config.yaml \
    --kubeconfig="$KUBECONFIG" --namespace=cert-manager-operator \
    --listen=127.0.0.1:28443 --v=2 > "$RUN_DIR/$CASE-follower.log" 2>&1 &
  FOLLOWER_PID=$!

  for mapping in cert-manager:19402:9402 cert-manager-cainjector:19403:9402 \
    cert-manager-webhook:19404:9402 cert-manager-webhook:19443:10250 \
    trust-manager:19444:6443; do
    deployment="${mapping%%:*}"
    oc -n cert-manager port-forward "deployment/$deployment" "${mapping#*:}" \
      > "$RUN_DIR/$CASE-forward-${mapping//:/-}.log" 2>&1 &
    FORWARD_PIDS+=("$!")
  done
  for attempt in {1..30}; do
    if "$OPENSSL" s_client -connect 127.0.0.1:28443 -tls1_3 \
      < /dev/null > /dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  after="$(oc -n cert-manager-operator get lease cert-manager-operator-lock \
    -o jsonpath='{.spec.holderIdentity}')" || return 1
  printf 'Leader before=%s\nLeader after=%s\n' "$before" "$after" \
    | tee "$RUN_DIR/$CASE-leader-comparison.txt"
  [[ "$before" == "$after" ]] || return 1
  tls_probe existing-positive 8443 -tls1_3 || return 1
  tls_probe fresh-positive 28443 -tls1_3 || return 1
  for port in 19402 19403 19404 19443 19444; do
    tls_probe operand-positive "$port" -tls1_3 || return 1
  done
}

prepare_case() {
  CASE="$1"
  local minimum="$2" profile="$3"
  stop_controls
  kill -0 "$LEADER_PID" || return 1
  operator_fingerprint > "$RUN_DIR/$CASE-fingerprint-before.txt" || return 1
  cmp "$RUN_DIR/baseline-fingerprint.txt" "$RUN_DIR/$CASE-fingerprint-before.txt" || return 1
  jq -n --argjson profile "$profile" '[
    {"op":"add","path":"/spec/tlsAdherence","value":"StrictAllComponents"},
    {"op":"add","path":"/spec/tlsSecurityProfile","value":$profile}
  ]' > "$RUN_DIR/$CASE-patch.json"
  oc patch apiserver cluster --type=json --patch-file="$RUN_DIR/$CASE-patch.json" || return 1
  oc get apiserver cluster -o json > "$RUN_DIR/$CASE-apiserver.json" || return 1
  wait_operands "$minimum" || return 1
  operator_fingerprint > "$RUN_DIR/$CASE-fingerprint-after.txt" || return 1
  cmp "$RUN_DIR/baseline-fingerprint.txt" "$RUN_DIR/$CASE-fingerprint-after.txt" || return 1
  start_controls
}

wait_operands baseline
operator_fingerprint | tee "$RUN_DIR/baseline-fingerprint.txt"
start_controls
tls_probe baseline-tls12 8443 -tls1_2
tls_probe baseline-tls11 8443 -tls1_1
tls_probe baseline-tls10 8443 -tls1
```

**Baseline expected and recorded:** operator TLS 1.2/1.3 succeed; TLS 1.0/1.1 receive protocol-version alerts. Stop and investigate if baseline setup fails. The fresh process on 28443 is a follower using the same leader lock; it is only a startup-policy control.

**Interpretation of OpenSSL output:** success includes the negotiated protocol and cipher (for example, `Protocol version: TLSv1.2`). A policy rejection requires a peer TLS alert such as `alert protocol version` or `alert handshake failure`. Connection refused, EOF, timeout, no listener, or a client-side “no protocols/ciphers available” error is **INCONCLUSIVE**, not proof of a TLS-policy rejection. `@SECLEVEL=0` affects only the test client and lets it offer the old protocols/ciphers. These protocol-only probes allow the local self-signed certificate; F2's HTTPS controls below verify the CA and DNS identity.

### 2. Reproduce F2 — HTTP monitoring fails, verified HTTPS works

Do this while the cluster is still at baseline. The three cert-manager metrics listeners already use HTTPS even without an explicit TLS profile.

#### 2a. Direct HTTP/HTTPS comparison

The baseline helpers have opened the operand port-forwards. Export only the public metrics CA certificate, then probe all three endpoints:

```bash
oc -n cert-manager get secret cert-manager-metrics-ca \
  -o jsonpath='{.data.tls\.crt}' |
  "$OPENSSL" base64 -d -A > "$RUN_DIR/metrics-ca.crt"

for mapping in cert-manager:19402 cert-manager-cainjector:19403 cert-manager-webhook:19404; do
  service="${mapping%:*}"
  port="${mapping##*:}"
  curl --noproxy '*' --max-time 10 -sS -i \
    "http://127.0.0.1:$port/metrics" |
    tee "$RUN_DIR/http-$service.txt"
  curl --noproxy '*' --max-time 10 -sS --fail \
    --cacert "$RUN_DIR/metrics-ca.crt" \
    --resolve "$service.cert-manager.svc:$port:127.0.0.1" \
    -D "$RUN_DIR/https-$service-headers.txt" \
    -o "$RUN_DIR/https-$service-metrics.txt" \
    "https://$service.cert-manager.svc:$port/metrics"
  head -n 1 "$RUN_DIR/https-$service-headers.txt"
  head -n 5 "$RUN_DIR/https-$service-metrics.txt"
done
```

| Check | Expected behavior being checked | Recorded actual behavior |
|---|---|---|
| Existing/documented HTTP metrics access | Existing HTTP scrape configuration continues to collect metrics, or documentation supplies the required migration | All three return **HTTP 400**, with `Client sent an HTTP request to an HTTPS server.` |
| HTTPS with CA and matching Service DNS identity | HTTP 200 and Prometheus metrics | **HTTP 200**, Prometheus text, successful CA/DNS verification |

The TLS handshake probe's self-signed certificate allowance does not apply here: the HTTPS control uses `--cacert` and never uses `-k`.

#### 2b. Demonstrate the failure in real Prometheus targets

Save the monitoring configuration before enabling user-workload monitoring:

```bash
oc -n openshift-monitoring get configmap cluster-monitoring-config \
  --ignore-not-found -o json > "$RUN_DIR/monitoring-original.json"
if [[ ! -s "$RUN_DIR/monitoring-original.json" ]]; then
  oc -n openshift-monitoring create configmap cluster-monitoring-config \
    --from-literal=config.yaml=''
fi
oc -n openshift-monitoring edit configmap cluster-monitoring-config
```

In the existing `data.config.yaml` document, set the **top-level** key `enableUserWorkload: true`, preserving every other setting. Do not add a duplicate key if it already exists. Save and exit the editor, then:

```bash
oc -n openshift-monitoring get configmap cluster-monitoring-config \
  -o json > "$RUN_DIR/monitoring-test-config.json"
oc -n openshift-user-workload-monitoring get pods
oc -n openshift-user-workload-monitoring wait pod \
  -l app.kubernetes.io/name=prometheus --for=condition=Ready --timeout=480s

PROM_POD="$(oc -n openshift-user-workload-monitoring get pods \
  -l app.kubernetes.io/name=prometheus -o json |
  jq -r '[.items[] | select(any(.status.conditions[]?;
    .type == "Ready" and .status == "True"))][0].metadata.name // empty')"
printf 'Prometheus pod: %s\n' "$PROM_POD"
oc -n openshift-user-workload-monitoring port-forward \
  "pod/$PROM_POD" 19091:9090 > "$RUN_DIR/prometheus-forward.log" 2>&1 &
PROM_FORWARD_PID=$!

oc apply -f - <<'YAML'
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: pr466-manual-http
  namespace: cert-manager
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: cert-manager
    matchExpressions:
      - key: app.kubernetes.io/component
        operator: In
        values: [controller, webhook, cainjector]
  endpoints:
    - honorLabels: false
      interval: 15s
      path: /metrics
      scrapeTimeout: 10s
      targetPort: 9402
YAML

read_targets() {
  curl --noproxy '*' --max-time 10 --fail -sS http://127.0.0.1:19091/api/v1/targets |
    jq '[.data.activeTargets[] |
      select(.scrapePool | startswith("serviceMonitor/cert-manager/pr466-manual-")) |
      {scrapePool, scrapeUrl, health, lastError}]'
}
read_targets | tee "$RUN_DIR/http-targets.json"
```

If Prometheus pods have not been created when `oc wait` runs, repeat the get/wait commands before selecting `PROM_POD`. It must be nonempty. Wait for the port-forward to report `Forwarding from` before querying it.

The HTTP monitor selects the same three components as the documentation, with a distinct test name and a 15-second interval for quicker observation. It deliberately omits `scheme` and `tlsConfig`, matching the documentation's HTTP behavior.

Repeat the last `read_targets` command until all three targets have been discovered and scraped; allow up to 180 seconds. **Recorded actual:** three `http://...:9402/metrics` targets, each with `health: "down"` and `lastError: "server returned HTTP status 400 Bad Request"`. Zero targets, RBAC errors, TLS errors from some other monitor, or connection timeouts do not reproduce this finding.

#### 2c. Positive control using verified HTTPS

Remove the HTTP monitor and create a separate HTTPS monitor for each Service identity:

```bash
oc -n cert-manager delete servicemonitor pr466-manual-http
for component in controller webhook cainjector; do
  case "$component" in
    controller) service=cert-manager ;;
    webhook) service=cert-manager-webhook ;;
    cainjector) service=cert-manager-cainjector ;;
  esac
  jq -n --arg component "$component" --arg service "$service" '{
    apiVersion:"monitoring.coreos.com/v1", kind:"ServiceMonitor",
    metadata:{name:("pr466-manual-https-" + $component), namespace:"cert-manager"},
    spec:{
      selector:{matchLabels:{
        "app.kubernetes.io/instance":"cert-manager",
        "app.kubernetes.io/component":$component}},
      endpoints:[{
        honorLabels:false, interval:"15s", path:"/metrics",
        scrapeTimeout:"10s", targetPort:9402, scheme:"https",
        tlsConfig:{
          ca:{secret:{name:"cert-manager-metrics-ca",key:"tls.crt"}},
          serverName:($service + ".cert-manager.svc")}
      }]
    }
  }' | oc apply -f -
done
read_targets | tee "$RUN_DIR/https-targets.json"
```

Repeat the final query for up to 180 seconds, until the old HTTP target disappears and the three HTTPS targets have scraped. **Expected and recorded actual:** exactly three HTTPS targets, all `health: "up"`, all `lastError: ""`. This control shows the monitoring failure is the HTTP/HTTPS configuration mismatch.

#### 2d. Restore monitoring before the TLS tests

Delete only this manual run's monitors and stop its Prometheus forward:

```bash
oc -n cert-manager delete servicemonitor pr466-manual-http \
  pr466-manual-https-controller pr466-manual-https-webhook \
  pr466-manual-https-cainjector --ignore-not-found
kill "$PROM_FORWARD_PID"
wait "$PROM_FORWARD_PID" 2>/dev/null || true

if [[ -s "$RUN_DIR/monitoring-original.json" ]]; then
  jq -n --slurpfile before "$RUN_DIR/monitoring-original.json" \
    --slurpfile during "$RUN_DIR/monitoring-test-config.json" '
    [{"op":"test","path":"/data","value":$during[0].data}] +
    (if ($before[0] | has("data")) then
       [{"op":"add","path":"/data","value":$before[0].data}]
     else [{"op":"remove","path":"/data"}] end)' \
    > "$RUN_DIR/monitoring-restore-patch.json"
  oc -n openshift-monitoring patch configmap cluster-monitoring-config \
    --type=json --patch-file="$RUN_DIR/monitoring-restore-patch.json"
else
  oc -n openshift-monitoring delete configmap cluster-monitoring-config
fi
```

The JSON Patch `test` prevents overwriting a concurrent configuration change. If it fails, compare the saved/current data and restore only this test's `enableUserWorkload` edit. On the recorded cluster the original ConfigMap existed, and its full original data was restored.

### 3. Reproduce F1 — the baseline operator retains its startup policy

Keep `LEADER_PID` running across profile changes. Each `prepare_case` uses JSON Patch to replace the **entire** profile union, waits for operand arguments and rollouts, verifies the original listener fingerprint, and starts a **new** follower under the new policy. Reusing a follower from the preceding case would invalidate the comparison.

The port mapping is:

| Local port | Listener |
|---|---|
| 8443 | Original operator started at baseline |
| 28443 | Fresh operator follower started after this profile change |
| 19402 / 19403 / 19404 | cert-manager controller / cainjector / webhook metrics |
| 19443 / 19444 | cert-manager / trust-manager admission webhook |

If `prepare_case` fails, do not score the following probes. Inspect its saved APIServer, Deployment and listener logs first. The braces after `&&` below run only when preparation succeeds.

#### F1.1 — Strict Modern still accepts TLS 1.2 on the existing operator

```bash
prepare_case strict-modern VersionTLS13 '{"type":"Modern","modern":{}}' && {
  for attempt in 1 2; do
    for port in 8443 28443 19402 19403 19404 19443 19444; do
      tls_probe "modern-tls12-attempt$attempt" "$port" -tls1_2
    done
    tls_probe "modern-positive-attempt$attempt" 8443 -tls1_3
    sleep 3
  done
  verify_original
}
```

**Expected:** every listener rejects TLS 1.2; TLS 1.3 succeeds. **Recorded actual:** the original operator accepts TLS 1.2; the fresh operator and all five operand listeners reject it with a TLS alert. The existing operator's TLS 1.3 positive control succeeds. **FAIL**, reproduced twice. [Evidence](tls-failures.json)

#### F1.2 — Strict Custom TLS 1.2 still accepts an excluded cipher

```bash
prepare_case strict-custom12 VersionTLS12 \
  '{"type":"Custom","custom":{"minTLSVersion":"VersionTLS12","ciphers":["ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-RSA-AES128-GCM-SHA256"]}}' && {
  for attempt in 1 2; do
    for port in 8443 28443 19402 19403 19404 19443 19444; do
      tls_probe "allowed-attempt$attempt" "$port" -tls1_2 \
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
      tls_probe "excluded-attempt$attempt" "$port" -tls1_2 \
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
    done
    tls_probe "custom12-positive-attempt$attempt" 8443 -tls1_3
    sleep 3
  done
  verify_original
}
```

**Expected:** the allowed AES128-GCM offer succeeds everywhere; the excluded AES256-GCM offer receives a handshake alert everywhere. **Recorded actual:** allowed-cipher controls succeed; the original operator additionally negotiates excluded `ECDHE-RSA-AES256-GCM-SHA384`. The fresh operator and all five operands reject the excluded offer. **FAIL**, reproduced twice. [Evidence](tls-failures.json)

#### F1.3 — Strict Custom minimum TLS 1.3 still accepts TLS 1.2

```bash
prepare_case strict-custom13 VersionTLS13 \
  '{"type":"Custom","custom":{"minTLSVersion":"VersionTLS13","ciphers":[]}}' && {
  for attempt in 1 2; do
    for port in 8443 28443 19402 19403 19404 19443 19444; do
      tls_probe "custom13-tls12-attempt$attempt" "$port" -tls1_2
    done
    tls_probe "custom13-positive-attempt$attempt" 8443 -tls1_3
    sleep 3
  done
  verify_original
}
```

**Expected:** TLS 1.2 is rejected everywhere; TLS 1.3 succeeds. **Recorded actual on the valid retry:** the original baseline-started operator accepts TLS 1.2; fresh/operand controls reject it; the existing TLS 1.3 control succeeds. **FAIL**, reproduced twice. Use the empty cipher list shown above for this API-valid TLS 1.3 Custom profile. [Evidence](tls-failures.json)

#### F1.4 and F1.5 — Strict Old still rejects TLS 1.0 and TLS 1.1

```bash
prepare_case strict-old VersionTLS10 '{"type":"Old","old":{}}' && {
  for attempt in 1 2; do
    for port in 8443 28443 19402 19403 19404 19443 19444; do
      tls_probe "old-tls10-attempt$attempt" "$port" -tls1
      tls_probe "old-tls11-attempt$attempt" "$port" -tls1_1
    done
    tls_probe "old-positive-attempt$attempt" 8443 -tls1_3
    sleep 3
  done
  verify_original
}
```

**Expected:** both TLS 1.0 and TLS 1.1 are accepted everywhere under the Old profile. **Recorded actual:** the original operator rejects both with protocol-version alerts; the fresh operator and all five operands accept both. The original TLS 1.3 control succeeds. **Two FAIL assertions**, each reproduced twice. [Evidence](tls-failures.json)

#### Validity check after each case

Each case above calls `verify_original` automatically. To repeat this check manually:

```bash
verify_original
```

Expected: the baseline process remains alive, its certificate fingerprint and lease holder are unchanged, its printed lease renewal time is recent, and TLS 1.3 remains usable. Inspect this output **before starting the next case**. If the process exits or its positive control fails, record the attempt as **INTERRUPTED**. Restore baseline TLS, start a new baseline operator and re-run that case with newly recorded PID/fingerprint. Do not restart the original operator under the failing profile and call that an update test: that would test startup behavior.

### 4. Restore TLS and finish the manual session

If monitoring testing was interrupted, complete section 2d first. Stop temporary followers/forwards, then restore the saved TLS configuration while the local leader is still running. JSON Patch replaces an original nonempty profile as a whole so fields from the last test profile cannot remain behind.

```bash
stop_controls
oc get apiserver cluster -o json > "$RUN_DIR/apiserver-before-restore.json"
jq -n --slurpfile original "$RUN_DIR/apiserver-original.json" \
  --slurpfile current "$RUN_DIR/apiserver-before-restore.json" '
  [{"op":"add","path":"/spec/tlsAdherence",
    "value":($original[0].spec.tlsAdherence // "LegacyAdheringComponentsOnly")}] +
  (if ($original[0].spec | has("tlsSecurityProfile")) then
     [{"op":"add","path":"/spec/tlsSecurityProfile","value":$original[0].spec.tlsSecurityProfile}]
   elif ($current[0].spec | has("tlsSecurityProfile")) then
     [{"op":"remove","path":"/spec/tlsSecurityProfile"}]
   else [] end)' > "$RUN_DIR/apiserver-restore-patch.json"
oc patch apiserver cluster --type=json --patch-file="$RUN_DIR/apiserver-restore-patch.json"
oc get apiserver cluster -o json > "$RUN_DIR/apiserver-restored.json"
jq '.spec | {tlsAdherence,tlsSecurityProfile}' "$RUN_DIR/apiserver-restored.json"

# For the recorded original state: Legacy adherence, no explicit profile.
CASE=restored
wait_operands baseline
oc -n cert-manager get deployments,pods
oc get clusteroperators
```

If your saved original configuration had a different effective profile, use its matching minimum in `wait_operands` and inspect the saved/restored fields. An originally omitted `tlsAdherence` becomes explicit `LegacyAdheringComponentsOnly`: the OpenShift API forbids removing this field once it has been set. This is the known restoration difference from the recorded run.

The local leader and installation can stay running for further investigation, as they were left in this QA run. To end your local session and restore the installed operator's previous replica count instead:

```bash
kill "$LEADER_PID"
wait "$LEADER_PID" 2>/dev/null || true
ORIGINAL_REPLICAS="$(jq -r '.spec.replicas' "$RUN_DIR/operator-deployment-original.json")"
oc -n cert-manager-operator scale deployment/cert-manager-operator-controller-manager \
  --replicas="$ORIGINAL_REPLICAS"
```

If that count was zero, this leaves no active operator until one is started again. CertManager/TrustManager CRs and their operands are retained; these manual steps do not create the disposable Certificate/Bundle resources used by the broader suite.

Share this report together with the new `RUN_DIR` outputs. For each reported failure include the tested commit, cluster version, APIServer profile, Deployment arguments, baseline PID/fingerprint, both attempts' protocol/cipher logs, and either the fresh/operand positive controls or the HTTP/HTTPS Prometheus target pair.
