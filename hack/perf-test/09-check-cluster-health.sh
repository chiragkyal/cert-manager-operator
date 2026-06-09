#!/usr/bin/env bash
set -euo pipefail

echo "=== Cluster Health Check for Performance Testing ==="
echo ""

# 1. Cluster info
echo "--- Cluster Information ---"
echo "Server:  $(oc whoami --show-server)"
echo "User:    $(oc whoami)"
echo "Version: $(oc version -o json 2>/dev/null | jq -r '.openshiftVersion // .serverVersion.gitVersion' 2>/dev/null || echo "unknown")"
echo ""

# 2. Node status
echo "--- Node Status ---"
oc get nodes -o wide
echo ""

# 3. Node resources
echo "--- Node Resource Usage ---"
oc adm top nodes 2>/dev/null || echo "Metrics server not available"
echo ""

# 4. cert-manager operator status
echo "--- cert-manager Operator Status ---"
oc get csv -n cert-manager-operator -o wide 2>/dev/null || oc get csv -A 2>/dev/null | grep cert-manager || echo "CSV not found"
echo ""

# 5. cert-manager components
echo "--- cert-manager Components ---"
oc get pods -n cert-manager -o wide
echo ""
echo "Controller deployment:"
oc get deployment cert-manager -n cert-manager -o wide
echo ""
echo "Controller args:"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . 2>/dev/null || echo "[]"
echo ""
echo "Controller resources:"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq . 2>/dev/null || echo "{}"
echo ""

# 6. CertManager CR
echo "--- CertManager CR ---"
oc get certmanager cluster -o yaml 2>/dev/null | grep -A50 "^spec:" || echo "CertManager CR not found"
echo ""

# 7. cert-manager resource usage
echo "--- cert-manager Pod Resources ---"
oc adm top pods -n cert-manager 2>/dev/null || echo "Metrics unavailable"
echo ""

# 8. API server health
echo "--- API Server Health ---"
oc get --raw /healthz 2>/dev/null && echo " (healthy)" || echo "UNHEALTHY"
echo ""

# 9. etcd health (if accessible)
echo "--- etcd Status ---"
oc get pods -n openshift-etcd -l app=etcd --no-headers 2>/dev/null | head -5 || echo "etcd pods not directly visible"
echo ""

# 10. Cluster operators
echo "--- Degraded Cluster Operators ---"
DEGRADED=$(oc get clusteroperators -o json 2>/dev/null | jq -r '.items[] | select(.status.conditions[]? | select(.type=="Degraded" and .status=="True")) | .metadata.name')
if [[ -z "${DEGRADED}" ]]; then
    echo "  None degraded (all healthy)"
else
    echo "  WARNING - Degraded operators:"
    echo "${DEGRADED}" | sed 's/^/    /'
fi
echo ""

# 11. Existing certificates (to understand current load)
echo "--- Existing Certificate Resources (all namespaces) ---"
TOTAL_CERTS=$(oc get certificates -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
READY_CERTS=$(oc get certificates -A -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
echo "  Total certificates:  ${TOTAL_CERTS}"
echo "  Ready certificates:  ${READY_CERTS}"
echo "  Not-ready:           $((TOTAL_CERTS - READY_CERTS))"
echo ""

# 12. Priority and Fairness (API rate limiting)
echo "--- API Priority and Fairness ---"
echo "Flow schemas relevant to cert-manager:"
oc get flowschemas -o json 2>/dev/null | jq -r '.items[] | select(.spec.rules[]?.subjects[]? | select(.kind=="ServiceAccount" and (.serviceAccount.name | test("cert-manager")))) | "  \(.metadata.name) (priority: \(.spec.priorityLevelConfiguration.name))"' 2>/dev/null || echo "  No cert-manager specific flow schemas found (using default)"
echo ""
echo "Priority levels:"
oc get prioritylevelconfigurations -o custom-columns=NAME:.metadata.name,TYPE:.spec.type,SHARES:.spec.limited.nominalConcurrencyShares --no-headers 2>/dev/null | head -10 || echo "  Not accessible"
echo ""

echo "=== Health Check Complete ==="
echo ""
echo "Recommendations before testing:"
echo "  - All nodes should be Ready"
echo "  - No degraded cluster operators"
echo "  - cert-manager controller pod should be Running with 0 restarts"
echo "  - API server should be healthy"
echo "  - Consider creating a dedicated FlowSchema for cert-manager if testing high QPS"
