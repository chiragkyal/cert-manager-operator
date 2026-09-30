package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Degraded is the condition type used to inform state of the operator when
	// it has failed with irrecoverable error like permission issues.
	// DebugEnabled has the following options:
	//   Status:
	//   - True
	//   - False
	//   Reason:
	//   - Failed
	Degraded string = "Degraded"

	// Ready is the condition type used to inform state of readiness of the
	// operator to process istio-csr enabling requests.
	//   Status:
	//   - True
	//   - False
	//   Reason:
	//   - Progressing
	//   - Failed
	//   - Ready: operand successfully deployed and ready
	Ready string = "Ready"

	// AutoApproverDisabled is the condition type set on the CertManager CR status to surface
	// the effective state of cert-manager's built-in CertificateRequest auto-approver.
	//   Status:
	//   - True: the built-in auto-approver is disabled (an ApproverPolicyManager CR reported
	//     Ready=True); approver-policy is expected to process CertificateRequest approvals.
	//   - False: the built-in auto-approver is active (no ApproverPolicyManager CR found, or
	//     it has not yet reported Ready=True).
	//   Reason:
	//   - ApproverPolicyReady
	//   - AutoApprovalEnabled
	AutoApproverDisabled string = "AutoApproverDisabled"
)

const (
	ReasonFailed string = "Failed"

	ReasonReady string = "Ready"

	ReasonInProgress string = "Progressing"

	// ReasonApproverPolicyReady is used on the AutoApproverDisabled condition when the
	// built-in auto-approver has been disabled because the ApproverPolicyManager CR
	// reported Ready=True.
	ReasonApproverPolicyReady string = "ApproverPolicyReady"

	// ReasonAutoApprovalEnabled is used on the AutoApproverDisabled condition when the
	// built-in auto-approver is active, because no ApproverPolicyManager CR exists (or it
	// has not yet reported Ready=True).
	ReasonAutoApprovalEnabled string = "AutoApprovalEnabled"
)

func (c *ConditionalStatus) GetCondition(t string) *metav1.Condition {
	for i, cond := range c.Conditions {
		if cond.Type == t {
			return &c.Conditions[i]
		}
	}
	return nil
}

func (c *ConditionalStatus) SetCondition(t string, cs metav1.ConditionStatus, reason, msg string) bool {
	condition := c.GetCondition(t)
	if condition == nil {
		c.Conditions = append(c.Conditions, metav1.Condition{
			Type:               t,
			Status:             cs,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            msg,
		})
		return true
	}
	if condition.Status != cs || condition.Reason != reason {
		condition.Status = cs
		condition.LastTransitionTime = metav1.Now()
		condition.Reason = reason
		condition.Message = msg
		return true
	}
	return false
}
