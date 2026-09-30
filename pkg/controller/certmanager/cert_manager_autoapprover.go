package certmanager

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
	certmanoperatorinformers "github.com/openshift/cert-manager-operator/pkg/operator/informers/externalversions"
	operatorv1alpha1informer "github.com/openshift/cert-manager-operator/pkg/operator/informers/externalversions/operator/v1alpha1"
	operatorv1alpha1lister "github.com/openshift/cert-manager-operator/pkg/operator/listers/operator/v1alpha1"
)

// This file implements Stories 10 & 11 of the approver-policy-controller enhancement:
// automatically disabling cert-manager's built-in CertificateRequest auto-approver when
// approver-policy is deployed and ready, and automatically re-enabling it when the
// ApproverPolicyManager CR is deleted. See:
//   enhancements/cert-manager/approver-policy-controller.md#design-for-auto-disabling-the-default-approver

const (
	certManagerAutoApproverControllerName = operatorName + "-autoapprover"

	// approverPolicyManagerName is the singleton name of the ApproverPolicyManager CR, enforced by
	// its CRD's XValidation rule.
	approverPolicyManagerName = "cluster"

	// defaultAutoApproverRequeueInterval bounds how long CertManagerAutoApproverController waits
	// before re-checking an ApproverPolicyManager CR that exists but has not yet reported
	// Ready=True.
	defaultAutoApproverRequeueInterval = 30 * time.Second

	// approveClusterRoleAssetName and approveClusterRoleBindingAssetName point to the RBAC bindata
	// that grants the "cert-manager" ServiceAccount the "approve" verb on cert-manager.io "signers"
	// for its own internal Issuer/ClusterIssuer signers. These are intentionally excluded from
	// certManagerControllerAssetFiles (the unconditional static asset list) and are instead owned by
	// CertManagerAutoApproverController, which creates them by default and deletes them once
	// approver-policy is confirmed Ready (see disableAutoApprover/enableAutoApprover below).
	approveClusterRoleAssetName        = "cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-cr.yaml"
	approveClusterRoleBindingAssetName = "cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-crb.yaml"

	// approveClusterRoleName is the name of the ClusterRole (and matching ClusterRoleBinding)
	// granting cert-manager's built-in auto-approver the "approve" RBAC capability.
	approveClusterRoleName = "cert-manager-controller-approve:cert-manager-io"

	// disableBuiltinApproverArg disables only the certificaterequests-approver controller while
	// keeping every other cert-manager controller enabled.
	disableBuiltinApproverArg = "--controllers=*,-certificaterequests-approver"
)

// CertManagerAutoApproverController implements the automatic disable/re-enable of
// cert-manager's built-in CertificateRequest auto-approver based on the ApproverPolicyManager
// CR's existence and Ready status. It owns:
//   - The `cert-manager-controller-approve:cert-manager-io` ClusterRole/ClusterRoleBinding.
//   - The `AutoApproverDisabled` status condition on the CertManager CR.
//
// It intentionally does NOT own the cert-manager controller Deployment's `--controllers` arg;
// that is injected by withAutoApproverDisableArgHook, which participates in the
// deploymentcontroller.NewDeploymentController reconciliation pipeline for the cert-manager
// controller Deployment so the flag is not clobbered by that controller's continuous reconciliation.
// Both this controller and the hook derive the same "should the built-in approver be disabled"
// decision from the SAME observed cluster state (see isBuiltinApproverDisableRequired), so they
// converge to a consistent state without needing to share any additional persisted flag.
type CertManagerAutoApproverController struct {
	operatorClient               v1helpers.OperatorClient
	certManagerOperatorInformers certmanoperatorinformers.SharedInformerFactory
	kubeClient                   kubernetes.Interface
	clusterRoleLister            rbaclisters.ClusterRoleLister
	eventRecorder                events.Recorder
}

// NewCertManagerAutoApproverController creates the CertManagerAutoApproverController.
func NewCertManagerAutoApproverController(
	operatorClient v1helpers.OperatorClient,
	certManagerOperatorInformers certmanoperatorinformers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
) factory.Controller {
	clusterRoleInformer := kubeInformersForNamespaces.InformersFor("").Rbac().V1().ClusterRoles()

	c := &CertManagerAutoApproverController{
		operatorClient:               operatorClient,
		certManagerOperatorInformers: certManagerOperatorInformers,
		kubeClient:                   kubeClient,
		clusterRoleLister:            clusterRoleInformer.Lister(),
		eventRecorder:                eventRecorder.WithComponentSuffix("cert-manager-autoapprover"),
	}

	return factory.New().
		WithInformers(
			operatorClient.Informer(),
			certManagerOperatorInformers.Operator().V1alpha1().CertManagers().Informer(),
			certManagerOperatorInformers.Operator().V1alpha1().ApproverPolicyManagers().Informer(),
			clusterRoleInformer.Informer(),
		).
		WithInformersQueueKeyFunc(
			// Always queue reconciliation for the singleton "cluster" CertManager CR, regardless
			// of which watched resource changed.
			func(obj runtime.Object) string {
				return "cluster"
			},
			certManagerOperatorInformers.Operator().V1alpha1().ApproverPolicyManagers().Informer(),
			clusterRoleInformer.Informer(),
		).
		WithSync(c.sync).
		ToController(certManagerAutoApproverControllerName, c.eventRecorder)
}

func (c *CertManagerAutoApproverController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if _, err := c.certManagerOperatorInformers.Operator().V1alpha1().CertManagers().Lister().Get("cluster"); err != nil {
		if apierrors.IsNotFound(err) {
			// CertManager CR not created yet, nothing to do.
			return nil
		}
		return fmt.Errorf("failed to get CertManager %q: %w", "cluster", err)
	}

	approverPolicy, err := c.certManagerOperatorInformers.Operator().V1alpha1().ApproverPolicyManagers().Lister().Get(approverPolicyManagerName)
	approverPolicyNotFound := apierrors.IsNotFound(err)
	if err != nil && !approverPolicyNotFound {
		return fmt.Errorf("failed to get ApproverPolicyManager %q: %w", approverPolicyManagerName, err)
	}

	if approverPolicyNotFound {
		// ApproverPolicyManager CR gone -> re-enable the built-in auto-approver.
		if err := c.enableAutoApprover(ctx); err != nil {
			return fmt.Errorf("failed to re-enable built-in auto-approver: %w", err)
		}
		return c.setAutoApproverDisabledCondition(ctx, operatorv1.ConditionFalse, v1alpha1.ReasonAutoApprovalEnabled,
			"No ApproverPolicyManager CR found; cert-manager's built-in CertificateRequest auto-approver is active")
	}

	disabled, err := c.approveClusterRoleAbsent()
	if err != nil {
		return err
	}

	switch {
	case disabled:
		// Latch held (or first-time disable already completed): keep the built-in auto-approver
		// disabled regardless of the operand's current Ready state. This call is an idempotent
		// no-op when already fully disabled.
		if err := c.disableAutoApprover(ctx); err != nil {
			return fmt.Errorf("failed to keep built-in auto-approver disabled: %w", err)
		}
		return c.setAutoApproverDisabledCondition(ctx, operatorv1.ConditionTrue, v1alpha1.ReasonApproverPolicyReady,
			"ApproverPolicyManager CR reported Ready=True; cert-manager's built-in CertificateRequest auto-approver has been disabled")

	case isApproverPolicyManagerReady(approverPolicy):
		// First time Ready=True observed while the built-in approver is still enabled -> disable it.
		if err := c.disableAutoApprover(ctx); err != nil {
			return fmt.Errorf("failed to disable built-in auto-approver: %w", err)
		}
		return c.setAutoApproverDisabledCondition(ctx, operatorv1.ConditionTrue, v1alpha1.ReasonApproverPolicyReady,
			"ApproverPolicyManager CR reported Ready=True; cert-manager's built-in CertificateRequest auto-approver has been disabled")

	default:
		// ApproverPolicyManager CR exists but has not yet reported Ready=True; wait rather than
		// disabling the built-in approver, to avoid a gap in certificate approval. Requeue so we
		// notice once it becomes Ready even without a new informer event.
		c.eventRecorder.Eventf("AutoApproverWaiting", "ApproverPolicyManager CR %q is not yet Ready=True; keeping built-in auto-approver enabled", approverPolicyManagerName)
		syncCtx.Queue().AddAfter(syncCtx.QueueKey(), defaultAutoApproverRequeueInterval)
		return nil
	}
}

// isApproverPolicyManagerReady reports whether the ApproverPolicyManager CR has a Ready=True
// status condition.
func isApproverPolicyManagerReady(apm *v1alpha1.ApproverPolicyManager) bool {
	cond := apm.Status.GetCondition(v1alpha1.Ready)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

// approveClusterRoleAbsent reports whether the cert-manager-controller-approve:cert-manager-io
// ClusterRole is currently absent from the cluster. Its absence is the single source of truth
// for "the built-in auto-approver is currently disabled" (the one-way latch), shared between
// this controller and withAutoApproverDisableArgHook.
func (c *CertManagerAutoApproverController) approveClusterRoleAbsent() (bool, error) {
	_, err := c.clusterRoleLister.Get(approveClusterRoleName)
	if err == nil {
		return false, nil
	}
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	return false, fmt.Errorf("failed to check if ClusterRole %q exists: %w", approveClusterRoleName, err)
}

// disableAutoApprover deletes the approve ClusterRole/ClusterRoleBinding. Per the enhancement,
// this is a hard capability-level guard: even if the Deployment arg were somehow reverted, the
// cert-manager ServiceAccount cannot approve CertificateRequests without this RBAC. Deletion is
// idempotent; deleting an already-absent resource is a safe no-op.
func (c *CertManagerAutoApproverController) disableAutoApprover(ctx context.Context) error {
	clusterRole := resourceread.ReadClusterRoleV1OrDie(assets.MustAsset(approveClusterRoleAssetName))
	clusterRoleBinding := resourceread.ReadClusterRoleBindingV1OrDie(assets.MustAsset(approveClusterRoleBindingAssetName))

	var errs []error
	if _, _, err := resourceapply.DeleteClusterRole(ctx, c.kubeClient.RbacV1(), c.eventRecorder, clusterRole); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete ClusterRole %q: %w", clusterRole.Name, err))
	}
	if _, _, err := resourceapply.DeleteClusterRoleBinding(ctx, c.kubeClient.RbacV1(), c.eventRecorder, clusterRoleBinding); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete ClusterRoleBinding %q: %w", clusterRoleBinding.Name, err))
	}
	return utilerrors.NewAggregate(errs)
}

// enableAutoApprover recreates the approve ClusterRole/ClusterRoleBinding. This is idempotent;
// re-applying when the resources already exist in the desired state is a safe no-op.
func (c *CertManagerAutoApproverController) enableAutoApprover(ctx context.Context) error {
	clusterRole := resourceread.ReadClusterRoleV1OrDie(assets.MustAsset(approveClusterRoleAssetName))
	clusterRoleBinding := resourceread.ReadClusterRoleBindingV1OrDie(assets.MustAsset(approveClusterRoleBindingAssetName))

	var errs []error
	if _, _, err := resourceapply.ApplyClusterRole(ctx, c.kubeClient.RbacV1(), c.eventRecorder, clusterRole); err != nil {
		errs = append(errs, fmt.Errorf("failed to apply ClusterRole %q: %w", clusterRole.Name, err))
	}
	if _, _, err := resourceapply.ApplyClusterRoleBinding(ctx, c.kubeClient.RbacV1(), c.eventRecorder, clusterRoleBinding); err != nil {
		errs = append(errs, fmt.Errorf("failed to apply ClusterRoleBinding %q: %w", clusterRoleBinding.Name, err))
	}
	return utilerrors.NewAggregate(errs)
}

// setAutoApproverDisabledCondition sets the AutoApproverDisabled condition on the CertManager CR
// status. This is only called after the corresponding RBAC operation (disableAutoApprover or
// enableAutoApprover) has already succeeded, per the enhancement's atomicity requirements.
func (c *CertManagerAutoApproverController) setAutoApproverDisabledCondition(ctx context.Context, status operatorv1.ConditionStatus, reason, message string) error {
	_, _, err := v1helpers.UpdateStatus(ctx, c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
		Type:    v1alpha1.AutoApproverDisabled,
		Status:  status,
		Reason:  reason,
		Message: message,
	}))
	if err != nil {
		return fmt.Errorf("failed to update CertManager %q status condition %q: %w", "cluster", v1alpha1.AutoApproverDisabled, err)
	}
	return nil
}

// withAutoApproverDisableArgHook is a deploymentcontroller.DeploymentHookFunc, wired only into
// the cert-manager controller Deployment (see generic_deployment_controller.go), that injects
// disableBuiltinApproverArg into the container args when the built-in approver should be
// disabled. It derives the same decision as CertManagerAutoApproverController.sync from the same
// observed cluster state (ApproverPolicyManager Ready status and approve ClusterRole existence),
// so that this hook -- which runs on every reconciliation of the cert-manager controller
// Deployment -- does not fight with or lag behind the bespoke controller that owns the RBAC.
func withAutoApproverDisableArgHook(
	approverPolicyManagerInformer operatorv1alpha1informer.ApproverPolicyManagerInformer,
	clusterRoleLister rbaclisters.ClusterRoleLister,
) func(*operatorv1.OperatorSpec, *appsv1.Deployment) error {
	return func(_ *operatorv1.OperatorSpec, deployment *appsv1.Deployment) error {
		shouldDisable, err := shouldDisableBuiltinApprover(approverPolicyManagerInformer.Lister(), clusterRoleLister)
		if err != nil {
			return err
		}
		if !shouldDisable {
			return nil
		}

		if len(deployment.Spec.Template.Spec.Containers) == 1 && deployment.Name == certmanagerControllerDeployment {
			deployment.Spec.Template.Spec.Containers[0].Args = common.MergeContainerArgs(
				deployment.Spec.Template.Spec.Containers[0].Args, []string{disableBuiltinApproverArg})
		}
		return nil
	}
}

// shouldDisableBuiltinApprover implements the same decision logic as
// CertManagerAutoApproverController.sync's disable/latch branches, based purely on observed
// cluster state so the hook and the bespoke controller stay consistent without needing to share
// any additional persisted state:
//   - ApproverPolicyManager CR NotFound -> false (re-enable).
//   - approve ClusterRole absent (latch: already disabled) -> true (keep disabled).
//   - approve ClusterRole present and ApproverPolicyManager Ready=True -> true (trigger disable).
//   - approve ClusterRole present and ApproverPolicyManager not yet Ready -> false (wait).
func shouldDisableBuiltinApprover(approverPolicyLister operatorv1alpha1lister.ApproverPolicyManagerLister, clusterRoleLister rbaclisters.ClusterRoleLister) (bool, error) {
	approverPolicy, err := approverPolicyLister.Get(approverPolicyManagerName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get ApproverPolicyManager %q: %w", approverPolicyManagerName, err)
	}

	_, err = clusterRoleLister.Get(approveClusterRoleName)
	switch {
	case apierrors.IsNotFound(err):
		// Latch: already disabled.
		return true, nil
	case err != nil:
		return false, fmt.Errorf("failed to check if ClusterRole %q exists: %w", approveClusterRoleName, err)
	default:
		return isApproverPolicyManagerReady(approverPolicy), nil
	}
}
