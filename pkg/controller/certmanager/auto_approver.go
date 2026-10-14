package certmanager

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
	operatorconfigclient "github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned/typed/operator/v1alpha1"
	operatorlisters "github.com/openshift/cert-manager-operator/pkg/operator/listers/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/operatorclient"
)

const (
	autoApproverName         = "certificaterequests-approver"
	autoApproverRBACName     = "cert-manager-controller-approve:cert-manager-io"
	autoApproverRoleAsset    = "cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-cr.yaml"
	autoApproverBindingAsset = "cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-crb.yaml"
	autoApproverDegraded     = "AutoApproverDegraded"
	autoApproverProgressing  = "AutoApproverProgressing"
)

type controllerSelectionConflictError struct{ message string }

func (e *controllerSelectionConflictError) Error() string { return e.message }

// autoApproverController is the single owner of default approval RBAC. It
// delegates Deployment mutation to the existing library-go controller only after
// the durable-intent and permission barriers pass. It is always registered, so
// turning off the optional operand controller cannot discard recorded intent.
type autoApproverController struct {
	client               operatorconfigclient.OperatorV1alpha1Interface
	kube                 kubernetes.Interface
	lister               operatorlisters.CertManagerLister
	statusClient         operatorclient.OperatorClient
	recorder             events.Recorder
	deploymentController factory.Controller
	mu                   sync.Mutex
	// Only bridges this serialized sync to library-go's context-free hook. Never
	// used for recovery: each sync reconstructs its decision from API state.
	current   *v1alpha1.CertManager
	disabling bool
	desired   *appsv1.Deployment
}

func newAutoApproverController(client operatorconfigclient.OperatorV1alpha1Interface, kube kubernetes.Interface, lister operatorlisters.CertManagerLister, recorder events.Recorder) *autoApproverController {
	return &autoApproverController{client: client, kube: kube, lister: lister, statusClient: operatorclient.OperatorClient{Client: client}, recorder: recorder}
}

func disableRequested(cm *v1alpha1.CertManager) bool {
	return cm.Status.AutoApproverDisabled || v1helpers.IsOperatorConditionTrue(cm.Status.Conditions, v1alpha1.AutoApproverDisableRequested)
}

// Only the named object's 404 proves absence. A missing CRD/endpoint can also
// produce a 404, but must never authorize restoration.
func managerNotFound(err error) bool {
	var status apierrors.APIStatus
	if !apierrors.IsNotFound(err) || !errors.As(err, &status) {
		return false
	}
	d := status.Status().Details
	return d != nil && d.Name == "cluster" && d.Group == v1alpha1.SchemeGroupVersion.Group && d.Kind == "approverpolicymanagers"
}

func (c *autoApproverController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current, c.desired, c.disabling = nil, nil, false
	defer func() { c.current, c.desired, c.disabling = nil, nil, false }()
	cm, err := c.client.CertManagers().Get(ctx, "cluster", metav1.GetOptions{})
	if apierrors.IsNotFound(err) && management.IsOperatorRemovable() {
		return nil
	}
	if err != nil {
		return err
	}
	c.current = cm
	if cm.Spec.ManagementState != operatorv1.Managed || (management.IsOperatorRemovable() && cm.DeletionTimestamp != nil) {
		if management.IsOperatorRemovable() && (cm.Spec.ManagementState == operatorv1.Removed || (cm.Spec.ManagementState == operatorv1.Managed && cm.DeletionTimestamp != nil)) {
			if err := c.removeRBAC(ctx); err != nil {
				return err
			}
		}
		if err := c.checkCachedConfiguration(); err != nil {
			return err
		}
		if err := c.deploymentController.Sync(ctx, syncCtx); err != nil {
			return fmt.Errorf("reconcile cert-manager deployment: %w", err)
		}
		return nil
	}
	err = c.reconcile(ctx, syncCtx)
	if err != nil {
		reason := "Failed"
		var conflict *controllerSelectionConflictError
		if errors.As(err, &conflict) {
			reason = "ControllerOverrideConflict"
		}
		if statusErr := c.setConditions(ctx, true, true, reason, err.Error()); statusErr != nil {
			return errors.Join(err, statusErr)
		}
	}
	return err
}

func (c *autoApproverController) reconcile(ctx context.Context, syncCtx factory.SyncContext) error {
	manager, readErr := c.client.ApproverPolicyManagers().Get(ctx, "cluster", metav1.GetOptions{})
	absent := managerNotFound(readErr)
	requested := disableRequested(c.current)
	if readErr != nil && !absent {
		// A read failure cannot restore permissions, even after process restart.
		if requested {
			if err := c.removeRBAC(ctx); err != nil {
				return errors.Join(readErr, err)
			}
		}
		return fmt.Errorf("cannot determine ApproverPolicyManager presence: %w", readErr)
	}
	ready := false
	if manager != nil && manager.DeletionTimestamp == nil {
		condition := manager.Status.GetCondition(v1alpha1.Ready)
		ready = condition != nil && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == manager.Generation
	}
	c.disabling = !absent && (requested || ready)
	if c.disabling {
		if err := c.disableDefaultApproval(ctx); err != nil {
			return err
		}
	} else {
		if err := c.restoreDefaultApproval(ctx, requested); err != nil {
			return err
		}
	}
	// All existing override hooks read this informer. Require the same spec and
	// identity as the live object before letting them construct the Deployment.
	if err := c.checkCachedConfiguration(); err != nil {
		return err
	}
	if err := c.deploymentController.Sync(ctx, syncCtx); err != nil {
		return fmt.Errorf("reconcile cert-manager deployment: %w", err)
	}
	if !c.disabling && !requested {
		return c.setConditions(ctx, false, false, "AsExpected", "Default approval configuration is unchanged")
	}
	if c.desired == nil {
		return fmt.Errorf("deployment hook did not produce handoff evidence")
	}
	converged, err := c.rolloutConverged(ctx)
	if err != nil {
		return err
	}
	if !converged {
		return c.setConditions(ctx, false, true, "RolloutPending", "Waiting for the intended cert-manager Deployment and old-pod termination; handoff completion is unconfirmed")
	}
	// Re-read the manager before recording a transition. A replacement or a new
	// manager invalidates the observation, and errors never count as absence.
	latest, err := c.client.ApproverPolicyManagers().Get(ctx, "cluster", metav1.GetOptions{})
	if c.disabling {
		if err != nil {
			return fmt.Errorf("reconfirm manager presence: %w", err)
		}
		if latest.UID != manager.UID {
			return fmt.Errorf("ApproverPolicyManager changed during handoff")
		}
		if err := c.confirmRBACAbsent(ctx); err != nil {
			return err
		}
	} else {
		if !managerNotFound(err) {
			if err != nil {
				return fmt.Errorf("manager absence no longer confirmed: %w", err)
			}
			return fmt.Errorf("manager reappeared before restoration completion")
		}
		if err := c.confirmRBACRestored(ctx); err != nil {
			return err
		}
	}
	wasDisabled := c.current.Status.AutoApproverDisabled
	changed, err := c.statusClient.UpdateCertManagerStatus(ctx, c.current, func(s *v1alpha1.CertManagerStatus) {
		s.AutoApproverDisabled = c.disabling
		if !c.disabling {
			v1helpers.RemoveOperatorCondition(&s.Conditions, v1alpha1.AutoApproverDisableRequested)
		}
		setHandoffConditions(s, false, false, "AsExpected", "Approval handoff configuration has converged")
	})
	if err != nil {
		return fmt.Errorf("record completed approval transition: %w", err)
	}
	if changed && (wasDisabled != c.disabling || (!c.disabling && requested)) {
		c.recordTransition(ctx)
	}
	return nil
}

func (c *autoApproverController) disableDefaultApproval(ctx context.Context) error {
	if !v1helpers.IsOperatorConditionTrue(c.current.Status.Conditions, v1alpha1.AutoApproverDisableRequested) {
		_, err := c.statusClient.UpdateCertManagerStatus(ctx, c.current, func(s *v1alpha1.CertManagerStatus) {
			v1helpers.SetOperatorCondition(&s.Conditions, operatorv1.OperatorCondition{Type: v1alpha1.AutoApproverDisableRequested, Status: operatorv1.ConditionTrue, Reason: "Requested", Message: "Disable built-in approval before completing the approver-policy handoff"})
		})
		if err != nil {
			return fmt.Errorf("persist auto-approver disable intent: %w", err)
		}
	}
	if err := c.removeRBAC(ctx); err != nil {
		return err
	}
	return nil
}

func (c *autoApproverController) checkCachedConfiguration() error {
	cached, err := c.lister.Get("cluster")
	if err != nil {
		return err
	}
	if cached.UID != c.current.UID || cached.Generation != c.current.Generation || !equality.Semantic.DeepEqual(cached.Spec, c.current.Spec) {
		return fmt.Errorf("waiting for the current CertManager configuration in the informer")
	}
	return nil
}

func (c *autoApproverController) restoreDefaultApproval(ctx context.Context, requested bool) error {
	if requested {
		if _, err := c.client.ApproverPolicyManagers().Get(ctx, "cluster", metav1.GetOptions{}); !managerNotFound(err) {
			if err != nil {
				return fmt.Errorf("manager absence unconfirmed before restoration: %w", err)
			}
			return fmt.Errorf("manager reappeared before restoration")
		}
	}
	return c.restoreRBAC(ctx)
}

func setHandoffConditions(status *v1alpha1.CertManagerStatus, degraded, progressing bool, reason, message string) {
	for _, condition := range []struct {
		name  string
		value bool
	}{{autoApproverDegraded, degraded}, {autoApproverProgressing, progressing}} {
		state := operatorv1.ConditionFalse
		if condition.value {
			state = operatorv1.ConditionTrue
		}
		v1helpers.SetOperatorCondition(&status.Conditions, operatorv1.OperatorCondition{Type: condition.name, Status: state, Reason: reason, Message: message})
	}
}

func (c *autoApproverController) setConditions(ctx context.Context, degraded, progressing bool, reason, message string) error {
	_, err := c.statusClient.UpdateCertManagerStatus(ctx, c.current, func(s *v1alpha1.CertManagerStatus) { setHandoffConditions(s, degraded, progressing, reason, message) })
	return err
}

func (c *autoApproverController) removeRBAC(ctx context.Context) error {
	if err := c.kube.RbacV1().ClusterRoleBindings().Delete(ctx, autoApproverRBACName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove auto-approver binding: %w", err)
	}
	if _, err := c.kube.RbacV1().ClusterRoleBindings().Get(ctx, autoApproverRBACName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		if err != nil {
			return fmt.Errorf("auto-approver binding absence unconfirmed: %w", err)
		}
		return fmt.Errorf("auto-approver binding still exists")
	}
	if err := c.kube.RbacV1().ClusterRoles().Delete(ctx, autoApproverRBACName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove auto-approver role: %w", err)
	}
	return c.confirmRBACAbsent(ctx)
}

func (c *autoApproverController) confirmRBACAbsent(ctx context.Context) error {
	if _, err := c.kube.RbacV1().ClusterRoleBindings().Get(ctx, autoApproverRBACName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		if err != nil {
			return fmt.Errorf("auto-approver binding absence unconfirmed: %w", err)
		}
		return fmt.Errorf("auto-approver binding still exists")
	}
	if _, err := c.kube.RbacV1().ClusterRoles().Get(ctx, autoApproverRBACName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		if err != nil {
			return fmt.Errorf("auto-approver role absence unconfirmed: %w", err)
		}
		return fmt.Errorf("auto-approver role still exists")
	}
	return nil
}

func (c *autoApproverController) restoreRBAC(ctx context.Context) error {
	role := resourceread.ReadClusterRoleV1OrDie(assets.MustAsset(autoApproverRoleAsset))
	binding := resourceread.ReadClusterRoleBindingV1OrDie(assets.MustAsset(autoApproverBindingAsset))
	if _, _, err := resourceapply.ApplyClusterRole(ctx, c.kube.RbacV1(), c.recorder, role); err != nil {
		return fmt.Errorf("restore auto-approver role: %w", err)
	}
	if _, _, err := resourceapply.ApplyClusterRoleBinding(ctx, c.kube.RbacV1(), c.recorder, binding); err != nil {
		return fmt.Errorf("restore auto-approver binding: %w", err)
	}
	return nil
}

func (c *autoApproverController) confirmRBACRestored(ctx context.Context) error {
	role, err := c.kube.RbacV1().ClusterRoles().Get(ctx, autoApproverRBACName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	binding, err := c.kube.RbacV1().ClusterRoleBindings().Get(ctx, autoApproverRBACName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	wantRole := resourceread.ReadClusterRoleV1OrDie(assets.MustAsset(autoApproverRoleAsset))
	wantBinding := resourceread.ReadClusterRoleBindingV1OrDie(assets.MustAsset(autoApproverBindingAsset))
	if role.DeletionTimestamp != nil || binding.DeletionTimestamp != nil || !equality.Semantic.DeepEqual(role.Rules, wantRole.Rules) || !equality.Semantic.DeepEqual(role.AggregationRule, wantRole.AggregationRule) || !equality.Semantic.DeepEqual(binding.RoleRef, wantBinding.RoleRef) || !equality.Semantic.DeepEqual(binding.Subjects, wantBinding.Subjects) {
		return fmt.Errorf("default approval RBAC restoration has not converged")
	}
	return nil
}

// controllerSelection reads StringSlice flag forms as used by cert-manager.
// Repeated flags append; exclusions take precedence and exclusion-only lists
// imply the default set (cert-manager v1.20.3 options.EnabledControllers).
func controllerSelection(args []string) ([]string, bool, error) {
	var values []string
	found := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var value string
		switch {
		case strings.HasPrefix(arg, "--controllers="):
			value = strings.TrimPrefix(arg, "--controllers=")
		case arg == "--controllers":
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return nil, true, fmt.Errorf("--controllers requires a value")
			}
			value = args[i]
		default:
			continue
		}
		found = true
		if value == "" {
			continue
		}
		fields, err := csv.NewReader(strings.NewReader(value)).Read()
		if err != nil {
			return nil, true, fmt.Errorf("invalid --controllers value: %w", err)
		}
		for _, field := range fields {
			if field == "" || strings.TrimSpace(field) != field {
				return nil, true, fmt.Errorf("invalid empty or whitespace controller selection")
			}
		}
		values = append(values, fields...)
	}
	return values, found, nil
}

func autoApproverEnabled(values []string, flagPresent bool) bool {
	if !flagPresent {
		return true
	}
	if slices.Contains(values, "-"+autoApproverName) {
		return false
	}
	positive, wildcard := false, false
	for _, value := range values {
		if !strings.HasPrefix(value, "-") {
			positive = true
		}
		if value == "*" || value == autoApproverName {
			wildcard = true
		}
	}
	return wildcard || (!positive && len(values) > 0)
}

func (c *autoApproverController) prepareDeployment(spec *operatorv1.OperatorSpec, desired *appsv1.Deployment) error {
	if c.current == nil {
		return fmt.Errorf("approval handoff hook called outside its reconciliation")
	}
	if err := c.checkCachedConfiguration(); err != nil {
		return err
	}
	if !equality.Semantic.DeepEqual(*spec, c.current.Spec.OperatorSpec) {
		return fmt.Errorf("operator configuration changed during Deployment construction")
	}
	if c.disabling {
		if err := excludeDefaultApprover(spec, desired); err != nil {
			return err
		}
	}
	c.desired = desired.DeepCopy()
	return nil
}

func excludeDefaultApprover(spec *operatorv1.OperatorSpec, desired *appsv1.Deployment) error {
	cfg, err := operatorclient.GetUnsupportedConfigOverrides(spec)
	if err != nil {
		return err
	}
	overridePresent := false
	if cfg != nil {
		for _, arg := range cfg.Controller.Args {
			if arg == "--controllers" {
				return &controllerSelectionConflictError{"unsupported --controllers override must use --controllers=<selection>"}
			}
		}
		// Unsupported overrides use the existing key merger (last value
		// wins), unlike repeated flags in an actual running container.
		argMap := map[string]string{}
		common.ParseArgMap(argMap, cfg.Controller.Args)
		value, present := argMap["--controllers"]
		overridePresent = present
		if present && value == "" {
			// Generic key merging drops '=' for empty values. Preserve an
			// explicitly empty selection instead of turning it into a bare flag.
			desired.Spec.Template.Spec.Containers[0].Args = common.StripArgsByKeys(desired.Spec.Template.Spec.Containers[0].Args, common.ArgKeysSet([]string{"--controllers"}))
			desired.Spec.Template.Spec.Containers[0].Args = append(desired.Spec.Template.Spec.Containers[0].Args, "--controllers=")
		}
	}
	args := desired.Spec.Template.Spec.Containers[0].Args
	selection, present, err := controllerSelection(args)
	if err != nil {
		return &controllerSelectionConflictError{err.Error()}
	}
	if overridePresent && autoApproverEnabled(selection, present) {
		return &controllerSelectionConflictError{"unsupportedConfigOverrides.controller.args enables certificaterequests-approver; remove the override or exclude that controller to complete handoff"}
	}
	if autoApproverEnabled(selection, present) {
		if !present {
			selection = []string{"*"}
		}
		selection = append(selection, "-"+autoApproverName)
		args = common.StripArgsByKeys(args, common.ArgKeysSet([]string{"--controllers"}))
		args = append(args, "--controllers="+strings.Join(selection, ","))
		desired.Spec.Template.Spec.Containers[0].Args = args
	}
	return nil
}

func (c *autoApproverController) rolloutConverged(ctx context.Context) (bool, error) {
	desired := c.desired
	live, err := c.kube.AppsV1().Deployments(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	replicas := int32(1)
	if desired.Spec.Replicas != nil {
		replicas = *desired.Spec.Replicas
	}
	if replicas < 1 || live.DeletionTimestamp != nil || live.Generation < 1 || live.Status.ObservedGeneration < live.Generation || live.Spec.Replicas == nil || *live.Spec.Replicas != replicas || live.Status.UpdatedReplicas != replicas || live.Status.AvailableReplicas != replicas || live.Status.ReadyReplicas != replicas || live.Status.Replicas != replicas || !equality.Semantic.DeepDerivative(desired.Spec.Template, live.Spec.Template) {
		return false, nil
	}
	// Do not filter by current pod labels: old replicas may have different
	// labels, and terminating pods still count until they disappear.
	sets, err := c.kube.AppsV1().ReplicaSets(desired.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	owned := map[types.UID]bool{}
	for _, rs := range sets.Items {
		owner := metav1.GetControllerOf(&rs)
		if owner != nil && owner.Kind == "Deployment" && owner.Name == desired.Name {
			owned[rs.UID] = true
		}
	}
	pods, err := c.kube.CoreV1().Pods(desired.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	selector, err := metav1.LabelSelectorAsSelector(live.Spec.Selector)
	if err != nil {
		return false, fmt.Errorf("read cert-manager rollout selector: %w", err)
	}
	observedReplicas := int32(0)
	for _, pod := range pods.Items {
		owner := metav1.GetControllerOf(&pod)
		if (owner == nil || !owned[owner.UID]) && !selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		found := false
		for _, container := range pod.Spec.Containers {
			if container.Name != desired.Spec.Template.Spec.Containers[0].Name {
				continue
			}
			found = true
			selection, present, err := controllerSelection(container.Args)
			if err != nil {
				return false, err
			}
			if c.disabling {
				if autoApproverEnabled(selection, present) {
					return false, nil
				}
			} else if !equality.Semantic.DeepEqual(container.Args, desired.Spec.Template.Spec.Containers[0].Args) {
				return false, nil
			}
		}
		if !found {
			return false, nil
		}
		if pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning && equality.Semantic.DeepDerivative(desired.Spec.Template.Spec, pod.Spec) {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					observedReplicas++
					break
				}
			}
		}
	}
	return observedReplicas >= replicas, nil
}

func (c *autoApproverController) recordTransition(ctx context.Context) {
	reason, message := "AutoApproverEnabled", "Built-in CertificateRequest auto-approver configuration has been restored"
	if c.disabling {
		reason, message = "AutoApproverDisabled", "Built-in CertificateRequest auto-approver has been disabled; approver-policy is now responsible for approvals"
	}
	now := metav1.Now()
	_, err := c.kube.CoreV1().Events(operatorclient.OperatorNamespace).Create(ctx, &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{GenerateName: "cert-manager-auto-approver-", Namespace: operatorclient.OperatorNamespace},
		InvolvedObject: corev1.ObjectReference{APIVersion: v1alpha1.SchemeGroupVersion.String(), Kind: "CertManager", Name: c.current.Name, UID: c.current.UID},
		Type:           corev1.EventTypeNormal, Reason: reason, Message: message, FirstTimestamp: now, LastTimestamp: now, Count: 1, Source: corev1.EventSource{Component: "cert-manager-operator"},
	}, metav1.CreateOptions{})
	if err != nil {
		c.recorder.Warningf("AutoApproverEventFailed", "Transition was recorded but its event could not be written: %v", err)
	}
}
