package certmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	openapispec "k8s.io/kube-openapi/pkg/validation/spec"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
	operatorfake "github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned/fake"
	operatorscheme "github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned/scheme"
	operatorinformers "github.com/openshift/cert-manager-operator/pkg/operator/informers/externalversions"
	"github.com/openshift/cert-manager-operator/pkg/operator/operatorclient"
	"github.com/openshift/cert-manager-operator/pkg/operator/utils"
)

type handoffFixture struct {
	t             *testing.T
	kube          *kubefake.Clientset
	client        *handoffClient
	informers     operatorinformers.SharedInformerFactory
	kubeInformers informers.SharedInformerFactory
	controller    factory.Controller
	trace         []string
}

type handoffClient struct {
	*operatorfake.Clientset
	tracker clienttesting.ObjectTracker
}

func (c *handoffClient) Tracker() clienttesting.ObjectTracker { return c.tracker }

// The generated fake's deduced schema treats conditions as an atomic list.
// Load the installed CRD schemas so SSA merges conditions by type, just as the
// API server does. This keeps the tests on the real typed adapter/SSA path.
func newHandoffClient(t *testing.T, objects ...runtime.Object) *handoffClient {
	t.Helper()
	models := map[string]*openapispec.Schema{}
	for _, name := range []string{"certmanagers", "approverpolicymanagers"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "bases", "operator.openshift.io_"+name+".yaml"))
		require.NoError(t, err)
		var crd apiextensionsv1.CustomResourceDefinition
		require.NoError(t, yaml.Unmarshal(data, &crd))
		for _, version := range crd.Spec.Versions {
			data, err := json.Marshal(version.Schema.OpenAPIV3Schema)
			require.NoError(t, err)
			model := &openapispec.Schema{}
			require.NoError(t, json.Unmarshal(data, model))
			model.AddExtension("x-kubernetes-group-version-kind", []interface{}{map[string]interface{}{"group": crd.Spec.Group, "version": version.Name, "kind": crd.Spec.Names.Kind}})
			models[crd.Spec.Names.Kind+"."+version.Name] = model
		}
	}
	// CRD metadata is implicit in the API server; preserve its fields here.
	converter, err := managedfields.NewTypeConverter(models, true)
	require.NoError(t, err)
	tracker := clienttesting.NewFieldManagedObjectTracker(operatorscheme.Scheme, operatorscheme.Codecs.UniversalDecoder(), converter)
	for _, object := range objects {
		require.NoError(t, tracker.Add(object))
	}
	client := &handoffClient{Clientset: operatorfake.NewClientset(), tracker: tracker}
	client.PrependReactor("*", "*", clienttesting.ObjectReaction(tracker))
	client.PrependWatchReactor("*", func(action clienttesting.Action) (bool, watch.Interface, error) {
		w, err := tracker.Watch(action.GetResource(), action.GetNamespace(), action.(clienttesting.WatchActionImpl).ListOptions)
		return true, w, err
	})
	return client
}

func newHandoffFixture(t *testing.T) *handoffFixture {
	t.Helper()
	t.Setenv("OPERATOR_NAME", "handoff-test")
	// The fake SSA tracker does not separate spec-update field ownership from
	// status ownership. Seed the established library-go finalizer, as on an
	// installed CertManager, so an unrelated metadata update cannot claim status.
	cm := &v1alpha1.CertManager{TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.SchemeGroupVersion.String(), Kind: "CertManager"}, ObjectMeta: metav1.ObjectMeta{Name: "cluster", UID: "cm", Generation: 1, ResourceVersion: "1", Finalizers: []string{"handoff-test.operator.openshift.io/" + certManagerControllerDeploymentControllerName}}, Spec: v1alpha1.CertManagerSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}}}
	manager := &v1alpha1.ApproverPolicyManager{ObjectMeta: metav1.ObjectMeta{Name: "cluster", UID: "manager", Generation: 1}}
	manager.Status.Conditions = []metav1.Condition{{Type: v1alpha1.Ready, Status: metav1.ConditionTrue, ObservedGeneration: 1, Reason: "Ready", LastTransitionTime: metav1.Now()}}
	f := &handoffFixture{t: t, client: newHandoffClient(t, cm, manager), kube: kubefake.NewClientset(resourceread.ReadClusterRoleV1OrDie(assets.MustAsset(autoApproverRoleAsset)), resourceread.ReadClusterRoleBindingV1OrDie(assets.MustAsset(autoApproverBindingAsset)))}
	f.informers = operatorinformers.NewSharedInformerFactory(f.client, 0)
	f.kubeInformers = informers.NewSharedInformerFactoryWithOptions(f.kube, 0, informers.WithNamespace("cert-manager"))
	f.client.PrependReactor("*", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		// Like the real status-subresource API, metadata/spec updates must
		// ignore the caller's stale status (for example EnsureFinalizer).
		if a.GetVerb() == "update" && a.GetResource().Resource == "certmanagers" && a.GetSubresource() == "" {
			cm := a.(clienttesting.UpdateAction).GetObject().(*v1alpha1.CertManager)
			live, err := f.client.Tracker().Get(v1alpha1.SchemeGroupVersion.WithResource("certmanagers"), "", cm.Name)
			if err != nil {
				return true, nil, err
			}
			cm.Status = live.(*v1alpha1.CertManager).Status
		}
		if a.GetVerb() == "update" && a.GetSubresource() == "status" {
			s := a.(clienttesting.UpdateAction).GetObject().(*v1alpha1.CertManager).Status
			f.trace = append(f.trace, fmt.Sprintf("status:intent=%v,complete=%v", v1helpers.IsOperatorConditionTrue(s.Conditions, v1alpha1.AutoApproverDisableRequested), s.AutoApproverDisabled))
		}
		return false, nil, nil
	})
	f.kube.PrependReactor("*", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if slices.Contains([]string{"create", "update", "patch", "delete"}, a.GetVerb()) {
			f.trace = append(f.trace, a.GetVerb()+":"+a.GetResource().Resource)
		}
		if a.GetVerb() == "create" && a.GetResource().Resource == "deployments" {
			d := a.(clienttesting.CreateAction).GetObject().(*appsv1.Deployment)
			d.Generation = 1
			d.UID = "deployment"
			d.ResourceVersion = "1"
		}
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			d := a.(clienttesting.UpdateAction).GetObject().(*appsv1.Deployment)
			d.Generation++
			d.Status = appsv1.DeploymentStatus{}
		}
		if a.GetVerb() == "create" && a.GetResource().Resource == "events" {
			e := a.(clienttesting.CreateAction).GetObject().(*corev1.Event)
			e.Name = fmt.Sprintf("transition-%d", len(f.trace))
		}
		return false, nil, nil
	})
	f.restart()
	return f
}

// Reconstruct the real controller, including every Deployment hook. Fake API
// clients exercise resourceapply and typed/SSA status writes; they do not model
// workload scheduling or admission, which settle() simulates explicitly.
func (f *handoffFixture) restart() {
	recorder := events.NewInMemoryRecorder("handoff-test", clock.RealClock{})
	op := &operatorclient.OperatorClient{Client: f.client.OperatorV1alpha1(), Informers: f.informers, Clock: clock.RealClock{}}
	f.controller = NewCertManagerControllerDeploymentController(op, f.informers, utils.OptionalInformer[configinformers.SharedInformerFactory]{}, f.kube, f.kubeInformers, recorder, "", nil, "", "", f.client.OperatorV1alpha1())
}
func (f *handoffFixture) cm() *v1alpha1.CertManager {
	f.t.Helper()
	cm, err := f.client.OperatorV1alpha1().CertManagers().Get(context.Background(), "cluster", metav1.GetOptions{})
	require.NoError(f.t, err)
	return cm
}
func (f *handoffFixture) changeCM(fn func(*v1alpha1.CertManager)) {
	f.t.Helper()
	cm := f.cm()
	fn(cm)
	require.NoError(f.t, f.client.Tracker().Update(v1alpha1.SchemeGroupVersion.WithResource("certmanagers"), cm, ""))
}
func (f *handoffFixture) changeManager(fn func(*v1alpha1.ApproverPolicyManager)) {
	f.t.Helper()
	m, err := f.client.OperatorV1alpha1().ApproverPolicyManagers().Get(context.Background(), "cluster", metav1.GetOptions{})
	require.NoError(f.t, err)
	fn(m)
	require.NoError(f.t, f.client.Tracker().Update(v1alpha1.SchemeGroupVersion.WithResource("approverpolicymanagers"), m, ""))
}
func (f *handoffFixture) sync() error {
	f.t.Helper()
	require.NoError(f.t, f.informers.Operator().V1alpha1().CertManagers().Informer().GetStore().Update(f.cm()))
	r := events.NewInMemoryRecorder("test", clock.RealClock{})
	s := factory.NewSyncContext("test", r)
	defer s.Queue().ShutDown()
	return f.controller.Sync(context.Background(), s)
}
func (f *handoffFixture) deployment() *appsv1.Deployment {
	f.t.Helper()
	d, err := f.kube.AppsV1().Deployments("cert-manager").Get(context.Background(), "cert-manager", metav1.GetOptions{})
	require.NoError(f.t, err)
	return d
}
func (f *handoffFixture) putDeployment(d *appsv1.Deployment) {
	f.t.Helper()
	require.NoError(f.t, f.kube.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("deployments"), d, d.Namespace))
}
func (f *handoffFixture) settle() {
	f.t.Helper()
	d := f.deployment()
	n := *d.Spec.Replicas
	d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: n, UpdatedReplicas: n, ReadyReplicas: n, AvailableReplicas: n}
	f.putDeployment(d)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "current", Namespace: d.Namespace, UID: "current-rs", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: ptr.To(true)}}}}
	if err := f.kube.Tracker().Add(rs); apierrors.IsAlreadyExists(err) {
		require.NoError(f.t, f.kube.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("replicasets"), rs, rs.Namespace))
	} else {
		require.NoError(f.t, err)
	}
	for i := range n {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("current-%d", i), Namespace: d.Namespace, Labels: d.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}}}, Spec: *d.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
		if err := f.kube.Tracker().Add(pod); apierrors.IsAlreadyExists(err) {
			require.NoError(f.t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, pod.Namespace))
		} else {
			require.NoError(f.t, err)
		}
	}
}
func (f *handoffFixture) assertRBACAbsent() {
	f.t.Helper()
	_, err := f.kube.RbacV1().ClusterRoles().Get(context.Background(), autoApproverRBACName, metav1.GetOptions{})
	require.True(f.t, apierrors.IsNotFound(err))
	_, err = f.kube.RbacV1().ClusterRoleBindings().Get(context.Background(), autoApproverRBACName, metav1.GetOptions{})
	require.True(f.t, apierrors.IsNotFound(err))
}
func (f *handoffFixture) eventCount(reason string) int {
	f.t.Helper()
	es, err := f.kube.CoreV1().Events(operatorclient.OperatorNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(f.t, err)
	n := 0
	for _, e := range es.Items {
		if e.Reason == reason {
			require.Equal(f.t, "CertManager", e.InvolvedObject.Kind)
			require.Equal(f.t, "cluster", e.InvolvedObject.Name)
			n++
		}
	}
	return n
}
func (f *handoffFixture) overrides(args ...string) {
	f.changeCM(func(cm *v1alpha1.CertManager) {
		raw, err := json.Marshal(map[string]any{"controller": map[string]any{"args": args}})
		require.NoError(f.t, err)
		cm.Spec.UnsupportedConfigOverrides.Raw = raw
		cm.Generation++
	})
}

func TestAutoApproverHandoffAndRestoration(t *testing.T) {
	f := newHandoffFixture(t)
	require.NoError(t, f.sync())
	f.assertRBACAbsent()
	require.False(t, f.cm().Status.AutoApproverDisabled)
	require.Equal(t, []string{"status:intent=true,complete=false", "delete:clusterrolebindings", "delete:clusterroles", "create:deployments"}, f.trace[:4])
	require.Contains(t, f.deployment().Spec.Template.Spec.Containers[0].Args, "--controllers=*,-certificaterequests-approver")
	f.settle()
	require.NoError(t, f.sync())
	require.True(t, f.cm().Status.AutoApproverDisabled)
	require.Equal(t, 1, f.eventCount("AutoApproverDisabled"))
	f.changeManager(func(m *v1alpha1.ApproverPolicyManager) { m.Status.Conditions = nil })
	f.restart()
	require.NoError(t, f.sync())
	f.assertRBACAbsent()
	require.True(t, f.cm().Status.AutoApproverDisabled)
	require.Equal(t, 1, f.eventCount("AutoApproverDisabled"))
	require.NoError(t, f.client.OperatorV1alpha1().ApproverPolicyManagers().Delete(context.Background(), "cluster", metav1.DeleteOptions{}))
	require.NoError(t, f.sync())
	require.True(t, f.cm().Status.AutoApproverDisabled, "restoration must be observed first")
	f.settle()
	require.NoError(t, f.sync())
	require.False(t, disableRequested(f.cm()))
	require.Equal(t, 1, f.eventCount("AutoApproverEnabled"))
	require.NoError(t, f.sync())
	require.Equal(t, 1, f.eventCount("AutoApproverEnabled"))
	for _, a := range f.kube.Actions() {
		if slices.Contains([]string{"create", "update", "patch", "delete"}, a.GetVerb()) {
			require.Contains(t, []string{"deployments", "clusterroles", "clusterrolebindings", "events"}, a.GetResource().Resource)
		}
	}
	for _, path := range certManagerControllerAssetFiles {
		require.NotEqual(t, autoApproverRoleAsset, path)
		require.NotEqual(t, autoApproverBindingAsset, path)
	}
}

func TestAutoApproverOverrideConflict(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		conflict bool
	}{
		{"wildcard", []string{"--controllers=*"}, true},
		{"explicit approver", []string{"--controllers=certificaterequests-approver"}, true},
		{"other exclusion implies defaults", []string{"--controllers=-issuers"}, true},
		{"last override wins conflict", []string{"--controllers=*,-certificaterequests-approver", "--controllers=*"}, true},
		{"bare override", []string{"--controllers", "*"}, true},
		{"invalid CSV", []string{"--controllers=\"unfinished"}, true},
		{"exclusion", []string{"--controllers=*,-certificaterequests-approver"}, false},
		{"other positives", []string{"--controllers=issuers,certificates-trigger"}, false},
		{"last override wins compatible", []string{"--controllers=*", "--controllers=-certificaterequests-approver"}, false},
		{"empty selection", []string{"--controllers="}, false},
		{"unrelated TLS", []string{"--metrics-tls-min-version=VersionTLS10"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHandoffFixture(t)
			f.overrides(tc.args...)
			err := f.sync()
			require.Equal(t, tc.conflict, err != nil, "%v", err)
			f.assertRBACAbsent()
			require.True(t, disableRequested(f.cm()))
			require.False(t, f.cm().Status.AutoApproverDisabled)
			if tc.conflict {
				condition := v1helpers.FindOperatorCondition(f.cm().Status.Conditions, autoApproverDegraded)
				require.NotNil(t, condition)
				require.Equal(t, "ControllerOverrideConflict", condition.Reason)
				_, err := f.kube.AppsV1().Deployments("cert-manager").Get(context.Background(), "cert-manager", metav1.GetOptions{})
				require.True(t, apierrors.IsNotFound(err))
				f.overrides("--controllers=issuers,certificates-trigger")
				require.NoError(t, f.sync())
			} else if tc.name == "unrelated TLS" {
				require.Contains(t, f.deployment().Spec.Template.Spec.Containers[0].Args, tc.args[0])
			}
			f.settle()
			require.NoError(t, f.sync())
			require.True(t, f.cm().Status.AutoApproverDisabled)
			f.overrides("--controllers=*")
			before := f.deployment().DeepCopy()
			require.Error(t, f.sync())
			require.Equal(t, before, f.deployment())
			require.True(t, f.cm().Status.AutoApproverDisabled)
			f.assertRBACAbsent()
		})
	}
}

func TestAutoApproverFailureBarriers(t *testing.T) {
	for _, tc := range []struct {
		name, verb, resource string
		delayed, completion  bool
	}{
		{"intent write", "update", "certmanagers", false, false},
		{"binding delete", "delete", "clusterrolebindings", false, false},
		{"binding read", "get", "clusterrolebindings", false, false},
		{"binding terminating", "delete", "clusterrolebindings", true, false},
		{"role delete", "delete", "clusterroles", false, false},
		{"role read", "get", "clusterroles", false, false},
		{"role terminating", "delete", "clusterroles", true, false},
		{"deployment apply", "create", "deployments", false, false},
		{"completion write", "update", "certmanagers", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHandoffFixture(t)
			if tc.completion {
				require.NoError(t, f.sync())
				f.settle()
			}
			fail := true
			reactor := func(a clienttesting.Action) (bool, runtime.Object, error) {
				if !fail {
					return false, nil, nil
				}
				if tc.resource == "certmanagers" {
					if a.GetSubresource() != "status" {
						return false, nil, nil
					}
					cm := a.(clienttesting.UpdateAction).GetObject().(*v1alpha1.CertManager)
					if tc.completion != cm.Status.AutoApproverDisabled {
						return false, nil, nil
					}
				}
				if tc.delayed {
					return true, nil, nil
				}
				return true, nil, fmt.Errorf("injected %s", tc.name)
			}
			if tc.resource == "certmanagers" {
				f.client.PrependReactor(tc.verb, tc.resource, reactor)
			} else {
				f.kube.PrependReactor(tc.verb, tc.resource, reactor)
			}
			require.Error(t, f.sync())
			require.False(t, f.cm().Status.AutoApproverDisabled)
			require.Zero(t, f.eventCount("AutoApproverDisabled"))
			if tc.name == "intent write" {
				require.NotContains(t, strings.Join(f.trace, ","), "delete:")
			} else {
				require.True(t, disableRequested(f.cm()))
			}
			if tc.resource != "deployments" && !tc.completion {
				_, err := f.kube.AppsV1().Deployments("cert-manager").Get(context.Background(), "cert-manager", metav1.GetOptions{})
				require.True(t, apierrors.IsNotFound(err))
			}
			fail = false
			f.restart()
			require.NoError(t, f.sync())
			f.settle()
			require.NoError(t, f.sync())
			require.True(t, f.cm().Status.AutoApproverDisabled)
			require.Equal(t, 1, f.eventCount("AutoApproverDisabled"))
		})
	}
}

func TestAutoApproverConvergenceEvidence(t *testing.T) {
	for _, name := range []string{"unobserved generation", "replica mismatch", "missing pods", "unready pod", "old pod", "terminating old pod", "pod list failure", "replicaset list failure", "deployment read failure", "completion RBAC read failure"} {
		t.Run(name, func(t *testing.T) {
			f := newHandoffFixture(t)
			require.NoError(t, f.sync())
			f.settle()
			d := f.deployment()
			wantErr := false
			switch name {
			case "unobserved generation":
				d.Status.ObservedGeneration--
				f.putDeployment(d)
			case "replica mismatch":
				d.Status.AvailableReplicas = 0
				f.putDeployment(d)
			case "missing pods":
				require.NoError(t, f.kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), "cert-manager", "current-0"))
			case "unready pod":
				p, err := f.kube.CoreV1().Pods("cert-manager").Get(context.Background(), "current-0", metav1.GetOptions{})
				require.NoError(t, err)
				p.Status.Conditions = nil
				require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), p, p.Namespace))
			case "old pod", "terminating old pod":
				rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: d.Namespace, UID: "old-rs", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: ptr.To(true)}}}}
				require.NoError(t, f.kube.Tracker().Add(rs))
				p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: d.Namespace, Labels: map[string]string{"old": "labels"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "old", UID: rs.UID, Controller: ptr.To(true)}}}, Spec: *d.Spec.Template.Spec.DeepCopy()}
				p.Spec.Containers[0].Args = []string{"--controllers=*"}
				if name == "terminating old pod" {
					p.DeletionTimestamp = ptr.To(metav1.Now())
				}
				require.NoError(t, f.kube.Tracker().Add(p))
			default:
				wantErr = true
				verb, resource := "list", "pods"
				if name == "replicaset list failure" {
					resource = "replicasets"
				}
				if name == "deployment read failure" {
					verb, resource = "get", "deployments"
				}
				if name == "completion RBAC read failure" {
					verb, resource = "get", "clusterroles"
				}
				reads := 0
				f.kube.PrependReactor(verb, resource, func(clienttesting.Action) (bool, runtime.Object, error) {
					reads++
					if name == "completion RBAC read failure" && reads == 1 {
						return false, nil, nil
					}
					return true, nil, fmt.Errorf("evidence unavailable")
				})
			}
			err := f.sync()
			require.Equal(t, wantErr, err != nil, "%v", err)
			require.False(t, f.cm().Status.AutoApproverDisabled)
			require.True(t, disableRequested(f.cm()))
			require.Zero(t, f.eventCount("AutoApproverDisabled"))
		})
	}
}

func TestAutoApproverPresenceAndRecovery(t *testing.T) {
	for _, name := range []string{"not ready", "stale ready", "deleting before intent", "absent before intent", "unmanaged", "removed", "deleting after intent", "readiness loss", "forbidden", "endpoint missing", "transport error", "restoration role failure", "restoration binding failure", "RBAC drift after completion"} {
		t.Run(name, func(t *testing.T) {
			f := newHandoffFixture(t)
			retained := !slices.Contains([]string{"not ready", "stale ready", "deleting before intent", "absent before intent", "unmanaged", "removed"}, name)
			if retained {
				require.NoError(t, f.sync())
				if name == "RBAC drift after completion" {
					f.settle()
					require.NoError(t, f.sync())
					require.True(t, f.cm().Status.AutoApproverDisabled)
				}
			}
			wantErr := false
			switch name {
			case "not ready", "readiness loss":
				f.changeManager(func(m *v1alpha1.ApproverPolicyManager) { m.Status.Conditions = nil })
			case "stale ready":
				f.changeManager(func(m *v1alpha1.ApproverPolicyManager) { m.Generation++ })
			case "deleting before intent", "deleting after intent":
				f.changeManager(func(m *v1alpha1.ApproverPolicyManager) { m.DeletionTimestamp = ptr.To(metav1.Now()) })
			case "absent before intent":
				require.NoError(t, f.client.Tracker().Delete(v1alpha1.SchemeGroupVersion.WithResource("approverpolicymanagers"), "", "cluster"))
			case "unmanaged":
				f.changeCM(func(cm *v1alpha1.CertManager) { cm.Spec.ManagementState = operatorv1.Unmanaged })
			case "removed":
				f.changeCM(func(cm *v1alpha1.CertManager) { cm.Spec.ManagementState = operatorv1.Removed })
			case "forbidden", "endpoint missing", "transport error":
				wantErr = true
				err := fmt.Errorf("transport unavailable")
				if name == "forbidden" {
					err = apierrors.NewForbidden(v1alpha1.SchemeGroupVersion.WithResource("approverpolicymanagers").GroupResource(), "cluster", err)
				}
				if name == "endpoint missing" {
					err = apierrors.NewNotFound(schema.GroupResource{}, "")
				}
				f.client.PrependReactor("get", "approverpolicymanagers", func(clienttesting.Action) (bool, runtime.Object, error) { return true, nil, err })
			case "restoration role failure", "restoration binding failure":
				wantErr = true
				require.NoError(t, f.client.Tracker().Delete(v1alpha1.SchemeGroupVersion.WithResource("approverpolicymanagers"), "", "cluster"))
				resource := "clusterroles"
				if name == "restoration binding failure" {
					resource = "clusterrolebindings"
				}
				f.kube.PrependReactor("create", resource, func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("restoration denied")
				})
			case "RBAC drift after completion":
				require.NoError(t, f.kube.Tracker().Add(resourceread.ReadClusterRoleBindingV1OrDie(assets.MustAsset(autoApproverBindingAsset))))
			}
			f.restart()
			err := f.sync()
			require.Equal(t, wantErr, err != nil, "%v", err)
			if retained {
				require.True(t, disableRequested(f.cm()))
				if !strings.HasPrefix(name, "restoration") {
					f.assertRBACAbsent()
				}
			} else {
				require.False(t, disableRequested(f.cm()))
			}
			if name == "unmanaged" || name == "removed" {
				for _, a := range f.kube.Actions() {
					require.False(t, a.GetVerb() == "create" && a.GetResource().Resource == "deployments")
				}
			}
		})
	}
}

func TestAutoApproverControllerSelection(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		enabled bool
		invalid bool
	}{
		{nil, true, false}, {[]string{"--controllers="}, false, false}, {[]string{"--controllers=*"}, true, false},
		{[]string{"--controllers=issuers"}, false, false}, {[]string{"--controllers=-issuers"}, true, false},
		{[]string{"--controllers", "*,-certificaterequests-approver"}, false, false},
		{[]string{"--controllers=-certificaterequests-approver", "--controllers=certificaterequests-approver"}, false, false},
		{[]string{"--controllers"}, false, true}, {[]string{"--controllers=*, issuers"}, false, true},
	} {
		t.Run(fmt.Sprint(tc.args), func(t *testing.T) {
			values, present, err := controllerSelection(tc.args)
			require.Equal(t, tc.invalid, err != nil)
			if err == nil {
				require.Equal(t, tc.enabled, autoApproverEnabled(values, present))
			}
		})
	}
}

func TestAutoApproverRestorationFailureRecovery(t *testing.T) {
	for _, scenario := range []string{
		"role create", "binding create", "role observation", "binding observation",
		"deployment update", "rollout pending", "completion write", "manager before restore",
		"manager before completion", "manager read uncertain", "endpoint missing", "terminating manager",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := newHandoffFixture(t)
			require.NoError(t, f.sync())
			f.settle()
			require.NoError(t, f.sync())
			require.True(t, f.cm().Status.AutoApproverDisabled)
			managerResource := v1alpha1.SchemeGroupVersion.WithResource("approverpolicymanagers")
			if scenario == "terminating manager" {
				f.changeManager(func(m *v1alpha1.ApproverPolicyManager) {
					m.DeletionTimestamp = ptr.To(metav1.Now())
					m.Finalizers = []string{"operator.openshift.io/approver-policy-cleanup"}
				})
			} else {
				require.NoError(t, f.client.Tracker().Delete(managerResource, "", "cluster"))
			}
			atCompletion := slices.Contains([]string{"role observation", "binding observation", "completion write", "manager before completion"}, scenario)
			if atCompletion {
				require.NoError(t, f.sync())
				f.settle()
			}
			fail, managerReads, roleReads := true, 0, 0
			f.client.PrependReactor("get", "approverpolicymanagers", func(clienttesting.Action) (bool, runtime.Object, error) {
				if !fail {
					return false, nil, nil
				}
				managerReads++
				if scenario == "manager read uncertain" {
					return true, nil, fmt.Errorf("presence unavailable")
				}
				if scenario == "endpoint missing" {
					return true, nil, apierrors.NewNotFound(schema.GroupResource{}, "")
				}
				if (scenario == "manager before restore" && managerReads == 2) || (scenario == "manager before completion" && managerReads == 3) {
					replacement := &v1alpha1.ApproverPolicyManager{ObjectMeta: metav1.ObjectMeta{Name: "cluster", UID: "replacement", Generation: 1}}
					require.NoError(t, f.client.Tracker().Add(replacement))
					return true, replacement, nil
				}
				return false, nil, nil
			})
			f.client.PrependReactor("update", "certmanagers", func(a clienttesting.Action) (bool, runtime.Object, error) {
				if fail && scenario == "completion write" && a.GetSubresource() == "status" && !a.(clienttesting.UpdateAction).GetObject().(*v1alpha1.CertManager).Status.AutoApproverDisabled {
					return true, nil, fmt.Errorf("completion unavailable")
				}
				return false, nil, nil
			})
			f.kube.PrependReactor("*", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
				if !fail {
					return false, nil, nil
				}
				resource, verb := a.GetResource().Resource, a.GetVerb()
				if (scenario == "role create" && resource == "clusterroles" && verb == "create") ||
					(scenario == "binding create" && resource == "clusterrolebindings" && verb == "create") ||
					(scenario == "deployment update" && resource == "deployments" && verb == "update") {
					return true, nil, fmt.Errorf("restore write unavailable")
				}
				if verb == "get" && ((scenario == "role observation" && resource == "clusterroles") || (scenario == "binding observation" && resource == "clusterrolebindings")) {
					roleReads++
					if roleReads == 2 {
						return true, nil, fmt.Errorf("restored RBAC cannot be confirmed")
					}
				}
				return false, nil, nil
			})
			f.restart()
			err := f.sync()
			if scenario == "terminating manager" || scenario == "rollout pending" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.True(t, f.cm().Status.AutoApproverDisabled, "incomplete restoration retains completion latch")
			require.True(t, disableRequested(f.cm()), "durable recovery intent must survive every failure")
			require.Zero(t, f.eventCount("AutoApproverEnabled"))
			if slices.Contains([]string{"terminating manager", "manager before restore", "manager read uncertain", "endpoint missing"}, scenario) {
				f.assertRBACAbsent()
			}
			if strings.HasSuffix(scenario, "observation") {
				require.Equal(t, 2, roleReads)
			}
			fail = false
			if err := f.client.Tracker().Delete(managerResource, "", "cluster"); err != nil {
				require.True(t, apierrors.IsNotFound(err))
			}
			f.restart()
			require.NoError(t, f.sync())
			f.settle()
			require.NoError(t, f.sync())
			require.False(t, f.cm().Status.AutoApproverDisabled)
			require.False(t, disableRequested(f.cm()))
			require.Equal(t, 1, f.eventCount("AutoApproverEnabled"))
			f.restart()
			require.NoError(t, f.sync())
			require.Equal(t, 1, f.eventCount("AutoApproverEnabled"), "steady restoration must not repeat completion events")
			for _, action := range f.kube.Actions() {
				if slices.Contains([]string{"create", "update", "patch", "delete"}, action.GetVerb()) {
					require.Contains(t, []string{"deployments", "clusterroles", "clusterrolebindings", "events"}, action.GetResource().Resource)
				}
			}
		})
	}
}
