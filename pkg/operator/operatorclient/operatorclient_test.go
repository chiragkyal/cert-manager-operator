package operatorclient

import (
	"context"
	"fmt"
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	operatorfake "github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned/fake"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
)

func statusFixture() *v1alpha1.CertManager {
	return &v1alpha1.CertManager{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster", UID: "original", Generation: 1, ResourceVersion: "1"},
		Status: v1alpha1.CertManagerStatus{OperatorStatus: operatorv1.OperatorStatus{
			ObservedGeneration: 1,
			Generations:        []operatorv1.GenerationStatus{{Group: "apps", Resource: "deployments", Namespace: "cert-manager", Name: "cert-manager", LastGeneration: 3}},
			Conditions:         []operatorv1.OperatorCondition{{Type: "OtherControllerAvailable", Status: operatorv1.ConditionTrue, Reason: "AsExpected"}},
		}},
	}
}

func TestUpdateCertManagerStatus(t *testing.T) {
	for _, tc := range []struct {
		name                                                      string
		initial, desired                                          bool
		conflict, replacement, specChanged, getError, updateError bool
	}{
		{name: "initial completion", desired: true},
		{name: "completion retained", initial: true, desired: true},
		{name: "restore completion", initial: true},
		{name: "omitted completion"},
		{name: "conflict preserves another writer", desired: true, conflict: true},
		{name: "replacement requires reconciliation", desired: true, replacement: true},
		{name: "spec change requires reconciliation", desired: true, specChanged: true},
		{name: "read failure", desired: true, getError: true},
		{name: "write failure", desired: true, updateError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			original := statusFixture()
			original.Status.AutoApproverDisabled = tc.initial
			live := original.DeepCopy()
			if tc.replacement {
				live.UID = "replacement"
			}
			if tc.specChanged {
				live.Generation++
			}
			client := operatorfake.NewClientset(live)
			updates := 0
			if tc.getError {
				client.PrependReactor("get", "certmanagers", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("read unavailable")
				})
			}
			client.PrependReactor("update", "certmanagers", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if action.GetSubresource() != "status" {
					t.Fatal("expected status update")
				}
				updates++
				if tc.updateError {
					return true, nil, fmt.Errorf("write unavailable")
				}
				if tc.conflict && updates == 1 {
					live.ResourceVersion = "2"
					live.Status.ObservedGeneration = 7
					live.Status.Conditions = append(live.Status.Conditions, operatorv1.OperatorCondition{Type: "Concurrent", Status: operatorv1.ConditionTrue})
					if err := client.Tracker().Update(v1alpha1.SchemeGroupVersion.WithResource("certmanagers"), live, ""); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewConflict(v1alpha1.SchemeGroupVersion.WithResource("certmanagers").GroupResource(), "cluster", fmt.Errorf("concurrent write"))
				}
				return false, nil, nil
			})
			c := OperatorClient{Client: client.OperatorV1alpha1()}
			changed, err := c.UpdateCertManagerStatus(ctx, original, func(s *v1alpha1.CertManagerStatus) { s.AutoApproverDisabled = tc.desired })
			wantError := tc.replacement || tc.specChanged || tc.getError || tc.updateError
			if (err != nil) != wantError {
				t.Fatalf("error = %v, want error %v", err, wantError)
			}
			if wantError {
				if changed {
					t.Fatal("failed write reported changed")
				}
				if !tc.updateError && updates != 0 {
					t.Fatal("mutated status without valid observation")
				}
				return
			}
			if changed != (tc.initial != tc.desired) {
				t.Fatalf("changed = %v", changed)
			}
			if !changed && updates != 0 {
				t.Fatal("no-op wrote status")
			}
			got, err := client.OperatorV1alpha1().CertManagers().Get(ctx, "cluster", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status.AutoApproverDisabled != tc.desired || len(got.Status.Generations) != 1 || got.Status.Generations[0].LastGeneration != 3 || got.Status.Conditions[0].Type != "OtherControllerAvailable" {
				t.Fatalf("status not preserved: %+v", got.Status)
			}
			if tc.conflict && (updates != 2 || got.Status.ObservedGeneration != 7 || len(got.Status.Conditions) != 2) {
				t.Fatalf("concurrent status lost: %+v", got.Status)
			}
		})
	}
}

func TestUpdateOperatorStatusPreservesCompletion(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%v", stale), func(t *testing.T) {
			cm := statusFixture()
			cm.Status.AutoApproverDisabled = true
			client := operatorfake.NewClientset(cm)
			c := OperatorClient{Client: client.OperatorV1alpha1()} // Deliberately no informer: use the live object.
			status := cm.Status.OperatorStatus.DeepCopy()
			status.ObservedGeneration = 2
			rv := cm.ResourceVersion
			if stale {
				rv = "0"
			}
			_, err := c.UpdateOperatorStatus(context.Background(), rv, status)
			if stale {
				if !apierrors.IsConflict(err) {
					t.Fatalf("expected conflict, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			got, _ := client.OperatorV1alpha1().CertManagers().Get(context.Background(), "cluster", metav1.GetOptions{})
			if !got.Status.AutoApproverDisabled {
				t.Fatal("custom completion lost")
			}
			if stale && got.Status.ObservedGeneration != 1 {
				t.Fatal("stale update accepted")
			}
			if !stale && got.Status.ObservedGeneration != 2 {
				t.Fatal("embedded status not updated")
			}
		})
	}
}

func TestApplyOperatorStatusPreservesCompletion(t *testing.T) {
	ctx := context.Background()
	cm := statusFixture()
	cm.Status.AutoApproverDisabled = true
	client := operatorfake.NewClientset(cm)
	c := OperatorClient{Client: client.OperatorV1alpha1(), Clock: clock.RealClock{}}
	for _, value := range []operatorv1.ConditionStatus{operatorv1.ConditionFalse, operatorv1.ConditionTrue} {
		desired := applyoperatorv1.OperatorStatus().WithConditions(applyoperatorv1.OperatorCondition().WithType("DeploymentAvailable").WithStatus(value).WithReason("Observed"))
		if err := c.ApplyOperatorStatus(ctx, "deployment-controller", desired); err != nil {
			t.Fatal(err)
		}
		got, err := client.OperatorV1alpha1().CertManagers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !got.Status.AutoApproverDisabled || len(got.Status.Generations) != 1 {
			t.Fatalf("independent status lost: %+v", got.Status)
		}
	}
}
