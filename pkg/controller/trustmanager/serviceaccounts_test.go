package trustmanager

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/pkg/controller/trustmanager/fakes"
)

func TestCreateOrApplyServiceAccount_CreateNew(t *testing.T) {
	// Setup
	fakeClient := &fakes.FakeCtrlClient{}
	r := testReconciler(t)
	r.ctrlClient = fakeClient

	trustManager := testTrustManager()
	labels := testResourceLabels()

	// Mock: ServiceAccount does not exist
	fakeClient.ExistsReturns(false, nil)

	// Execute
	err := r.createOrApplyServiceAccount(trustManager, labels, true)

	// Verify
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Verify Exists was called
	if fakeClient.ExistsCallCount() != 1 {
		t.Errorf("expected Exists to be called once, got %d", fakeClient.ExistsCallCount())
	}

	// Verify Create was called
	if fakeClient.CreateCallCount() != 1 {
		t.Errorf("expected Create to be called once, got %d", fakeClient.CreateCallCount())
	}

	// Verify the created object is a ServiceAccount
	_, createdObj, _ := fakeClient.CreateArgsForCall(0)
	if _, ok := createdObj.(*corev1.ServiceAccount); !ok {
		t.Errorf("expected ServiceAccount to be created, got %T", createdObj)
	}
}

func TestCreateOrApplyServiceAccount_AlreadyExists(t *testing.T) {
	// Setup
	fakeClient := &fakes.FakeCtrlClient{}
	r := testReconciler(t)
	r.ctrlClient = fakeClient

	trustManager := testTrustManager()
	labels := testResourceLabels()

	// Mock: ServiceAccount exists
	existingSA := testServiceAccount()
	fakeClient.ExistsStub = func(_ context.Context, _ client.ObjectKey, obj client.Object) (bool, error) {
		// Copy existing SA into the passed object
		existingSA.DeepCopyInto(obj.(*corev1.ServiceAccount))
		return true, nil
	}

	// Execute - not a new reconcile
	err := r.createOrApplyServiceAccount(trustManager, labels, false)

	// Verify
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Verify Create was NOT called (resource exists)
	if fakeClient.CreateCallCount() != 0 {
		t.Errorf("expected Create not to be called, got %d calls", fakeClient.CreateCallCount())
	}

	// Verify Update was NOT called (no changes)
	if fakeClient.UpdateCallCount() != 0 {
		t.Errorf("expected Update not to be called, got %d calls", fakeClient.UpdateCallCount())
	}
}

func TestCreateOrApplyServiceAccount_ExistsError(t *testing.T) {
	// Setup
	fakeClient := &fakes.FakeCtrlClient{}
	r := testReconciler(t)
	r.ctrlClient = fakeClient

	trustManager := testTrustManager()
	labels := testResourceLabels()

	// Mock: Error checking existence
	fakeClient.ExistsReturns(false, testError)

	// Execute
	err := r.createOrApplyServiceAccount(trustManager, labels, true)

	// Verify error is returned
	if err == nil {
		t.Error("expected error, got nil")
	}

	// Verify Create was NOT called
	if fakeClient.CreateCallCount() != 0 {
		t.Errorf("expected Create not to be called, got %d calls", fakeClient.CreateCallCount())
	}
}

func TestCreateOrApplyServiceAccount_CreateError(t *testing.T) {
	// Setup
	fakeClient := &fakes.FakeCtrlClient{}
	r := testReconciler(t)
	r.ctrlClient = fakeClient

	trustManager := testTrustManager()
	labels := testResourceLabels()

	// Mock: ServiceAccount does not exist, but create fails
	fakeClient.ExistsReturns(false, nil)
	fakeClient.CreateReturns(testError)

	// Execute
	err := r.createOrApplyServiceAccount(trustManager, labels, true)

	// Verify error is returned
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetServiceAccountObject(t *testing.T) {
	r := testReconciler(t)
	trustManager := testTrustManager()
	labels := testResourceLabels()

	sa := r.getServiceAccountObject(trustManager, labels)

	// Verify namespace is set to cert-manager
	if sa.GetNamespace() != operandNamespace {
		t.Errorf("expected namespace %q, got %q", operandNamespace, sa.GetNamespace())
	}

	// Verify labels are set
	saLabels := sa.GetLabels()
	for k, v := range labels {
		if saLabels[k] != v {
			t.Errorf("expected label %q=%q, got %q", k, v, saLabels[k])
		}
	}
}

