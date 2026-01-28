package platformutil

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"

	operatorv1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/clientset/versioned/fake"
)

func createFakeClient(isResourcePresent bool) *fake.Clientset {
	if !isResourcePresent {
		return fake.NewClientset()
	}

	fakeClient := fake.NewClientset(&operatorv1alpha1.CertManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: operatorv1alpha1.CertManagerStatus{},
	})

	// the fake client set does not populate API resource list by default
	// which is required to make a fake discovery call
	fakeClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: operatorv1alpha1.SchemeGroupVersion.String(),
			APIResources: []metav1.APIResource{
				{
					Name:         "certmanagers",
					SingularName: "certmanager",
					Namespaced:   false,
					Group:        operatorv1alpha1.SchemeGroupVersion.Group,
					Version:      operatorv1alpha1.SchemeGroupVersion.Version,
					Kind:         "CertManager",
					Verbs:        []string{"get", "list", "create", "update", "patch", "watch", "delete"},
				},
			},
		},
	}

	return fakeClient
}

type alwaysErrorFakeDiscovery struct {
	fakediscovery.FakeDiscovery
}

// ServerResourcesForGroupVersion is the only func that discovery client calls.
func (f *alwaysErrorFakeDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	return nil, fmt.Errorf("expected foo error")
}

func createErroneousFakeDiscoveryClient() discovery.DiscoveryInterface {
	return &alwaysErrorFakeDiscovery{}
}

// createFakeDiscoveryWithResources creates a fake discovery client with the specified API resources.
// Pass nil or empty slice for a discovery client with no resources.
func createFakeDiscoveryWithResources(resources []*metav1.APIResourceList) *fakediscovery.FakeDiscovery {
	fake := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}
	fake.Resources = resources
	return fake
}
