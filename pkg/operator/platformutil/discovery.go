package platformutil

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// ResourceDiscovery provides methods to check if resources exist on the cluster
type ResourceDiscovery struct {
	discoveryClient discovery.DiscoveryInterface
}

// NewResourceDiscovery creates a new ResourceDiscovery
func NewResourceDiscovery(discoveryClient discovery.DiscoveryInterface) *ResourceDiscovery {
	return &ResourceDiscovery{
		discoveryClient: discoveryClient,
	}
}

// ResourceExists checks if a resource with the given GVR exists on the cluster.
// Returns true if the resource exists, false if it doesn't exist or the API group is not found.
func (r *ResourceDiscovery) ResourceExists(gvr schema.GroupVersionResource) (bool, error) {
	resources, err := r.discoveryClient.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to discover %s resource: %w", gvr.String(), err)
	}

	for _, res := range resources.APIResources {
		if res.Name == gvr.Resource {
			return true, nil
		}
	}

	return false, nil
}
