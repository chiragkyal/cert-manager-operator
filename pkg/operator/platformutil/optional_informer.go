package platformutil

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// OptionalInformer creates an informer only if the required CRD is present on the cluster.
// This is useful for optional features that depend on CRDs that may not be installed.
type OptionalInformer[GroupInformer any] struct {
	gvr       schema.GroupVersionResource
	discovery *ResourceDiscovery

	InformerFactory *GroupInformer
}

// NewOptionalInformer creates a new OptionalInformer.
// If the CRD specified by gvr exists, the informerInitFunc is called to create the informer.
// If the CRD doesn't exist, no informer is created and Applicable() returns false.
func NewOptionalInformer[groupInformer any](
	ctx context.Context,
	gvr schema.GroupVersionResource,
	discoveryClient discovery.DiscoveryInterface,
	informerInitFunc func() groupInformer,
) (*OptionalInformer[groupInformer], error) {
	o := &OptionalInformer[groupInformer]{
		gvr:       gvr,
		discovery: NewResourceDiscovery(discoveryClient),
	}

	discovered, err := o.discover()
	if err != nil {
		return nil, err
	}

	if discovered {
		informer := informerInitFunc()
		o.InformerFactory = &informer
	}

	return o, nil
}

// Applicable returns true if the CRD was discovered and an informer was created.
func (o *OptionalInformer[GroupInformer]) Applicable() bool {
	return o.InformerFactory != nil
}

// discover checks if the required CRD is present on the cluster.
func (o *OptionalInformer[GroupInformer]) discover() (bool, error) {
	return o.discovery.ResourceExists(o.gvr)
}
