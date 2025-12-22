package trustmanager

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// =============================================================================
// CLIENT WRAPPER OVERVIEW
// =============================================================================
//
// Why wrap the controller-runtime client?
//
// 1. TESTABILITY: The interface allows us to mock the client in unit tests
//    using tools like counterfeiter or mockgen.
//
// 2. RETRY LOGIC: Kubernetes uses optimistic locking (resourceVersion).
//    When two controllers try to update the same resource, one gets a
//    "conflict" error. UpdateWithRetry handles this automatically.
//
// 3. HELPER METHODS: Common patterns like "check if exists" are encapsulated.
//
// 4. CONSISTENT ERROR HANDLING: All methods return errors in a consistent way.
//
// =============================================================================

// =============================================================================
// CLIENT INTERFACE
// =============================================================================
// ctrlClient defines the operations our controller needs from the Kubernetes API.
// By defining an interface, we can:
// - Mock it in tests
// - Swap implementations if needed
// - Document exactly what operations we use
//
//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate -o fakes . ctrlClient
type ctrlClient interface {
	// Get retrieves a single resource by namespace/name.
	// Returns error if not found or other API error.
	Get(ctx context.Context, key client.ObjectKey, obj client.Object) error

	// List retrieves multiple resources matching the given options.
	// Options can include label selectors, field selectors, namespace, etc.
	List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error

	// Create creates a new resource.
	// Returns AlreadyExists error if resource already exists.
	Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error

	// Update updates an existing resource.
	// Requires correct resourceVersion (optimistic locking).
	// Use UpdateWithRetry for automatic conflict handling.
	Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error

	// UpdateWithRetry updates a resource with automatic retry on conflicts.
	// This is the preferred method for updates in reconcilers.
	UpdateWithRetry(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error

	// Delete removes a resource.
	// For resources with finalizers, this sets deletionTimestamp.
	Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error

	// Patch applies a partial update to a resource.
	// More efficient than Update when changing only a few fields.
	Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error

	// StatusUpdate updates only the status subresource.
	// This is separate from spec updates and has its own resourceVersion.
	StatusUpdate(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error

	// Exists checks if a resource exists without returning NotFound errors.
	// Returns (true, nil) if exists, (false, nil) if not found, (false, err) on error.
	Exists(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error)
}

// =============================================================================
// CLIENT IMPLEMENTATION
// =============================================================================
// ctrlClientImpl wraps controller-runtime's client.Client.
// It embeds the Client interface to inherit all its methods,
// then overrides or adds methods as needed.
type ctrlClientImpl struct {
	client.Client
}

// NewClient creates a new client wrapper using the manager's client.
//
// Why use the manager's client?
// - The manager's client is connected to the manager's cache
// - This ensures reads come from the same cache that watches use
// - Prevents "cache mismatch" issues where we read stale data
//
// Example:
//
//	func SetupWithManager(mgr manager.Manager) error {
//	    client, err := NewClient(mgr)
//	    if err != nil {
//	        return err
//	    }
//	    reconciler := &Reconciler{client: client}
//	    // ...
//	}
func NewClient(m manager.Manager) (ctrlClient, error) {
	return &ctrlClientImpl{
		Client: m.GetClient(),
	}, nil
}

// =============================================================================
// BASIC OPERATIONS
// =============================================================================
// These methods are thin wrappers around the embedded client.
// They exist to satisfy the interface and enable mocking.

func (c *ctrlClientImpl) Get(ctx context.Context, key client.ObjectKey, obj client.Object) error {
	return c.Client.Get(ctx, key, obj)
}

func (c *ctrlClientImpl) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.Client.List(ctx, list, opts...)
}

func (c *ctrlClientImpl) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return c.Client.Create(ctx, obj, opts...)
}

func (c *ctrlClientImpl) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return c.Client.Update(ctx, obj, opts...)
}

func (c *ctrlClientImpl) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	return c.Client.Delete(ctx, obj, opts...)
}

func (c *ctrlClientImpl) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *ctrlClientImpl) StatusUpdate(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	return c.Client.Status().Update(ctx, obj, opts...)
}

// =============================================================================
// ADVANCED OPERATIONS
// =============================================================================

// UpdateWithRetry updates a resource with automatic retry on conflict errors.
//
// How Kubernetes Optimistic Locking Works:
// 1. Every resource has a `resourceVersion` field
// 2. When you update, you must send the current resourceVersion
// 3. If someone else updated the resource, the version changed
// 4. Your update fails with a "Conflict" (409) error
// 5. You must fetch the latest version and retry
//
// This method automates that retry loop:
// 1. Get the latest version of the resource
// 2. Copy the resourceVersion to the object being updated
// 3. Attempt the update
// 4. If conflict, repeat from step 1
//
// The retry.DefaultRetry uses exponential backoff with jitter.
func (c *ctrlClientImpl) UpdateWithRetry(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	key := client.ObjectKeyFromObject(obj)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Create a new instance of the same type to fetch current state.
		// We use reflection because we don't know the concrete type at compile time.
		//
		// reflect.TypeOf(obj) returns *SomeType
		// .Elem() returns SomeType
		// reflect.New() returns *SomeType (a new zero instance)
		// .Interface().(client.Object) converts back to client.Object
		current := reflect.New(reflect.TypeOf(obj).Elem()).Interface().(client.Object)

		// Fetch the latest version from the API server
		if err := c.Client.Get(ctx, key, current); err != nil {
			return fmt.Errorf("failed to fetch latest %q for update: %w", key, err)
		}

		// Copy the resourceVersion to our object
		// This tells the API server which version we're updating from
		obj.SetResourceVersion(current.GetResourceVersion())

		// Attempt the update
		if err := c.Client.Update(ctx, obj, opts...); err != nil {
			return fmt.Errorf("failed to update %q resource: %w", key, err)
		}

		return nil
	})
}

// Exists checks if a resource exists in the cluster.
//
// This is a common pattern in controllers:
// - Check if resource exists
// - If not, create it
// - If yes, maybe update it
//
// Returns:
// - (true, nil): Resource exists, obj is populated with its data
// - (false, nil): Resource does not exist (NotFound error)
// - (false, error): Some other error occurred (network, permission, etc.)
//
// Example:
//
//	exists, err := c.Exists(ctx, key, deployment)
//	if err != nil {
//	    return err
//	}
//	if !exists {
//	    return c.Create(ctx, desiredDeployment)
//	}
//	// Update existing deployment...
func (c *ctrlClientImpl) Exists(ctx context.Context, key client.ObjectKey, obj client.Object) (bool, error) {
	if err := c.Client.Get(ctx, key, obj); err != nil {
		if errors.IsNotFound(err) {
			// Not found is not an error condition - resource just doesn't exist
			return false, nil
		}
		// Real error (network, permissions, etc.)
		return false, err
	}
	// Resource exists and obj is now populated with its data
	return true, nil
}
