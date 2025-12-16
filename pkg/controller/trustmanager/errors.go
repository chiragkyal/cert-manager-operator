package trustmanager

import (
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// =============================================================================
// ERROR REASONS
// =============================================================================
// ErrorReason categorizes errors to help the controller decide how to respond.
// This is a key concept in Kubernetes controllers:
//
// - Some errors are temporary (network issues, conflicts) → retry later
// - Some errors are permanent (invalid config, missing permissions) → don't retry
//
// By categorizing errors, we can:
// 1. Avoid wasting resources retrying unrecoverable errors
// 2. Provide better status conditions to users
// 3. Log appropriate severity levels
type ErrorReason string

const (
	// IrrecoverableError indicates the error cannot be fixed by retrying.
	// Examples:
	// - Invalid configuration (missing required fields)
	// - Permission denied (RBAC issues)
	// - Resource validation failed
	//
	// Controller behavior: Sets Degraded condition, does NOT requeue
	IrrecoverableError ErrorReason = "IrrecoverableError"

	// RetryRequiredError indicates the error might resolve with a retry.
	// Examples:
	// - Network timeout
	// - Resource conflict (optimistic locking)
	// - Temporary API server unavailability
	//
	// Controller behavior: Requeues after defaultRequeueTime
	RetryRequiredError ErrorReason = "RetryRequiredError"
)

// =============================================================================
// RECONCILE ERROR TYPE
// =============================================================================
// ReconcileError wraps errors with additional context for the controller.
// It implements the standard error interface so it can be used like any error.
type ReconcileError struct {
	// Reason categorizes the error for controller decision making
	Reason ErrorReason `json:"reason,omitempty"`

	// Message provides human-readable context about what operation failed
	Message string `json:"message,omitempty"`

	// Err is the underlying error that caused the failure
	Err error `json:"error,omitempty"`
}

// Ensure ReconcileError implements the error interface at compile time.
// This is a common Go pattern: var _ interface = (*Type)(nil)
// If ReconcileError doesn't implement error, this won't compile.
var _ error = &ReconcileError{}

// =============================================================================
// ERROR CONSTRUCTORS
// =============================================================================
// These factory functions create properly categorized errors.
// Using constructors instead of struct literals ensures consistency.

// NewIrrecoverableError creates an error that won't be retried.
// Use this when:
// - Configuration is invalid
// - Required resources are missing and won't appear
// - Permissions are insufficient
//
// Example:
//
//	if config.Required == "" {
//	    return NewIrrecoverableError(nil, "required field is empty")
//	}
func NewIrrecoverableError(err error, message string, args ...any) *ReconcileError {
	// If no underlying error, still create the ReconcileError with the message
	if err == nil {
		err = errors.New("irrecoverable error occurred")
	}
	return &ReconcileError{
		Reason:  IrrecoverableError,
		Message: fmt.Sprintf(message, args...),
		Err:     err,
	}
}

// NewRetryRequiredError creates an error that should be retried.
// Use this when:
// - Network operations fail temporarily
// - Resource conflicts occur
// - Dependencies aren't ready yet
//
// Example:
//
//	deployment, err := client.Get(...)
//	if err != nil {
//	    return NewRetryRequiredError(err, "failed to get deployment")
//	}
func NewRetryRequiredError(err error, message string, args ...any) *ReconcileError {
	if err == nil {
		return nil
	}
	return &ReconcileError{
		Reason:  RetryRequiredError,
		Message: fmt.Sprintf(message, args...),
		Err:     err,
	}
}

// =============================================================================
// ERROR CLASSIFICATION HELPERS
// =============================================================================
// These helpers analyze Kubernetes API errors to determine if they're recoverable.

// FromClientError analyzes a Kubernetes API error and returns the appropriate
// ReconcileError type.
//
// Irrecoverable API errors (won't succeed on retry):
// - Unauthorized (401): Authentication failed
// - Forbidden (403): RBAC denies the operation
// - Invalid (422): Resource validation failed
// - BadRequest (400): Malformed request
// - ServiceUnavailable (503): Server is overloaded (could be temp, but treated as fatal)
//
// Recoverable API errors (may succeed on retry):
// - NotFound (404): Resource might be created soon
// - Conflict (409): Optimistic locking, retry with fresh data
// - Timeout (504): Temporary network issue
// - InternalError (500): Server-side issue, might resolve
func FromClientError(err error, message string, args ...any) *ReconcileError {
	if err == nil {
		return nil
	}

	// These errors indicate fundamental problems that won't be fixed by retrying
	if apierrors.IsUnauthorized(err) ||
		apierrors.IsForbidden(err) ||
		apierrors.IsInvalid(err) ||
		apierrors.IsBadRequest(err) ||
		apierrors.IsServiceUnavailable(err) {
		return NewIrrecoverableError(err, message, args...)
	}

	// All other errors might be temporary, so we'll retry
	return NewRetryRequiredError(err, message, args...)
}

// FromError wraps any error, preserving its reason if it's already a ReconcileError.
// This is useful when errors are passed through multiple layers.
func FromError(err error, message string, args ...any) *ReconcileError {
	if err == nil {
		return nil
	}

	// If it's already a ReconcileError, preserve its reason
	if IsIrrecoverableError(err) {
		return NewIrrecoverableError(err, message, args...)
	}

	// Default to retry-required for unknown errors
	return NewRetryRequiredError(err, message, args...)
}

// =============================================================================
// ERROR TYPE CHECKERS
// =============================================================================
// These functions check what type of error we're dealing with.
// They use errors.As to properly unwrap nested errors.

// IsIrrecoverableError returns true if the error should not be retried.
func IsIrrecoverableError(err error) bool {
	var rerr *ReconcileError
	if errors.As(err, &rerr) {
		return rerr.Reason == IrrecoverableError
	}
	return false
}

// IsRetryRequiredError returns true if the error should be retried.
func IsRetryRequiredError(err error) bool {
	var rerr *ReconcileError
	if errors.As(err, &rerr) {
		return rerr.Reason == RetryRequiredError
	}
	return false
}

// =============================================================================
// ERROR INTERFACE IMPLEMENTATION
// =============================================================================

// Error implements the error interface.
// Format: "message: underlying error"
func (e *ReconcileError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error, enabling errors.Is and errors.As to work.
// This is important for error chain inspection.
func (e *ReconcileError) Unwrap() error {
	return e.Err
}

