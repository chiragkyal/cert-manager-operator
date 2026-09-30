package approverpolicy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetResourceLabels(t *testing.T) {
	apm := testApproverPolicyManager().WithLabels(map[string]string{
		"app":           "should-be-overridden",
		"user-supplied": "kept",
	}).Build()

	labels := getResourceLabels(apm)

	if labels["app"] != approverPolicyCommonName {
		t.Errorf("expected default label to take precedence, got app=%q", labels["app"])
	}
	if labels["user-supplied"] != "kept" {
		t.Errorf("expected user-supplied label to be preserved, got %q", labels["user-supplied"])
	}
}

func TestGetResourceAnnotations(t *testing.T) {
	apm := testApproverPolicyManager().WithAnnotations(map[string]string{"foo": "bar"}).Build()
	annotations := getResourceAnnotations(apm)
	if annotations["foo"] != "bar" {
		t.Errorf("expected annotation foo=bar, got %q", annotations["foo"])
	}
}

func TestValidateApproverPolicyConfig(t *testing.T) {
	tests := []struct {
		name    string
		apm     *approverPolicyManagerBuilder
		wantErr string
	}{
		{
			name: "valid default config",
			apm:  testApproverPolicyManager(),
		},
		{
			name:    "invalid labels",
			apm:     testApproverPolicyManager().WithLabels(map[string]string{"": "empty-key"}),
			wantErr: "Invalid value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateApproverPolicyConfig(tt.apm.Build())
			assertError(t, err, tt.wantErr)
		})
	}
}

func TestManagedLabelsModified(t *testing.T) {
	tests := []struct {
		name     string
		desired  map[string]string
		existing map[string]string
		want     bool
	}{
		{
			name:     "identical labels",
			desired:  map[string]string{"app": "foo"},
			existing: map[string]string{"app": "foo"},
			want:     false,
		},
		{
			name:     "existing has extra labels",
			desired:  map[string]string{"app": "foo"},
			existing: map[string]string{"app": "foo", "extra": "bar"},
			want:     false,
		},
		{
			name:     "value drift",
			desired:  map[string]string{"app": "foo"},
			existing: map[string]string{"app": "bar"},
			want:     true,
		},
		{
			name:     "missing key in existing",
			desired:  map[string]string{"app": "foo"},
			existing: map[string]string{},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Labels: tt.desired}}
			existing := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Labels: tt.existing}}
			if got := managedLabelsModified(desired, existing); got != tt.want {
				t.Errorf("managedLabelsModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManagedAnnotationsModified(t *testing.T) {
	desired := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"a": "1"}}}
	existing := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"a": "2"}}}
	if !managedAnnotationsModified(desired, existing) {
		t.Errorf("expected annotation drift to be detected")
	}
}

func TestUpdateResourceAnnotations(t *testing.T) {
	obj := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"existing": "keep"}}}
	updateResourceAnnotations(obj, map[string]string{"new": "added"})

	if obj.Annotations["existing"] != "keep" {
		t.Errorf("expected existing annotation to be preserved")
	}
	if obj.Annotations["new"] != "added" {
		t.Errorf("expected new annotation to be added")
	}
}

func TestUpdateResourceAnnotationsNoop(t *testing.T) {
	obj := &corev1.ServiceAccount{}
	updateResourceAnnotations(obj, nil)
	if obj.GetAnnotations() != nil {
		t.Errorf("expected no annotations to be set when input is empty")
	}
}
