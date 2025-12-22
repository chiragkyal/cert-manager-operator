package trustmanager

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestUpdateNamespace(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "old-namespace",
		},
	}

	updateNamespace(sa, "new-namespace")

	if sa.GetNamespace() != "new-namespace" {
		t.Errorf("expected namespace 'new-namespace', got %q", sa.GetNamespace())
	}
}

func TestUpdateResourceLabels(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-sa",
			Labels: map[string]string{
				"old-label": "old-value",
			},
		},
	}

	newLabels := map[string]string{
		"new-label1": "new-value1",
		"new-label2": "new-value2",
	}

	updateResourceLabels(sa, newLabels)

	labels := sa.GetLabels()
	if len(labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(labels))
	}
	if labels["new-label1"] != "new-value1" {
		t.Errorf("expected label new-label1=new-value1, got %q", labels["new-label1"])
	}
	if labels["old-label"] != "" {
		t.Error("old-label should be removed")
	}
}

func TestMergeLabels(t *testing.T) {
	existing := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	additional := map[string]string{
		"key2": "overwritten",
		"key3": "value3",
	}

	result := mergeLabels(existing, additional)

	if len(result) != 3 {
		t.Errorf("expected 3 labels, got %d", len(result))
	}
	if result["key1"] != "value1" {
		t.Errorf("expected key1=value1, got %q", result["key1"])
	}
	if result["key2"] != "overwritten" {
		t.Errorf("expected key2=overwritten, got %q", result["key2"])
	}
	if result["key3"] != "value3" {
		t.Errorf("expected key3=value3, got %q", result["key3"])
	}

	// Verify original maps are not modified
	if existing["key3"] != "" {
		t.Error("original existing map was modified")
	}
}

func TestHasObjectChanged_ServiceAccount(t *testing.T) {
	desired := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-sa",
			Labels: map[string]string{
				"label1": "value1",
			},
		},
	}

	fetched := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-sa",
			Labels: map[string]string{
				"label1": "value1",
			},
		},
	}

	// Same - no change
	if hasObjectChanged(desired, fetched) {
		t.Error("expected no change when objects are identical")
	}

	// Different labels - change detected
	fetched.Labels["label1"] = "different"
	if !hasObjectChanged(desired, fetched) {
		t.Error("expected change when labels differ")
	}
}

func TestHasObjectChanged_Deployment(t *testing.T) {
	replicas := int32(1)
	desired := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deploy",
			Labels: map[string]string{
				"label1": "value1",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
			},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "test-sa",
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "test-image:v1",
						},
					},
				},
			},
		},
	}

	fetched := desired.DeepCopy()

	// Same - no change
	if hasObjectChanged(desired, fetched) {
		t.Error("expected no change when deployments are identical")
	}

	// Different image
	fetched.Spec.Template.Spec.Containers[0].Image = "test-image:v2"
	if !hasObjectChanged(desired, fetched) {
		t.Error("expected change when container image differs")
	}
}

func TestHasObjectChanged_Service(t *testing.T) {
	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-svc",
			Labels: map[string]string{
				"label1": "value1",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					TargetPort: intstr.FromInt(6443),
				},
			},
			Selector: map[string]string{"app": "test"},
		},
	}

	fetched := desired.DeepCopy()

	// Same - no change
	if hasObjectChanged(desired, fetched) {
		t.Error("expected no change when services are identical")
	}

	// Different port
	fetched.Spec.Ports[0].Port = 8443
	if !hasObjectChanged(desired, fetched) {
		t.Error("expected change when service port differs")
	}
}

func TestHasObjectChanged_ClusterRole(t *testing.T) {
	desired := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	fetched := desired.DeepCopy()

	// Same - no change
	if hasObjectChanged(desired, fetched) {
		t.Error("expected no change when roles are identical")
	}

	// Different rules
	fetched.Rules[0].Verbs = []string{"get", "list", "watch"}
	if !hasObjectChanged(desired, fetched) {
		t.Error("expected change when role rules differ")
	}
}

func TestServiceSpecChanged(t *testing.T) {
	tests := []struct {
		name     string
		desired  *corev1.Service
		fetched  *corev1.Service
		expected bool
	}{
		{
			name: "identical services",
			desired: &corev1.Service{
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeClusterIP,
					Ports: []corev1.ServicePort{
						{Port: 443},
					},
					Selector: map[string]string{"app": "test"},
				},
			},
			fetched: &corev1.Service{
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeClusterIP,
					Ports: []corev1.ServicePort{
						{Port: 443},
					},
					Selector: map[string]string{"app": "test"},
				},
			},
			expected: false,
		},
		{
			name: "different type",
			desired: &corev1.Service{
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeClusterIP,
				},
			},
			fetched: &corev1.Service{
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeNodePort,
				},
			},
			expected: true,
		},
		{
			name: "different selector",
			desired: &corev1.Service{
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{"app": "test1"},
				},
			},
			fetched: &corev1.Service{
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{"app": "test2"},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := serviceSpecChanged(tt.desired, tt.fetched)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
