package approverpolicy

import (
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestUpdateDeploymentArgs(t *testing.T) {
	deployment := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: approverPolicyContainerName},
					},
				},
			},
		},
	}

	apm := testApproverPolicyManager().WithLogLevel(3).WithLogFormat("json").Build()
	updateDeploymentArgs(deployment, apm)

	args := deployment.Spec.Template.Spec.Containers[0].Args
	if !slices.Contains(args, "--log-level=3") {
		t.Errorf("expected --log-level=3 in args, got %v", args)
	}
	if !slices.Contains(args, "--log-format=json") {
		t.Errorf("expected --log-format=json in args, got %v", args)
	}
	if !slices.Contains(args, "--webhook-service-name="+approverPolicyServiceName) {
		t.Errorf("expected webhook service name arg, got %v", args)
	}
	if !slices.Contains(args, "--webhook-ca-secret-name="+webhookTLSSecretName) {
		t.Errorf("expected webhook ca secret name arg, got %v", args)
	}
}

func TestUpdateImage(t *testing.T) {
	t.Run("errors when env var unset", func(t *testing.T) {
		t.Setenv(approverPolicyImageNameEnvVarName, "")
		deployment := &appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: approverPolicyContainerName}},
			}}},
		}
		err := updateImage(deployment)
		assertError(t, err, "environment variable")
	})

	t.Run("sets image from env var", func(t *testing.T) {
		t.Setenv(approverPolicyImageNameEnvVarName, "quay.io/example/approver-policy:v1")
		deployment := &appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: approverPolicyContainerName}},
			}}},
		}
		if err := updateImage(deployment); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := deployment.Spec.Template.Spec.Containers[0].Image; got != "quay.io/example/approver-policy:v1" {
			t.Errorf("expected image to be set, got %q", got)
		}
	})
}

func TestUpdateResourceRequirements(t *testing.T) {
	deployment := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: approverPolicyContainerName}},
		}}},
	}
	apm := testApproverPolicyManager().WithResources(corev1.ResourceRequirements{
		Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
	}).Build()

	if err := updateResourceRequirements(deployment, apm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := deployment.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU]
	if got.String() != "100m" {
		t.Errorf("expected cpu limit 100m, got %s", got.String())
	}
}

func TestUpdateNodeSelector(t *testing.T) {
	deployment := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
		}}},
	}
	apm := testApproverPolicyManager().WithNodeSelector(map[string]string{"disktype": "ssd"}).Build()

	if err := updateNodeSelector(deployment, apm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ns := deployment.Spec.Template.Spec.NodeSelector
	if ns["kubernetes.io/os"] != "linux" {
		t.Errorf("expected default node selector to be preserved, got %v", ns)
	}
	if ns["disktype"] != "ssd" {
		t.Errorf("expected user node selector to be merged, got %v", ns)
	}
}

func TestDeploymentModified(t *testing.T) {
	base := func() *appsv1.Deployment {
		return &appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  approverPolicyContainerName,
								Image: "quay.io/example/approver-policy:v1",
								Args:  []string{"--log-level=1"},
							},
						},
					},
				},
			},
		}
	}

	t.Run("identical deployments are not modified", func(t *testing.T) {
		desired, existing := base(), base()
		if deploymentModified(desired, existing) {
			t.Errorf("expected no modification for identical deployments")
		}
	})

	t.Run("image drift is detected", func(t *testing.T) {
		desired, existing := base(), base()
		existing.Spec.Template.Spec.Containers[0].Image = "quay.io/example/approver-policy:v2"
		if !deploymentModified(desired, existing) {
			t.Errorf("expected image drift to be detected")
		}
	})

	t.Run("args drift is detected", func(t *testing.T) {
		desired, existing := base(), base()
		existing.Spec.Template.Spec.Containers[0].Args = []string{"--log-level=5"}
		if !deploymentModified(desired, existing) {
			t.Errorf("expected args drift to be detected")
		}
	})
}
