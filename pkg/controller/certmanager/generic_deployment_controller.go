package certmanager

import (
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/deploymentcontroller"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
	certmanoperatorinformers "github.com/openshift/cert-manager-operator/pkg/operator/informers/externalversions"
	"github.com/openshift/cert-manager-operator/pkg/operator/utils"
)

func newGenericDeploymentController(
	controllerName, targetVersion, deploymentFile string,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	certManagerOperatorInformers certmanoperatorinformers.SharedInformerFactory,
	infraInformers utils.OptionalInformer[configinformers.SharedInformerFactory],
	kubeClient kubernetes.Interface,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	eventsRecorder events.Recorder,
	versionRecorder status.VersionGetter,
	trustedCAConfigmapName string,
	cloudCredentialsSecretName string,
	handoffControllers ...*autoApproverController,
) factory.Controller {
	deployment := resourceread.ReadDeploymentV1OrDie(assets.MustAsset(deploymentFile))

	hooks := []deploymentcontroller.DeploymentHookFunc{
		withOperandImageOverrideHook,
		withLogLevel,
		withPodLabelsOverrideHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name, getOverridePodLabelsFor),
		withPodLabelsValidateHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name),
		withContainerArgsOverrideHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name, getOverrideArgsFor),
		withContainerArgsValidateHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name),
		withProxyEnv,
		withContainerEnvOverrideHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name, getOverrideEnvFor),
		withContainerEnvValidateHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name),
		withDeploymentReplicasOverrideHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name, getOverrideReplicasFor),
		withContainerResourcesOverrideHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name, getOverrideResourcesFor),
		withContainerResourcesValidateHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name),
		withPodSchedulingOverrideHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name, getOverrideSchedulingFor),
		withPodSchedulingValidateHook(certManagerOperatorInformers.Operator().V1alpha1().CertManagers(), deployment.Name),
		withCAConfigMap(kubeInformersForTargetNamespace.Core().V1().ConfigMaps(), deployment, trustedCAConfigmapName),
		withSABoundToken,
	}

	informers := []factory.Informer{
		kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
		kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
	}

	if infraInformers.Applicable() {
		infraInformerFactory := (*infraInformers.InformerFactory)

		hooks = append(hooks, withCloudCredentials(
			kubeInformersForTargetNamespace.Core().V1().Secrets(),
			infraInformerFactory.Config().V1().Infrastructures(),
			deployment.Name,
			cloudCredentialsSecretName,
		))

		informers = append(informers, infraInformerFactory.Config().V1().Infrastructures().Informer())

		hooks = append(hooks, common.WithClusterTLSProfileFromAPIServer(infraInformerFactory.Config().V1().APIServers()))
		informers = append(informers, infraInformerFactory.Config().V1().APIServers().Informer())
	}

	// unsupportedConfigOverrides must run after cluster TLS so break-glass operand args win.
	hooks = append(hooks, withUnsupportedArgsOverrideHook)
	var handoff *autoApproverController
	if len(handoffControllers) != 0 {
		handoff = handoffControllers[0]
		hooks = append(hooks, handoff.prepareDeployment)
		informers = append(informers,
			certManagerOperatorInformers.Operator().V1alpha1().ApproverPolicyManagers().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Apps().V1().ReplicaSets().Informer(),
			kubeInformersForTargetNamespace.Rbac().V1().ClusterRoles().Informer(),
			kubeInformersForTargetNamespace.Rbac().V1().ClusterRoleBindings().Informer(),
		)
	}

	controller := deploymentcontroller.NewDeploymentController(
		controllerName,
		assets.MustAsset(deploymentFile),
		eventsRecorder,
		operatorClient,
		kubeClient,
		kubeInformersForTargetNamespace.Apps().V1().Deployments(),
		informers,
		[]deploymentcontroller.ManifestHookFunc{},
		hooks...,
	)
	if handoff == nil {
		return controller
	}
	// Run only this outer sync. The delegated DeploymentController retains its
	// existing hooks, resourceapply behavior and generation/status accounting.
	// No status-only predicates: readiness and old-pod termination must enqueue.
	handoff.deploymentController = controller
	return factory.New().WithInformers(append(informers,
		operatorClient.Informer(), kubeInformersForTargetNamespace.Apps().V1().Deployments().Informer())...).
		WithSync(handoff.sync).WithSyncDegradedOnError(operatorClient).
		ResyncEvery(30*time.Second).ToController(controllerName, eventsRecorder)
}
