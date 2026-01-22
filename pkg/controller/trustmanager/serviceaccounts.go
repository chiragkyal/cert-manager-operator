package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/controller/common"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

func (r *Reconciler) createOrApplyServiceAccounts(trustManager *v1alpha1.TrustManager, resourceLabels map[string]string, createRecon bool) error {
	// get serviceaccount object
	serviceAccount := r.getServiceAccountObject(resourceLabels)

	serviceAccountName := fmt.Sprintf("%s/%s", serviceAccount.GetNamespace(), serviceAccount.GetName())
	r.log.V(4).Info("reconciling serviceaccount resource", "name", serviceAccountName)

	// check if serviceaccount resource already exists
	fetched := &corev1.ServiceAccount{}
	exist, err := r.Exists(r.ctx, client.ObjectKeyFromObject(serviceAccount), fetched)
	if err != nil {
		return common.FromClientError(err, "failed to check %s serviceaccount resource already exists", serviceAccountName)
	}

	if !exist {
		r.log.V(4).Info("creating serviceaccount", "name", serviceAccountName)
		if err := r.Create(r.ctx, serviceAccount); err != nil {
			return common.FromClientError(err, "failed to create serviceaccount %q", serviceAccountName)
		}
		r.log.V(2).Info("created serviceaccount", "name", serviceAccountName)
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled", "serviceaccount resource %s created", serviceAccountName)
		return nil
	}

	// Resource exists - check if update is needed
	if createRecon {
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists", "%s serviceaccount resource already exists, maybe from previous installation", serviceAccountName)
	}

	if common.HasObjectChanged(serviceAccount, fetched) {
		r.log.V(4).Info("updating serviceaccount", "name", serviceAccountName)
		if err := r.UpdateWithRetry(r.ctx, serviceAccount); err != nil {
			return common.FromClientError(err, "failed to update serviceaccount %q", serviceAccountName)
		}
		r.log.V(2).Info("updated serviceaccount", "name", serviceAccountName)
	}

	return nil
}

func (r *Reconciler) getServiceAccountObject(resourceLabels map[string]string) *corev1.ServiceAccount {
	serviceAccount := decodeServiceAccountObjBytes(assets.MustAsset(serviceAccountAssetName))
	common.UpdateNamespace(serviceAccount, operandNamespace)
	common.UpdateResourceLabels(serviceAccount, resourceLabels)

	return serviceAccount
}
