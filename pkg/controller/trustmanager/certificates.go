package trustmanager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"github.com/openshift/cert-manager-operator/pkg/operator/assets"
)

// =============================================================================
// CERTIFICATE RECONCILIATION
// =============================================================================
// trust-manager needs TLS certificates for its webhook server.
// We create:
//
// 1. Issuer (self-signed): A namespace-scoped self-signed issuer
// 2. Certificate: Requests a certificate from the Issuer for webhook TLS
//
// The Certificate creates a Secret (trust-manager-tls) that is mounted
// into the trust-manager Deployment for webhook TLS.

// createOrApplyCertificates reconciles the Issuer and Certificate.
func (r *Reconciler) createOrApplyCertificates(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	// 1. Create the Issuer first (Certificate depends on it)
	if err := r.createOrApplyIssuer(trustManager, resourceLabels, isNewReconcile); err != nil {
		return err
	}

	// 2. Create the Certificate
	if err := r.createOrApplyCertificate(trustManager, resourceLabels, isNewReconcile); err != nil {
		return err
	}

	return nil
}

// =============================================================================
// ISSUER
// =============================================================================

func (r *Reconciler) createOrApplyIssuer(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	desired := r.getIssuerObject(trustManager, resourceLabels)
	issuerName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling Issuer", "name", issuerName)

	fetched := &certmanagerv1.Issuer{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if Issuer %s exists", issuerName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Issuer %s already exists", issuerName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("Issuer has changed, updating", "name", issuerName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update Issuer %s", issuerName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Issuer %s updated", issuerName)
		} else {
			r.log.V(4).Info("Issuer is in expected state", "name", issuerName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create Issuer %s", issuerName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Issuer %s created", issuerName)
	}

	return nil
}

func (r *Reconciler) getIssuerObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *certmanagerv1.Issuer {
	issuer := decodeIssuerObjBytes(assets.MustAsset(issuerAssetName))

	// Set namespace to cert-manager
	updateNamespace(issuer, operandNamespace)

	// Apply labels
	updateResourceLabels(issuer, resourceLabels)

	// Apply user-specified annotations if any
	if trustManager.Spec.ControllerConfig != nil && trustManager.Spec.ControllerConfig.Annotations != nil {
		updateResourceAnnotations(issuer, trustManager.Spec.ControllerConfig.Annotations)
	}

	return issuer
}

// =============================================================================
// CERTIFICATE
// =============================================================================

func (r *Reconciler) createOrApplyCertificate(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
	isNewReconcile bool,
) error {
	desired := r.getCertificateObject(trustManager, resourceLabels)
	certName := fmt.Sprintf("%s/%s", desired.GetNamespace(), desired.GetName())

	r.log.V(4).Info("reconciling Certificate", "name", certName)

	fetched := &certmanagerv1.Certificate{}
	exists, err := r.Exists(r.ctx, client.ObjectKeyFromObject(desired), fetched)
	if err != nil {
		return FromClientError(err, "failed to check if Certificate %s exists", certName)
	}

	if exists {
		if isNewReconcile {
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeWarning, "ResourceAlreadyExists",
				"Certificate %s already exists", certName)
		}

		if hasObjectChanged(desired, fetched) {
			r.log.V(2).Info("Certificate has changed, updating", "name", certName)
			desired.SetResourceVersion(fetched.GetResourceVersion())
			if err := r.Update(r.ctx, desired); err != nil {
				return FromClientError(err, "failed to update Certificate %s", certName)
			}
			r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
				"Certificate %s updated", certName)
		} else {
			r.log.V(4).Info("Certificate is in expected state", "name", certName)
		}
	} else {
		if err := r.Create(r.ctx, desired); err != nil {
			return FromClientError(err, "failed to create Certificate %s", certName)
		}
		r.eventRecorder.Eventf(trustManager, corev1.EventTypeNormal, "Reconciled",
			"Certificate %s created", certName)
	}

	return nil
}

func (r *Reconciler) getCertificateObject(
	trustManager *v1alpha1.TrustManager,
	resourceLabels map[string]string,
) *certmanagerv1.Certificate {
	cert := decodeCertificateObjBytes(assets.MustAsset(certificateAssetName))

	// Set namespace to cert-manager
	updateNamespace(cert, operandNamespace)

	// Apply labels
	updateResourceLabels(cert, resourceLabels)

	// Update DNS names to use cert-manager namespace
	// Format: <service-name>.<namespace>.svc
	cert.Spec.CommonName = fmt.Sprintf("%s.%s.svc", trustManagerCommonName, operandNamespace)
	cert.Spec.DNSNames = []string{
		fmt.Sprintf("%s.%s.svc", trustManagerCommonName, operandNamespace),
	}

	// Apply user-specified annotations if any
	if trustManager.Spec.ControllerConfig != nil && trustManager.Spec.ControllerConfig.Annotations != nil {
		updateResourceAnnotations(cert, trustManager.Spec.ControllerConfig.Annotations)
	}

	return cert
}

