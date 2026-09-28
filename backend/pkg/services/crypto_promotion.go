package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/migration/catokms"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	coreServices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	log "github.com/sirupsen/logrus"
)

// ServicePromotionProvisioner creates a dedicated key and CA using the existing
// tenant-scoped CA and KMS services. The operation ID makes the CA resource
// deterministic for retry and is stored in metadata for reconciliation.
type ServicePromotionProvisioner struct {
	CA     coreServices.CAService
	KMS    coreServices.KMSService
	Logger *log.Entry
}

func (provisioner ServicePromotionProvisioner) Provision(ctx context.Context, tenantID string, currentCAID string, operationID string, targetEngineID string) (catokms.PromotionCandidate, error) {
	if provisioner.CA == nil || provisioner.KMS == nil {
		return catokms.PromotionCandidate{}, catokms.ErrPromotionUnavailable
	}
	current, err := provisioner.CA.GetCAByID(ctx, coreServices.GetCAByIDInput{CAID: currentCAID})
	if err != nil {
		return catokms.PromotionCandidate{}, fmt.Errorf("get current CA: %w", err)
	}
	if current.TenantID != tenantID {
		return catokms.PromotionCandidate{}, errors.New("current CA does not belong to tenant")
	}

	candidateCAID := "dedicated-" + operationID
	if existing, getErr := provisioner.CA.GetCAByID(ctx, coreServices.GetCAByIDInput{CAID: candidateCAID}); getErr == nil {
		return candidateFromCA(existing)
	}

	certificate := (*x509.Certificate)(current.Certificate.Certificate)
	algorithm, bits, keyType := publicKeySpec(certificate.PublicKey)
	key, err := provisioner.KMS.CreateKey(ctx, coreServices.CreateKeyInput{
		Algorithm: algorithm,
		Size:      bits,
		EngineID:  targetEngineID,
		Name:      "Dedicated promotion " + operationID,
		Metadata:  map[string]any{"lamassu.io/promotion-operation": operationID},
	})
	if err != nil {
		return catokms.PromotionCandidate{}, fmt.Errorf("create dedicated key: %w", err)
	}

	parentID := current.Certificate.IssuerCAMetadata.ID
	if current.Certificate.SubjectKeyID == current.Certificate.AuthorityKeyID {
		parentID = ""
	}
	created, err := provisioner.CA.CreateCA(ctx, coreServices.CreateCAInput{
		ID:           candidateCAID,
		ParentID:     parentID,
		KeyMetadata:  models.KeyMetadata{KeyID: key.KeyID, Type: keyType, Bits: bits},
		Subject:      current.Certificate.Subject,
		ProfileID:    current.ProfileID,
		CAExpiration: models.Validity{Type: models.Time, Time: current.Certificate.ValidTo},
		EngineID:     targetEngineID,
		Metadata: map[string]any{
			"lamassu.io/promotion-operation": operationID,
			"lamassu.io/promoted-from-ca":    currentCAID,
		},
	})
	if err != nil {
		_ = provisioner.KMS.DeleteKeyByID(ctx, coreServices.GetKeyInput{Identifier: key.KeyID})
		return catokms.PromotionCandidate{}, fmt.Errorf("create dedicated CA: %w", err)
	}
	return catokms.PromotionCandidate{TenantID: tenantID, EngineID: created.Certificate.EngineID, KeyID: key.KeyID, CAID: created.ID, PublicKey: key.PublicKey}, nil
}

func (provisioner ServicePromotionProvisioner) Rollback(ctx context.Context, candidate catokms.PromotionCandidate) error {
	if provisioner.CA == nil || provisioner.KMS == nil {
		return catokms.ErrPromotionUnavailable
	}
	if err := provisioner.CA.DeleteCA(ctx, coreServices.DeleteCAInput{CAID: candidate.CAID, CascadeDelete: true}); err != nil {
		return fmt.Errorf("delete promoted CA: %w", err)
	}
	if err := provisioner.KMS.DeleteKeyByID(ctx, coreServices.GetKeyInput{Identifier: candidate.KeyID}); err != nil {
		return fmt.Errorf("delete promoted key: %w", err)
	}
	return nil
}

// ServicePromotionVerifier verifies ownership, public-key continuity and a
// real signature round trip through the CA/KMS services.
type ServicePromotionVerifier struct {
	CA  coreServices.CAService
	KMS coreServices.KMSService
}

func (verifier ServicePromotionVerifier) Verify(ctx context.Context, candidate catokms.PromotionCandidate) error {
	if verifier.CA == nil || verifier.KMS == nil {
		return catokms.ErrPromotionUnavailable
	}
	key, err := verifier.KMS.GetKey(ctx, coreServices.GetKeyInput{Identifier: candidate.KeyID})
	if err != nil {
		return fmt.Errorf("get promoted key: %w", err)
	}
	ca, err := verifier.CA.GetCAByID(ctx, coreServices.GetCAByIDInput{CAID: candidate.CAID})
	if err != nil {
		return fmt.Errorf("get promoted CA: %w", err)
	}
	if key.TenantID != candidate.TenantID || ca.TenantID != candidate.TenantID || key.PublicKey != candidate.PublicKey || ca.Certificate.SubjectKeyID != candidate.KeyID || ca.Certificate.EngineID != candidate.EngineID {
		return errors.New("promoted CA, key and engine ownership or public key mismatch")
	}

	algorithm := signingAlgorithm(key.Algorithm)
	message := []byte("lamassu dedicated crypto promotion verification")
	signature, err := verifier.CA.SignatureSign(ctx, coreServices.SignatureSignInput{CAID: candidate.CAID, Message: message, MessageType: models.Raw, SigningAlgorithm: algorithm})
	if err != nil {
		return fmt.Errorf("sign promotion verification message: %w", err)
	}
	valid, err := verifier.CA.SignatureVerify(ctx, coreServices.SignatureVerifyInput{CAID: candidate.CAID, Message: message, Signature: signature, MessageType: models.Raw, SigningAlgorithm: algorithm})
	if err != nil {
		return fmt.Errorf("verify promotion signature: %w", err)
	}
	if !valid {
		return errors.New("promotion signature verification failed")
	}
	return nil
}

func candidateFromCA(ca *models.CACertificate) (catokms.PromotionCandidate, error) {
	if ca == nil || ca.Certificate.Certificate == nil {
		return catokms.PromotionCandidate{}, errors.New("existing promoted CA is incomplete")
	}
	certificate := (*x509.Certificate)(ca.Certificate.Certificate)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return catokms.PromotionCandidate{}, err
	}
	publicKey := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}))
	return catokms.PromotionCandidate{
		TenantID:  ca.TenantID,
		EngineID:  ca.Certificate.EngineID,
		KeyID:     ca.Certificate.SubjectKeyID,
		CAID:      ca.ID,
		PublicKey: publicKey,
	}, nil
}

func publicKeySpec(publicKey any) (string, int, models.KeyType) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen(), models.KeyType(x509.RSA)
	case *ecdsa.PublicKey:
		return "ECDSA", key.Params().BitSize, models.KeyType(x509.ECDSA)
	default:
		return "", 0, models.KeyType(0)
	}
}

func signingAlgorithm(algorithm string) string {
	if strings.EqualFold(algorithm, "RSA") {
		return "RSASSA_PKCS1_V1_5_SHA_256"
	}
	return "ECDSA_SHA_256"
}
