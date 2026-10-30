package services

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
	"github.com/sirupsen/logrus"
)

// NormalizeKeyNames renames, in their engine and in the KMS, the keys whose key_id is not the SHA-256 of
// their SubjectPublicKeyInfo, and returns how many it renamed. Crypto engines before the KMS renamed the
// keys of imported CAs to their certificate's SKI, and ca-to-kms-migration registered them under it.
// Each renamed key keeps its old name as an alias, and its bindings follow it.
//
// It is safe to run again: a key its engine already holds under its digest only has its row renamed.
// A key that cannot be renamed is logged and left as it is, for the next run.
func NormalizeKeyNames(ctx context.Context, logger *logrus.Entry, kmsStorage storage.KMSKeysRepo, engines map[string]*Engine) int {
	keys := []models.Key{}
	_, err := kmsStorage.SelectAll(ctx, storage.StorageListRequest[models.Key]{
		ExhaustiveRun: true,
		ApplyFunc:     func(key models.Key) { keys = append(keys, key) },
	})
	if err != nil {
		logger.Errorf("could not list the keys to normalize their names: %s", err)
		return 0
	}

	renamed := 0
	for _, key := range keys {
		if !key.HasPrivateKey {
			continue
		}
		digest, err := publicKeyDigest(ctx, logger, key.PublicKey)
		if err != nil {
			logger.Warnf("leaving key %s in engine %s as it is: could not read its public key: %s", key.KeyID, key.EngineID, err)
			continue
		}
		if digest == key.KeyID {
			continue
		}

		engine, ok := engines[key.EngineID]
		if !ok {
			logger.Warnf("leaving key %s as it is: engine %s is not configured", key.KeyID, key.EngineID)
			continue
		}
		duplicated, _, err := kmsStorage.SelectExistsByKeyID(ctx, digest, key.EngineID)
		if err != nil {
			logger.Warnf("leaving key %s in engine %s as it is: %s", key.KeyID, key.EngineID, err)
			continue
		}
		if duplicated {
			logger.Warnf("leaving key %s in engine %s as it is: the engine also holds it as %s, remove one of them by hand", key.KeyID, key.EngineID, digest)
			continue
		}

		done, err := kmsStorage.RenameKey(ctx, key.EngineID, key.KeyID, digest, func() error {
			return renameInEngine(ctx, engine.Service, key.KeyID, digest)
		})
		if err != nil {
			logger.Warnf("could not rename key %s in engine %s to %s: %s", key.KeyID, key.EngineID, digest, err)
			continue
		}
		if done {
			logger.Infof("renamed key %s in engine %s to %s", key.KeyID, key.EngineID, digest)
			renamed++
		}
	}
	return renamed
}

// renameInEngine renames an engine copy, unless the engine already holds it under the new name.
func renameInEngine(ctx context.Context, engine cryptoengines.CryptoEngine, oldName, newName string) error {
	if _, err := engine.GetPrivateKeyByID(ctx, newName); err == nil {
		return nil
	}
	return engine.RenameKey(ctx, oldName, newName)
}

// publicKeyDigest returns the SHA-256 of the SubjectPublicKeyInfo of a public key stored by the KMS, the
// base64 of its PEM encoding.
func publicKeyDigest(ctx context.Context, logger *logrus.Entry, publicKey string) (string, error) {
	pemKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", err
	}
	pub, err := chelpers.ParsePublicKey(pemKey)
	if err != nil {
		return "", fmt.Errorf("not a PEM public key: %w", err)
	}
	return software.NewSoftwareCryptoEngine(logger).EncodePKIXPublicKeyDigest(ctx, pub)
}
