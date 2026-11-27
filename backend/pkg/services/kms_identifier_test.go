package services

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// identifierRepo keeps keys in memory and implements only the lookups an identifier is resolved with.
type identifierRepo struct {
	storage.KMSKeysRepo
	keys    []*models.Key
	updates int
}

func (r *identifierRepo) SelectExistsByID(_ context.Context, id string) (bool, *models.Key, error) {
	for _, k := range r.keys {
		if k.ID == id {
			return true, k, nil
		}
	}
	return false, nil, nil
}

func (r *identifierRepo) SelectByDigest(_ context.Context, digest string) ([]*models.Key, error) {
	var out []*models.Key
	for _, k := range r.keys {
		if k.Digest == digest {
			out = append(out, k)
		}
	}
	return out, nil
}

func (r *identifierRepo) SelectByKeyID(_ context.Context, keyID string) ([]*models.Key, error) {
	var out []*models.Key
	for _, k := range r.keys {
		if k.KeyID == keyID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (r *identifierRepo) SelectExistsByKeyID(_ context.Context, keyID, engineID string) (bool, *models.Key, error) {
	for _, k := range r.keys {
		if k.KeyID == keyID && k.EngineID == engineID {
			return true, k, nil
		}
	}
	return false, nil, nil
}

func (r *identifierRepo) SelectExistsByAlias(_ context.Context, alias string) (bool, *models.Key, error) {
	for _, k := range r.keys {
		if slices.Contains(k.Aliases, alias) {
			return true, k, nil
		}
	}
	return false, nil, nil
}

func (r *identifierRepo) Update(_ context.Context, key *models.Key) (*models.Key, error) {
	r.updates++
	return key, nil
}

func newIdentifierService(repo storage.KMSKeysRepo) *KMSServiceBackend {
	kmsValidator = validator.New()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &KMSServiceBackend{kmsStorage: repo, logger: logrus.NewEntry(logger)}
}

const (
	idOne    = "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c01"
	idTwo    = "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c02"
	idThree  = "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c03"
	skiNamed = "5a1b2c3d4e5f60718293a4b5c6d7e8f901234567" // the name a legacy engine holds a key under
)

var digestOne = strings.Repeat("ab", 32)
var digestShared = strings.Repeat("cd", 32)

func identifierFixture() *identifierRepo {
	return &identifierRepo{keys: []*models.Key{
		{ID: idOne, Digest: digestOne, KeyID: digestOne, EngineID: "e1", Aliases: []string{"prod-signer"}},
		// the key of a CA imported before the KMS: its engine holds it under the SKI, its digest is another value
		{ID: idTwo, Digest: strings.Repeat("ef", 32), KeyID: skiNamed, EngineID: "e1", Aliases: []string{}},
		// the same public key in two engines
		{ID: idThree, Digest: digestShared, KeyID: digestShared, EngineID: "e1", Aliases: []string{}},
		{ID: "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c04", Digest: digestShared, KeyID: digestShared, EngineID: "e2", Aliases: []string{}},
		// aliases written before an alias could not look like an id or a digest
		{ID: "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c05", Digest: strings.Repeat("12", 32), KeyID: strings.Repeat("12", 32), EngineID: "e1",
			Aliases: []string{"0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c99", strings.Repeat("34", 32)}},
	}}
}

// An identifier is a PKCS#11 URI, an id, a digest, the name of a key in its engine or an alias, and only the
// last of them is free text: what is shaped like an id or a digest is never looked up as an alias, or an alias
// could answer for a key that does not exist.
func TestGetKeyResolvesIdentifiers(t *testing.T) {
	ctx := context.Background()
	svc := newIdentifierService(identifierFixture())

	get := func(identifier string) (*models.Key, error) {
		return svc.GetKey(ctx, services.GetKeyInput{Identifier: identifier})
	}

	for name, tc := range map[string]struct {
		identifier string
		wantID     string
	}{
		"id":                               {idOne, idOne},
		"id in uppercase":                  {strings.ToUpper(idOne), idOne},
		"digest":                           {digestOne, idOne},
		"digest in uppercase":              {strings.ToUpper(digestOne), idOne},
		"digest of a key held under a SKI": {strings.Repeat("ef", 32), idTwo},
		"name of the key in its engine":    {skiNamed, idTwo},
		"alias":                            {"prod-signer", idOne},
		"pkcs11 URI":                       {"pkcs11:token-id=e2;id=" + digestShared + ";type=private", "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c04"},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := get(tc.identifier)
			require.NoError(t, err)
			require.Equal(t, tc.wantID, key.ID)
		})
	}

	t.Run("an id tells apart the copies of a key in several engines", func(t *testing.T) {
		key, err := get(idThree)
		require.NoError(t, err)
		require.Equal(t, "e1", key.EngineID)
	})

	t.Run("a digest that is also the name of one of its copies resolves to that copy", func(t *testing.T) {
		repo := identifierFixture()
		dig := strings.Repeat("5e", 32)
		repo.keys = append(repo.keys,
			&models.Key{ID: "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c06", Digest: dig, KeyID: dig, EngineID: "e1", Aliases: []string{}},
			&models.Key{ID: "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c07", Digest: dig, KeyID: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", EngineID: "e2", Aliases: []string{}})
		key, err := newIdentifierService(repo).GetKey(ctx, services.GetKeyInput{Identifier: dig})
		require.NoError(t, err)
		require.Equal(t, "e1", key.EngineID)
	})

	t.Run("a digest held by several engines needs the engine", func(t *testing.T) {
		_, err := get(digestShared)
		require.ErrorIs(t, err, errs.ErrKeyEngineRequired)
	})

	t.Run("an id that no key has is not looked up as an alias", func(t *testing.T) {
		_, err := get("0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c99")
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("a digest that no key has is not looked up as an alias", func(t *testing.T) {
		_, err := get(strings.Repeat("34", 32))
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("an unknown alias is not found", func(t *testing.T) {
		_, err := get("no-such-alias")
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})
}

// UpdateKeyAliases refuses what an identifier would read as something else.
func TestUpdateKeyAliasesRefusesIdentifierShapes(t *testing.T) {
	ctx := context.Background()
	repo := identifierFixture()
	svc := newIdentifierService(repo)

	update := func(alias string, op models.PatchOp) error {
		_, err := svc.UpdateKeyAliases(ctx, services.UpdateKeyAliasesInput{
			ID:      idOne,
			Patches: []models.PatchOperation{{Op: op, Path: "/-", Value: alias}},
		})
		return err
	}

	for name, alias := range map[string]string{
		"an id":                 "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c77",
		"an id in uppercase":    "0190A6C4-7F3E-7B2A-9C1D-3E5F6A7B8C77",
		"a digest":              strings.Repeat("56", 32),
		"a digest in uppercase": strings.Repeat("AB", 32),
		"a pkcs11 URI":          "pkcs11:token-id=e1;id=x;type=private",
		"the id of another key": idTwo,
		"the digest of a key":   digestShared,
	} {
		for _, op := range []models.PatchOp{models.PatchAdd, models.PatchReplace} {
			t.Run(name+"/"+string(op), func(t *testing.T) {
				before := repo.updates
				require.ErrorIs(t, update(alias, op), errs.ErrKeyAliasReservedFormat)
				require.Equal(t, before, repo.updates, "a refused alias is not stored")
			})
		}
	}

	t.Run("an ordinary alias is accepted", func(t *testing.T) {
		before := repo.updates
		require.NoError(t, update("signing-key-2026", models.PatchAdd))
		require.Equal(t, before+1, repo.updates)
	})

	t.Run("the name of a key in its engine is still refused", func(t *testing.T) {
		require.ErrorIs(t, update(skiNamed, models.PatchAdd), errs.ErrKeyAliasCollidesWithKeyID)
	})
}
