package upgradecheck

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"gorm.io/gorm"
)

const (
	vaSignerMigration      = "va/20261104121000_va_role_signer_certificate"
	vaCRLSettingsMigration = "va/20261111120000_crl_settings"
)

// VAChecks reports, on a 3.8 database, the conditions under which the VA migrations abort. Each one computes from
// the 3.8 data what the earlier v4 migrations derive, and uses the wording of the migration it covers.
func VAChecks() []Check {
	return []Check{
		{Name: "va signer", Covers: []string{vaSignerMigration}, Run: vaRoleCheck(signerProblem)},
		{Name: "va ca ids in urls", Covers: []string{vaCRLSettingsMigration}, Run: caIDsInURLsCheck},
		{Name: "va shared ski", Covers: []string{vaCRLSettingsMigration}, Run: vaRoleCheck(sharedSKIProblem)},
		{Name: "va signer key", Covers: []string{vaCRLSettingsMigration}, Run: vaRoleCheck(signerKeyProblem)},
		{Name: "va archived settings id", Covers: []string{vaCRLSettingsMigration}, Run: vaRoleCheck(archivedIDProblem)},
		{Name: "va ambiguous crl urls", Covers: []string{vaCRLSettingsMigration}, Run: ambiguousURLsCheck},
	}
}

type vaRole struct {
	CASKI     string  `gorm:"column:ca_ski"`
	SignerSKI *string `gorm:"column:crl_subject_key_id_signer"`
}

// roleProblem returns the problem of one role, or "" if it has none.
type roleProblem func(ctx context.Context, db *gorm.DB, role vaRole) (string, error)

// vaRoleCheck applies a roleProblem to every VA role.
func vaRoleCheck(problem roleProblem) func(ctx context.Context, env *Env) ([]string, error) {
	return func(ctx context.Context, env *Env) ([]string, error) {
		db, err := env.Schema("va")
		if err != nil {
			return nil, err
		}
		db = db.WithContext(ctx)

		var roles []vaRole
		if err := db.Raw(`SELECT ca_ski, crl_subject_key_id_signer FROM va.va_role ORDER BY ca_ski`).Scan(&roles).Error; err != nil {
			return nil, fmt.Errorf("read va roles: %w", err)
		}

		problems := []string{}
		for _, role := range roles {
			p, err := problem(ctx, db, role)
			if err != nil {
				return nil, fmt.Errorf("VA role %s: %w", role.CASKI, err)
			}
			if p != "" {
				problems = append(problems, p)
			}
		}
		return problems, nil
	}
}

// roleCAIDs are the ids of the CAs whose certificate has the SKI of the role: none for a role whose CA was deleted.
func roleCAIDs(db *gorm.DB, role vaRole) ([]string, error) {
	var ids []string
	err := db.Raw(`SELECT DISTINCT a.id FROM ca.certificates c JOIN ca.ca_certificates a ON a.serial_number = c.serial_number
		WHERE c.subject_key_id = ? ORDER BY a.id`, role.CASKI).Scan(&ids).Error
	return ids, err
}

// signerCandidates resolves the signer of a role as migration 20261104121000 does: the CA certificates with the
// signer SKI, only the oldest CA when several share it; if none, every certificate with that SKI. The role is
// resolved when exactly one candidate is left.
func signerCandidates(db *gorm.DB, role vaRole) ([]string, error) {
	if role.SignerSKI == nil {
		return nil, nil
	}
	var serials []string
	err := db.Raw(`SELECT c.serial_number FROM ca.certificates c JOIN ca.ca_certificates a ON a.serial_number = c.serial_number
		WHERE c.subject_key_id = ? ORDER BY a.creation_ts ASC NULLS LAST, c.serial_number`, *role.SignerSKI).Scan(&serials).Error
	if err != nil {
		return nil, err
	}
	if len(serials) > 1 {
		return serials[:1], nil
	}
	if len(serials) == 1 {
		return serials, nil
	}
	err = db.Raw(`SELECT serial_number FROM ca.certificates WHERE subject_key_id = ? ORDER BY serial_number`, *role.SignerSKI).Scan(&serials).Error
	return serials, err
}

func signerProblem(_ context.Context, db *gorm.DB, role vaRole) (string, error) {
	candidates, err := signerCandidates(db, role)
	if err != nil || len(candidates) == 1 {
		return "", err
	}
	signerSKI, list := "<NULL>", "none"
	if role.SignerSKI != nil {
		signerSKI = *role.SignerSKI
	}
	if len(candidates) > 0 {
		list = strings.Join(candidates, ", ")
	}
	return fmt.Sprintf("cannot resolve signer certificate for VA role %s, SKI %s: %d candidates: %s",
		role.CASKI, signerSKI, len(candidates), list), nil
}

func sharedSKIProblem(_ context.Context, db *gorm.DB, role vaRole) (string, error) {
	ids, err := roleCAIDs(db, role)
	if err != nil || len(ids) <= 1 {
		return "", err
	}
	return fmt.Sprintf("VA role %s: SKI shared by CAs %s. Every SKI must belong to a single CA before upgrading: recreate all but one of them on a different key",
		role.CASKI, strings.Join(ids, ", ")), nil
}

// signerKeyProblem applies to a role with exactly one CA and a resolved signer. The signer has a key when the CA
// migrations 20261027100000 and 20261030120000 give it a key_id: it has an engine, and its certificate decodes.
func signerKeyProblem(_ context.Context, db *gorm.DB, role vaRole) (string, error) {
	ids, err := roleCAIDs(db, role)
	if err != nil || len(ids) != 1 {
		return "", err
	}
	candidates, err := signerCandidates(db, role)
	if err != nil || len(candidates) != 1 {
		return "", err
	}
	signer := candidates[0]

	var row struct {
		EngineID    *string `gorm:"column:engine_id"`
		Certificate *string `gorm:"column:certificate"`
	}
	if err := db.Raw(`SELECT engine_id, certificate FROM ca.certificates WHERE serial_number = ?`, signer).Scan(&row).Error; err != nil {
		return "", err
	}
	if hasKey(row.EngineID, row.Certificate) {
		return "", nil
	}
	return fmt.Sprintf("VA role %s, CA %s: signer certificate %s has no key, so it cannot sign CRLs. Point the role to a signer with a key, or fix the key reference of the certificate, before upgrading",
		role.CASKI, ids[0], signer), nil
}

func hasKey(engineID, certificate *string) bool {
	if engineID == nil || *engineID == "" || certificate == nil {
		return false
	}
	cert, err := mhelper.DecodeCertificate(*certificate)
	if err != nil {
		return false
	}
	_, err = x509.MarshalPKIXPublicKey(cert.PublicKey)
	return err == nil
}

func archivedIDProblem(_ context.Context, db *gorm.DB, role vaRole) (string, error) {
	ids, err := roleCAIDs(db, role)
	if err != nil || len(ids) > 0 {
		return "", err
	}
	archivedID := "legacy-" + role.CASKI
	var clash bool
	if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM ca.ca_certificates WHERE id = ?)`, archivedID).Scan(&clash).Error; err != nil || !clash {
		return "", err
	}
	return fmt.Sprintf("VA role %s: CA %s has the id reserved for the archived settings of this role, whose CA was deleted. Recreate that CA with a different id before upgrading",
		role.CASKI, archivedID), nil
}

func caIDsInURLsCheck(ctx context.Context, env *Env) ([]string, error) {
	db, err := env.Schema("va")
	if err != nil {
		return nil, err
	}
	var ids *string
	err = db.WithContext(ctx).Raw(`SELECT string_agg(id, ', ' ORDER BY id) FROM ca.ca_certificates WHERE position('/' IN id) > 0`).Scan(&ids).Error
	if err != nil || ids == nil {
		return nil, err
	}
	return []string{fmt.Sprintf(`CA ids containing "/" cannot be used in CRL URLs: %s. Recreate these CAs with a different id before upgrading`, *ids)}, nil
}

// ambiguousURLsCheck finds the CAs whose id is the SKI of a role that is not theirs: /crl/<id> would resolve to the
// settings of that CA by id and to those of the role by legacy SKI.
func ambiguousURLsCheck(ctx context.Context, env *Env) ([]string, error) {
	db, err := env.Schema("va")
	if err != nil {
		return nil, err
	}
	var ids *string
	err = db.WithContext(ctx).Raw(`SELECT string_agg(DISTINCT a.id, ', ' ORDER BY a.id)
		FROM ca.ca_certificates a
		JOIN va.va_role r ON r.ca_ski = a.id
		JOIN ca.certificates c ON c.serial_number = a.serial_number
		WHERE c.subject_key_id IS DISTINCT FROM r.ca_ski`).Scan(&ids).Error
	if err != nil || ids == nil {
		return nil, err
	}
	return []string{fmt.Sprintf("CA ids equal to the SKI of another VA role: %s. Their CRL URLs would be ambiguous", *ids)}, nil
}
