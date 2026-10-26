package migrationstest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/assert"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var controlPlaneDBName = "controlplane"

func migrationTest_ControlPlane_20261023120000_create_controlplane(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, controlPlaneDBName)

	var organizationName string
	tx := con.Raw("SELECT name FROM organizations WHERE id = ?", models.DefaultOrganizationID).Scan(&organizationName)
	if tx.Error != nil {
		t.Fatalf("failed to read the default organization: %v", tx.Error)
	}
	assert.Equal(t, "Default Organization", organizationName)

	var organizationID, installationID, status, isolationMode string
	err := con.Raw("SELECT organization_id, installation_id, status, isolation_mode FROM tenants WHERE id = ?", models.DefaultTenantID).
		Row().Scan(&organizationID, &installationID, &status, &isolationMode)
	if err != nil {
		t.Fatalf("failed to read the default tenant: %v", err)
	}
	assert.Equal(t, models.DefaultOrganizationID, organizationID)
	assert.Equal(t, "default", installationID)
	assert.Equal(t, "ACTIVE", status)
	assert.Equal(t, "POOLED", isolationMode)

	tx = con.Exec(`INSERT INTO organizations (id, name) VALUES ('org-b', 'Org B')`)
	if tx.Error != nil {
		t.Fatalf("failed to insert an organization: %v", tx.Error)
	}
	tx = con.Exec(`INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode)
		VALUES ('tenant-b', 'org-b', 'default', 'Tenant B', 'ACTIVE', 'POOLED')`)
	if tx.Error != nil {
		t.Fatalf("failed to insert a tenant: %v", tx.Error)
	}
	tx = con.Exec(`INSERT INTO identities (issuer, subject) VALUES ('https://issuer.example', 'subject-1')`)
	if tx.Error != nil {
		t.Fatalf("failed to insert an identity: %v", tx.Error)
	}

	tx = con.Exec(`INSERT INTO memberships (id, organization_id, tenant_id, identity_issuer, identity_subject, role, status)
		VALUES ('membership-cross-org', ?, 'tenant-b', 'https://issuer.example', 'subject-1', 'operator', 'ACTIVE')`, models.DefaultOrganizationID)
	assert.Error(t, tx.Error, "a membership must not point to a tenant of another organization")

	tx = con.Exec(`INSERT INTO memberships (id, organization_id, tenant_id, identity_issuer, identity_subject, role, status)
		VALUES ('membership-1', 'org-b', 'tenant-b', 'https://issuer.example', 'subject-1', 'operator', 'ACTIVE')`)
	if tx.Error != nil {
		t.Fatalf("failed to insert a membership: %v", tx.Error)
	}

	tx = con.Exec(`INSERT INTO memberships (id, organization_id, tenant_id, identity_issuer, identity_subject, role, status)
		VALUES ('membership-2', 'org-b', 'tenant-b', 'https://issuer.example', 'subject-1', 'auditor', 'ACTIVE')`)
	assert.Error(t, tx.Error, "an identity must have a single membership per tenant")

	tx = con.Exec(`INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode)
		VALUES ('tenant-provisioning', 'org-b', 'default', 'Provisioning', 'PROVISIONING', 'POOLED')`)
	assert.Error(t, tx.Error, "PROVISIONING is not a tenant status")
}

func TestControlPlaneMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, controlPlaneDBName)

	defer cleanup()

	migrationTest_ControlPlane_20261023120000_create_controlplane(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261023120000_create_controlplane")
	}
}
