package postgrestest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
)

const tenantManagementIssuer = "https://issuer.test"

func newTenantManagementStore(t *testing.T) *postgresstorage.TenantManagementStore {
	t.Helper()
	cfg, suite := BeforeSuite([]string{postgresstorage.CONTROLPLANE_DB_NAME}, false)
	t.Cleanup(suite.AfterSuite)
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "tenant management test")
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.CONTROLPLANE_DB_NAME))
	return postgresstorage.NewTenantManagementRepository(suite.DB[postgresstorage.CONTROLPLANE_DB_NAME])
}

func createTestTenant(t *testing.T, store *postgresstorage.TenantManagementStore, organizationID, tenantID, adminSubject string) {
	t.Helper()
	require.NoError(t, store.CreateTenantWithAdmin(context.Background(), &models.Tenant{
		ID: tenantID, OrganizationID: organizationID, Name: tenantID,
		Status: models.TenantActive, IsolationMode: models.IsolationPooled,
	}, &models.Membership{
		ID: "membership-" + tenantID + "-" + adminSubject, OrganizationID: organizationID, TenantID: tenantID,
		IdentityIssuer: tenantManagementIssuer, IdentitySubject: adminSubject,
		Role: models.RoleTenantAdmin, Status: models.MembershipActive,
	}))
}

func TestTenantManagementCatalogAndMemberships(t *testing.T) {
	store := newTenantManagementStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateOrganization(ctx, &models.Organization{ID: "org-a", Name: "Org A"}))
	require.ErrorIs(t, store.CreateOrganization(ctx, &models.Organization{ID: "org-a2", Name: "Org A"}), errs.ErrTenantManagerConflict)

	err := store.CreateTenantWithAdmin(ctx, &models.Tenant{
		ID: "tenant-x", OrganizationID: "missing-org", Name: "X", Status: models.TenantActive, IsolationMode: models.IsolationPooled,
	}, &models.Membership{ID: "m-x", OrganizationID: "missing-org", TenantID: "tenant-x",
		IdentityIssuer: tenantManagementIssuer, IdentitySubject: "admin", Role: models.RoleTenantAdmin, Status: models.MembershipActive})
	require.ErrorIs(t, err, errs.ErrTenantManagerNotFound)

	createTestTenant(t, store, "org-a", "tenant-a", "alice")
	createTestTenant(t, store, "org-a", "tenant-b", "bob")

	summaries, err := store.ListIdentityMemberships(ctx, tenantManagementIssuer, "alice")
	require.NoError(t, err)
	require.Len(t, summaries, 1, "alice only sees her own tenant")
	require.Equal(t, "tenant-a", summaries[0].TenantID)
	require.Equal(t, "Org A", summaries[0].OrganizationName)
	require.Equal(t, models.RoleTenantAdmin, summaries[0].Role)

	assigned, err := store.AssignMembership(ctx, &models.Membership{ID: "m-carol", TenantID: "tenant-a",
		IdentityIssuer: tenantManagementIssuer, IdentitySubject: "carol", Role: models.RoleViewer})
	require.NoError(t, err)
	require.Equal(t, "org-a", assigned.OrganizationID)
	_, err = store.AssignMembership(ctx, &models.Membership{ID: "m-carol-2", TenantID: "tenant-a",
		IdentityIssuer: tenantManagementIssuer, IdentitySubject: "carol", Role: models.RoleOperator})
	require.ErrorIs(t, err, errs.ErrTenantManagerConflict, "one membership per identity and tenant")

	_, err = store.GetTenantMembership(ctx, "tenant-b", "m-carol")
	require.ErrorIs(t, err, errs.ErrTenantManagerNotFound, "memberships are scoped to their tenant")

	revoked := models.MembershipRevoked
	_, err = store.UpdateMembership(ctx, "tenant-a", "m-carol", models.MembershipUpdate{Status: &revoked})
	require.NoError(t, err)
	active := models.MembershipActive
	_, err = store.UpdateMembership(ctx, "tenant-a", "m-carol", models.MembershipUpdate{Status: &active})
	require.ErrorIs(t, err, errs.ErrTenantManagerConflict, "a revoked membership is only reactivated through a new assignment")

	reactivated, err := store.AssignMembership(ctx, &models.Membership{ID: "m-carol-3", TenantID: "tenant-a",
		IdentityIssuer: tenantManagementIssuer, IdentitySubject: "carol", Role: models.RoleOperator})
	require.NoError(t, err)
	require.Equal(t, "m-carol", reactivated.ID)
	require.Equal(t, models.RoleOperator, reactivated.Role)
	require.Equal(t, models.MembershipActive, reactivated.Status)

	memberships, err := store.ListTenantMemberships(ctx, "tenant-a")
	require.NoError(t, err)
	require.Len(t, memberships, 2)
}

func TestTenantManagementKeepsLastTenantAdmin(t *testing.T) {
	store := newTenantManagementStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateOrganization(ctx, &models.Organization{ID: "org-a", Name: "Org A"}))
	createTestTenant(t, store, "org-a", "tenant-a", "alice")

	viewer := models.RoleViewer
	suspended := models.MembershipSuspended
	_, err := store.UpdateMembership(ctx, "tenant-a", "membership-tenant-a-alice", models.MembershipUpdate{Role: &viewer})
	require.ErrorIs(t, err, errs.ErrTenantManagerLastTenantAdmin)
	_, err = store.UpdateMembership(ctx, "tenant-a", "membership-tenant-a-alice", models.MembershipUpdate{Status: &suspended})
	require.ErrorIs(t, err, errs.ErrTenantManagerLastTenantAdmin)

	_, err = store.AssignMembership(ctx, &models.Membership{ID: "m-bob", TenantID: "tenant-a",
		IdentityIssuer: tenantManagementIssuer, IdentitySubject: "bob", Role: models.RoleTenantAdmin})
	require.NoError(t, err)

	// Two admins demoting each other at the same time: the tenant lock must let
	// exactly one of them succeed.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, membershipID := range []string{"membership-tenant-a-alice", "m-bob"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := store.UpdateMembership(ctx, "tenant-a", id, models.MembershipUpdate{Role: &viewer})
			results <- err
		}(membershipID)
	}
	wg.Wait()
	close(results)
	var succeeded, lastAdmin int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case err == errs.ErrTenantManagerLastTenantAdmin:
			lastAdmin++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, lastAdmin)
}

func TestTenantManagementTenantLifecycle(t *testing.T) {
	store := newTenantManagementStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateOrganization(ctx, &models.Organization{ID: "org-a", Name: "Org A"}))
	createTestTenant(t, store, "org-a", "tenant-a", "alice")
	now := time.Now().UTC()

	_, err := store.UpdateTenantStatus(ctx, "tenant-a", models.TenantDeleted, now)
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidTransition)
	_, err = store.UpdateTenantStatus(ctx, "missing", models.TenantSuspended, now)
	require.ErrorIs(t, err, errs.ErrTenantManagerNotFound)

	tenant, err := store.UpdateTenantStatus(ctx, "tenant-a", models.TenantSuspended, now)
	require.NoError(t, err)
	require.Equal(t, models.TenantSuspended, tenant.Status)
	summaries, err := store.ListIdentityMemberships(ctx, tenantManagementIssuer, "alice")
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	require.Equal(t, models.TenantSuspended, summaries[0].TenantStatus)

	_, err = store.UpdateTenantStatus(ctx, "tenant-a", models.TenantDeprovisioning, now)
	require.NoError(t, err)
	tenant, err = store.UpdateTenantStatus(ctx, "tenant-a", models.TenantDeleted, now)
	require.NoError(t, err)
	require.NotNil(t, tenant.DeletedAt)
	summaries, err = store.ListIdentityMemberships(ctx, tenantManagementIssuer, "alice")
	require.NoError(t, err)
	require.Empty(t, summaries, "deleted tenants are not offered to their members")

	tenant, err = store.UpdateTenantStatus(ctx, "tenant-a", models.TenantRestoring, now)
	require.NoError(t, err)
	require.Nil(t, tenant.DeletedAt)
}

func TestTenantManagementInvitations(t *testing.T) {
	store := newTenantManagementStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateOrganization(ctx, &models.Organization{ID: "org-a", Name: "Org A"}))
	createTestTenant(t, store, "org-a", "tenant-a", "alice")
	now := time.Now().UTC()

	newInvitation := func(id, hash string, role models.TenantRole, expiresAt time.Time) {
		require.NoError(t, store.CreateInvitation(ctx, &models.Invitation{
			ID: id, TenantID: "tenant-a", Role: role, CodeHash: hash, Status: models.InvitationPending,
			CreatedByIssuer: tenantManagementIssuer, CreatedBySubject: "alice", ExpiresAt: expiresAt,
		}))
	}

	newInvitation("inv-1", "hash-1", models.RolePKIAdmin, now.Add(time.Hour))
	membership, err := store.AcceptInvitation(ctx, "hash-1", tenantManagementIssuer, "dave", "m-dave", now)
	require.NoError(t, err)
	require.Equal(t, models.RolePKIAdmin, membership.Role)
	require.Equal(t, "org-a", membership.OrganizationID)
	_, err = store.AcceptInvitation(ctx, "hash-1", tenantManagementIssuer, "erin", "m-erin", now)
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidInvitation, "an invitation is single use")
	_, err = store.AcceptInvitation(ctx, "unknown", tenantManagementIssuer, "erin", "m-erin", now)
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidInvitation)

	newInvitation("inv-expired", "hash-expired", models.RoleViewer, now.Add(-time.Minute))
	_, err = store.AcceptInvitation(ctx, "hash-expired", tenantManagementIssuer, "erin", "m-erin", now)
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidInvitation)

	newInvitation("inv-revoked", "hash-revoked", models.RoleViewer, now.Add(time.Hour))
	revoked, err := store.RevokeInvitation(ctx, "tenant-a", "inv-revoked")
	require.NoError(t, err)
	require.Equal(t, models.InvitationRevoked, revoked.Status)
	_, err = store.RevokeInvitation(ctx, "tenant-a", "inv-revoked")
	require.ErrorIs(t, err, errs.ErrTenantManagerConflict)
	_, err = store.AcceptInvitation(ctx, "hash-revoked", tenantManagementIssuer, "erin", "m-erin", now)
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidInvitation)

	newInvitation("inv-member", "hash-member", models.RoleViewer, now.Add(time.Hour))
	_, err = store.AcceptInvitation(ctx, "hash-member", tenantManagementIssuer, "dave", "m-dave-2", now)
	require.ErrorIs(t, err, errs.ErrTenantManagerConflict, "an existing member cannot accept another invitation")

	newInvitation("inv-suspended", "hash-suspended", models.RoleViewer, now.Add(time.Hour))
	_, err = store.UpdateTenantStatus(ctx, "tenant-a", models.TenantSuspended, now)
	require.NoError(t, err)
	_, err = store.AcceptInvitation(ctx, "hash-suspended", tenantManagementIssuer, "erin", "m-erin", now)
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidInvitation, "suspended tenants do not accept new members")

	invitations, err := store.ListInvitations(ctx, "tenant-a")
	require.NoError(t, err)
	require.Len(t, invitations, 5)
	_, err = store.RevokeInvitation(ctx, "other-tenant", "inv-member")
	require.ErrorIs(t, err, errs.ErrTenantManagerNotFound)
}
