package services

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type tenantManagementRepoStub struct {
	storage.TenantManagementRepo
	memberships    map[string]models.Membership
	createdTenant  *models.Tenant
	createdAdmin   *models.Membership
	invitation     *models.Invitation
	acceptedHash   string
	updateRequests int
}

func (stub *tenantManagementRepoStub) CreateTenantWithAdmin(_ context.Context, tenant *models.Tenant, admin *models.Membership) error {
	stub.createdTenant, stub.createdAdmin = tenant, admin
	return nil
}

func (stub *tenantManagementRepoStub) GetTenantMembership(_ context.Context, tenantID string, membershipID string) (*models.Membership, error) {
	membership, ok := stub.memberships[membershipID]
	if !ok || membership.TenantID != tenantID {
		return nil, errs.ErrTenantManagerNotFound
	}
	return &membership, nil
}

func (stub *tenantManagementRepoStub) UpdateMembership(_ context.Context, _ string, membershipID string, update models.MembershipUpdate) (*models.Membership, error) {
	stub.updateRequests++
	membership := stub.memberships[membershipID]
	if update.Role != nil {
		membership.Role = *update.Role
	}
	if update.Status != nil {
		membership.Status = *update.Status
	}
	return &membership, nil
}

func (stub *tenantManagementRepoStub) CreateInvitation(_ context.Context, invitation *models.Invitation) error {
	stub.invitation = invitation
	return nil
}

func (stub *tenantManagementRepoStub) AcceptInvitation(_ context.Context, codeHash string, issuer string, subject string, newMembershipID string, _ time.Time) (*models.Membership, error) {
	stub.acceptedHash = codeHash
	return &models.Membership{ID: newMembershipID, TenantID: "tenant-a", IdentityIssuer: issuer, IdentitySubject: subject, Role: models.RoleViewer}, nil
}

func newTenantManagerTestService(t *testing.T, repo storage.TenantManagementRepo) *TenantManagerService {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	svc, err := NewTenantManagerService(repo, []TenantManagerIdentity{{Issuer: "https://issuer", Subject: "provisioner"}}, logrus.NewEntry(logger))
	require.NoError(t, err)
	return svc
}

func TestTenantManagerCatalogRequiresProvisioner(t *testing.T) {
	repo := &tenantManagementRepoStub{}
	svc := newTenantManagerTestService(t, repo)
	input := CreateTenantInput{OrganizationID: "org-a", Name: "Plant", Admin: TenantManagerIdentity{Issuer: "https://issuer", Subject: "alice"}}

	_, err := svc.CreateTenant(context.Background(), TenantManagerActor{Issuer: "https://issuer", Subject: "alice"}, input)
	require.ErrorIs(t, err, errs.ErrTenantManagerForbidden)
	_, err = svc.CreateOrganization(context.Background(), TenantManagerActor{Issuer: "https://other-issuer", Subject: "provisioner"}, "Org")
	require.ErrorIs(t, err, errs.ErrTenantManagerForbidden, "issuer and subject must both match")
	_, err = svc.SetTenantStatus(context.Background(), TenantManagerActor{Issuer: "https://issuer", Subject: "alice"}, "tenant-a", models.TenantSuspended)
	require.ErrorIs(t, err, errs.ErrTenantManagerForbidden)

	provisioner := TenantManagerActor{Issuer: "https://issuer", Subject: "provisioner"}
	tenant, err := svc.CreateTenant(context.Background(), provisioner, input)
	require.NoError(t, err)
	require.Equal(t, models.TenantActive, tenant.Status)
	require.Equal(t, models.IsolationPooled, tenant.IsolationMode)
	require.Equal(t, models.RoleTenantAdmin, repo.createdAdmin.Role)
	require.Equal(t, "alice", repo.createdAdmin.IdentitySubject)

	input.Admin.Subject = ""
	_, err = svc.CreateTenant(context.Background(), provisioner, input)
	require.ErrorIs(t, err, errs.ErrTenantManagerValidation)
	_, err = svc.CreateOrganization(context.Background(), provisioner, "   ")
	require.ErrorIs(t, err, errs.ErrTenantManagerValidation)
}

func TestTenantManagerRejectsSelfModificationAndInvalidUpdates(t *testing.T) {
	repo := &tenantManagementRepoStub{memberships: map[string]models.Membership{
		"m-alice": {ID: "m-alice", TenantID: "tenant-a", IdentityIssuer: "https://issuer", IdentitySubject: "alice", Role: models.RoleTenantAdmin, Status: models.MembershipActive},
		"m-bob":   {ID: "m-bob", TenantID: "tenant-a", IdentityIssuer: "https://issuer", IdentitySubject: "bob", Role: models.RoleViewer, Status: models.MembershipActive},
	}}
	svc := newTenantManagerTestService(t, repo)
	alice := TenantManagerActor{Issuer: "https://issuer", Subject: "alice"}
	admin := models.RoleTenantAdmin

	_, err := svc.UpdateMembership(context.Background(), alice, "tenant-a", "m-alice", models.MembershipUpdate{Role: &admin})
	require.ErrorIs(t, err, errs.ErrTenantManagerSelfModification)
	_, err = svc.RevokeMembership(context.Background(), alice, "tenant-a", "m-alice")
	require.ErrorIs(t, err, errs.ErrTenantManagerSelfModification)
	_, err = svc.AssignMembership(context.Background(), alice, "tenant-a", TenantManagerIdentity{Issuer: "https://issuer", Subject: "alice"}, models.RoleViewer)
	require.ErrorIs(t, err, errs.ErrTenantManagerSelfModification)
	require.Zero(t, repo.updateRequests)

	revoked := models.MembershipRevoked
	_, err = svc.UpdateMembership(context.Background(), alice, "tenant-a", "m-bob", models.MembershipUpdate{Status: &revoked})
	require.ErrorIs(t, err, errs.ErrTenantManagerValidation, "revocation goes through RevokeMembership")
	unknownRole := models.TenantRole("platform_admin")
	_, err = svc.UpdateMembership(context.Background(), alice, "tenant-a", "m-bob", models.MembershipUpdate{Role: &unknownRole})
	require.ErrorIs(t, err, errs.ErrTenantManagerValidation, "removed roles cannot be assigned")
	_, err = svc.UpdateMembership(context.Background(), alice, "tenant-b", "m-bob", models.MembershipUpdate{Role: &admin})
	require.ErrorIs(t, err, errs.ErrTenantManagerNotFound)

	updated, err := svc.UpdateMembership(context.Background(), alice, "tenant-a", "m-bob", models.MembershipUpdate{Role: &admin})
	require.NoError(t, err)
	require.Equal(t, models.RoleTenantAdmin, updated.Role)
}

func TestTenantManagerInvitationCodeIsOnlyStoredHashed(t *testing.T) {
	repo := &tenantManagementRepoStub{}
	svc := newTenantManagerTestService(t, repo)
	alice := TenantManagerActor{Issuer: "https://issuer", Subject: "alice"}

	_, _, err := svc.CreateInvitation(context.Background(), alice, "tenant-a", models.RoleViewer, MaxInvitationTTL+time.Hour)
	require.ErrorIs(t, err, errs.ErrTenantManagerValidation)

	invitation, code, err := svc.CreateInvitation(context.Background(), alice, "tenant-a", models.RoleViewer, 0)
	require.NoError(t, err)
	require.Len(t, code, 43, "32 random bytes in unpadded base64url")
	require.NotEqual(t, code, invitation.CodeHash)
	require.Equal(t, hashInvitationCode(code), repo.invitation.CodeHash)
	require.WithinDuration(t, time.Now().Add(DefaultInvitationTTL), invitation.ExpiresAt, time.Minute)

	dave := TenantManagerActor{Issuer: "https://issuer", Subject: "dave"}
	membership, err := svc.AcceptInvitation(context.Background(), dave, code)
	require.NoError(t, err)
	require.Equal(t, hashInvitationCode(code), repo.acceptedHash)
	require.Equal(t, "dave", membership.IdentitySubject)

	_, err = svc.AcceptInvitation(context.Background(), dave, " ")
	require.ErrorIs(t, err, errs.ErrTenantManagerInvalidInvitation)
}
