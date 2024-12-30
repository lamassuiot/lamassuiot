package migrationstest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

var CADBName = "ca"

func MigrationTest_CA_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, CADBName)

	con.Exec(`INSERT INTO ca_certificates
			(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_strength_meta_type, key_strength_meta_bits, key_strength_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, id, issuance_expiration_ref, creation_ts, "level")
			VALUES('ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47', '{}', 'ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47', '9beebc5b-ba8d-4fc0-9e97-58299d30ae9f', 0, 'ACTIVE', 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY5RENDQTl5Z0F3SUJBZ0lSQU85dFIvVGx2Y2pqZ1dkMFlCTEJEMGN3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlJVTlRMVTFoYm5WbVlXTjBkWEpwYm1jd0hoY05NalF4TVRJMU1EazBOVFE0V2hjTgpNalV3T1RJeE1EazBOVFEwV2pBY01Sb3dHQVlEVlFRREV4RkZRMU10VFdGdWRXWmhZM1IxY21sdVp6Q0NBaUl3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFOQllQKytacmZNY2MzL1BiTXVVYjBVcklMMVEKb2Jtbm41TllWdXJkU1c2ZEhZMEF3ajQzbmhlTndtV3NPbGt5bmR3UGNmVWdpWnlsS1dpVzcxUlFsMGF1bWFZLworczFVcnhjQXhidFFCOGQ3c3dBd2xYZ0xoMk1XR3ppUm4wUjBuNDJkRDdxVFdZWXIwcFRnbkc1WG82LzV1ak5iCmlSVzZaWXA4ZzNuM1BCbWFhbFRRVmxmRWgzNHBIbFU5SThFUExUdmFvMnFXU01RSlY4WDM5Y1VDdjBib0RKVEwKa0daaWpxTVM0dEoyR3NRWHo4UE8yTk83UHlXVndLWlgvSE5tYTA1NWlZV0tzNi9GN2I3bEY3YkNEQVFMalVCdwphWldWOW00VmpwRWpCMEc0WTkzTm5VMFNqVUxzR2ZFYVRlblovVk5zMXBZZ3hJcHRXWFdtZUdBT3RJWi90bFJ0CmwyTitweTVZenFtQ2tYbjZxRlRpb3ZyN1huTjFWSkxRblJKMkhSZUxWVUJ6K21TWmMzSmRXOHd6QmgvWTVtYUgKK1RpZ0dyTnIrcFZVZi9vNTZ6ZS9pblAzWUUvdERoUG5FRk1PSVBCbGdyZktlcFRKOVd6dmtPWHNkb1hwR2RHYQp6QlIwNTl1N05uVFpEQzBsc3ByKzJWMTVGVVhIMXRyelg3Nmk4QSt5bVJRak45U2NhTWlhemlzWUdSU09XNVRTClhJZ0VkSVM0YXg4TWQ1Skd5TStFVVdyQ2pwaHRaamVlQzNvdjY0R25mSWdiL1lOTFNQUi9FeHhwekJwNjN4d3AKdS8wWnZaRTZVNVBNTExwNkF0RzkzY2h2NTFVdE1lVVAzYXlQaUF4OEhZTmp3L0djN2VHKzZ1cnhYMVFnakpHSQp1MWNqU3djTE00dFA4aXdMQWdNQkFBR2pnZ0V2TUlJQkt6QU9CZ05WSFE4QkFmOEVCQU1DQVpZd0hRWURWUjBsCkJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3TFFZRFZSME8KQkNZRUpEbGlaV1ZpWXpWaUxXSmhPR1F0Tkdaak1DMDVaVGszTFRVNE1qazVaRE13WVdVNVpqQXZCZ05WSFNNRQpLREFtZ0NRNVltVmxZbU0xWWkxaVlUaGtMVFJtWXpBdE9XVTVOeTAxT0RJNU9XUXpNR0ZsT1dZd053WUlLd1lCCkJRVUhBUUVFS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWoKYzNBd1VBWURWUjBmQkVrd1J6QkZvRU9nUVlZL2FIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dgpPV0psWldKak5XSXRZbUU0WkMwMFptTXdMVGxsT1RjdE5UZ3lPVGxrTXpCaFpUbG1NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElDQVFDQ1pTOG5pRStxeEdBYjJjSVhVWW4rRHNJVGRwZXFnM3BQRU1EZU5DR29rUUY4cGcwbkpOdjcKZURmaTR3TEp2ZlBRK0lzNjNLYnU4dVBoanpYcnVrWUE3VWgyTmJRZnJHM1d3L3JDUGlJTkVZNktjNmltdnk1RApyK2NIbFJKYkEyaE9yNTd3Tnc0b2RrMERsdkdIbVN6M2hOWXFxcWZJcEYxMEYwdUNTNllOV1AvUHU1VFVaN2V4CkFPTjF2aWZMdFBGcGFnYkxPd3k5K3JicStHUkZET0ZSRjlzYzdBUHdoWVpUZTdHSnFNblZKbklPOU1Qd01idDEKMW1KRHNJTzlqTkhNVkVMbzBGWVRhOE05K29EWE1CaThzRWN5aER0ZlN1ZUU5bU9wWkhFck1Wb2s5aTd6Y2FObwp4OEFBZTNHRFU5MDB1SlB1Y0t3TmprVjZpL21FMk1maXBCYTMxV3NHcUdNbjY3MDBoSjJhS00wcjVIRnhhK3l4CnMzMVArQ1hCZjF4THBaYTBPY3ZTTFJuTzJtSFhnTTlzRGRsdW5WZkEzOGFoU2Zna1ZBK1BQU1EvTTFZTVUxT1YKRTIvdlNvUjR0elF4QU9wU3RjaUxGUFpxczcrY0ZJbzlKSk5aZnNNR2ZKempDbFBlRU91VFJ0YklmR0FEc1VzeQp0MmdtdDZMeDhSc2M1V0NXanNGMjFjR3FKZjB3TlJHcloyb20xTnlRcjhDZTdmQ1Y1dWY0dlNJMEZkVGU3cE5WCjNKKzJwa3ZDV05TVUdyNktmUEw2OGw1YnhiVWl0d294N0doV0dZT2IwaEp5b2V4VC92MmNiQys2WWNDUXZCSFUKeUR6bU1EZVFVQkVJeXhFRk96bE5uZlZxRnNQbmVJT2ZhbWNNaHd1VkdRSUhMdWhIK0gwdDVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=', 1, 4096, 'HIGH', 'ECS-Manufacturing', '', '', '', '', '', '2024-11-25 9:45:48.000', '2025-09-21 11:45:44.000', '0001-01-01 01:00:00.000', 0, 'MANAGED', 'filesystem-1', '9beebc5b-ba8d-4fc0-9e97-58299d30ae9f', '{"type":"Duration","duration":"14w2d","time":""}', '2024-11-25 11:45:48.620', 0);
	`)

	var result map[string]interface{}
	tx := con.Raw("SELECT * FROM ca_certificates").Scan(&result)
	if tx.RowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", tx.RowsAffected)
	}

	assert.Equal(t, "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47", result["serial_number"])
	assert.Equal(t, "9beebc5b-ba8d-4fc0-9e97-58299d30ae9f", result["issuer_meta_id"])
	assert.Equal(t, "ACTIVE", result["status"])
	assert.Equal(t, "filesystem-1", result["engine_id"])
	assertEqualD(t, time.Date(2024, time.November, 25, 9, 45, 48, 0, time.UTC), result["valid_from"].(time.Time))
	assertEqualD(t, time.Date(2025, time.September, 21, 11, 45, 44, 0, time.UTC), result["valid_to"].(time.Time))
	assert.Equal(t, "MANAGED", result["type"])
	assert.Equal(t, "9beebc5b-ba8d-4fc0-9e97-58299d30ae9f", result["id"])
	assertEqualD(t, time.Date(2024, time.November, 25, 11, 45, 48, 620000000, time.UTC), result["creation_ts"].(time.Time))
	assert.Equal(t, int64(0), result["level"])
	assert.Equal(t, "{}", result["metadata"])
	assert.Equal(t, "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47", result["issuer_meta_serial_number"])
	assert.Equal(t, int64(0), result["issuer_meta_level"])
	assert.Equal(t, int64(1), result["key_strength_meta_type"])
	assert.Equal(t, int64(4096), result["key_strength_meta_bits"])
	assert.Equal(t, "HIGH", result["key_strength_meta_strength"])
	assertEqualD(t, time.Time(time.Date(1, time.January, 1, 1, 0, 0, 0, time.UTC)), result["revocation_timestamp"].(time.Time))
	assert.Equal(t, int64(0), result["revocation_reason"])
	assert.Equal(t, `{"type":"Duration","duration":"14w2d","time":""}`, result["issuance_expiration_ref"])
	assert.Equal(t, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY5RENDQTl5Z0F3SUJBZ0lSQU85dFIvVGx2Y2pqZ1dkMFlCTEJEMGN3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlJVTlRMVTFoYm5WbVlXTjBkWEpwYm1jd0hoY05NalF4TVRJMU1EazBOVFE0V2hjTgpNalV3T1RJeE1EazBOVFEwV2pBY01Sb3dHQVlEVlFRREV4RkZRMU10VFdGdWRXWmhZM1IxY21sdVp6Q0NBaUl3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFOQllQKytacmZNY2MzL1BiTXVVYjBVcklMMVEKb2Jtbm41TllWdXJkU1c2ZEhZMEF3ajQzbmhlTndtV3NPbGt5bmR3UGNmVWdpWnlsS1dpVzcxUlFsMGF1bWFZLworczFVcnhjQXhidFFCOGQ3c3dBd2xYZ0xoMk1XR3ppUm4wUjBuNDJkRDdxVFdZWXIwcFRnbkc1WG82LzV1ak5iCmlSVzZaWXA4ZzNuM1BCbWFhbFRRVmxmRWgzNHBIbFU5SThFUExUdmFvMnFXU01RSlY4WDM5Y1VDdjBib0RKVEwKa0daaWpxTVM0dEoyR3NRWHo4UE8yTk83UHlXVndLWlgvSE5tYTA1NWlZV0tzNi9GN2I3bEY3YkNEQVFMalVCdwphWldWOW00VmpwRWpCMEc0WTkzTm5VMFNqVUxzR2ZFYVRlblovVk5zMXBZZ3hJcHRXWFdtZUdBT3RJWi90bFJ0CmwyTitweTVZenFtQ2tYbjZxRlRpb3ZyN1huTjFWSkxRblJKMkhSZUxWVUJ6K21TWmMzSmRXOHd6QmgvWTVtYUgKK1RpZ0dyTnIrcFZVZi9vNTZ6ZS9pblAzWUUvdERoUG5FRk1PSVBCbGdyZktlcFRKOVd6dmtPWHNkb1hwR2RHYQp6QlIwNTl1N05uVFpEQzBsc3ByKzJWMTVGVVhIMXRyelg3Nmk4QSt5bVJRak45U2NhTWlhemlzWUdSU09XNVRTClhJZ0VkSVM0YXg4TWQ1Skd5TStFVVdyQ2pwaHRaamVlQzNvdjY0R25mSWdiL1lOTFNQUi9FeHhwekJwNjN4d3AKdS8wWnZaRTZVNVBNTExwNkF0RzkzY2h2NTFVdE1lVVAzYXlQaUF4OEhZTmp3L0djN2VHKzZ1cnhYMVFnakpHSQp1MWNqU3djTE00dFA4aXdMQWdNQkFBR2pnZ0V2TUlJQkt6QU9CZ05WSFE4QkFmOEVCQU1DQVpZd0hRWURWUjBsCkJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3TFFZRFZSME8KQkNZRUpEbGlaV1ZpWXpWaUxXSmhPR1F0Tkdaak1DMDVaVGszTFRVNE1qazVaRE13WVdVNVpqQXZCZ05WSFNNRQpLREFtZ0NRNVltVmxZbU0xWWkxaVlUaGtMVFJtWXpBdE9XVTVOeTAxT0RJNU9XUXpNR0ZsT1dZd053WUlLd1lCCkJRVUhBUUVFS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWoKYzNBd1VBWURWUjBmQkVrd1J6QkZvRU9nUVlZL2FIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dgpPV0psWldKak5XSXRZbUU0WkMwMFptTXdMVGxsT1RjdE5UZ3lPVGxrTXpCaFpUbG1NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElDQVFDQ1pTOG5pRStxeEdBYjJjSVhVWW4rRHNJVGRwZXFnM3BQRU1EZU5DR29rUUY4cGcwbkpOdjcKZURmaTR3TEp2ZlBRK0lzNjNLYnU4dVBoanpYcnVrWUE3VWgyTmJRZnJHM1d3L3JDUGlJTkVZNktjNmltdnk1RApyK2NIbFJKYkEyaE9yNTd3Tnc0b2RrMERsdkdIbVN6M2hOWXFxcWZJcEYxMEYwdUNTNllOV1AvUHU1VFVaN2V4CkFPTjF2aWZMdFBGcGFnYkxPd3k5K3JicStHUkZET0ZSRjlzYzdBUHdoWVpUZTdHSnFNblZKbklPOU1Qd01idDEKMW1KRHNJTzlqTkhNVkVMbzBGWVRhOE05K29EWE1CaThzRWN5aER0ZlN1ZUU5bU9wWkhFck1Wb2s5aTd6Y2FObwp4OEFBZTNHRFU5MDB1SlB1Y0t3TmprVjZpL21FMk1maXBCYTMxV3NHcUdNbjY3MDBoSjJhS00wcjVIRnhhK3l4CnMzMVArQ1hCZjF4THBaYTBPY3ZTTFJuTzJtSFhnTTlzRGRsdW5WZkEzOGFoU2Zna1ZBK1BQU1EvTTFZTVUxT1YKRTIvdlNvUjR0elF4QU9wU3RjaUxGUFpxczcrY0ZJbzlKSk5aZnNNR2ZKempDbFBlRU91VFJ0YklmR0FEc1VzeQp0MmdtdDZMeDhSc2M1V0NXanNGMjFjR3FKZjB3TlJHcloyb20xTnlRcjhDZTdmQ1Y1dWY0dlNJMEZkVGU3cE5WCjNKKzJwa3ZDV05TVUdyNktmUEw2OGw1YnhiVWl0d294N0doV0dZT2IwaEp5b2V4VC92MmNiQys2WWNDUXZCSFUKeUR6bU1EZVFVQkVJeXhFRk96bE5uZlZxRnNQbmVJT2ZhbWNNaHd1VkdRSUhMdWhIK0gwdDVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", result["certificate"])

	tx = con.Raw("SELECT * FROM certificates")
	assert.Equal(t, int64(0), tx.RowsAffected)
}

func MigrationTest_CA_20241215165048_add_key_id(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, CADBName)

	var result map[string]interface{}
	tx := con.Raw("SELECT * FROM ca_certificates").Scan(&result)
	if tx.RowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", tx.RowsAffected)
	}

	assert.Equal(t, "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47", result["serial_number"])
	assert.Equal(t, "9beebc5b-ba8d-4fc0-9e97-58299d30ae9f", result["issuer_meta_id"])
	assert.Equal(t, "ACTIVE", result["status"])
	assert.Equal(t, "filesystem-1", result["engine_id"])
	assertEqualD(t, time.Date(2024, time.November, 25, 9, 45, 48, 0, time.UTC), result["valid_from"].(time.Time))
	assertEqualD(t, time.Date(2025, time.September, 21, 11, 45, 44, 0, time.UTC), result["valid_to"].(time.Time))
	assert.Equal(t, "MANAGED", result["type"])
	assert.Equal(t, "9beebc5b-ba8d-4fc0-9e97-58299d30ae9f", result["id"])
	assertEqualD(t, time.Date(2024, time.November, 25, 11, 45, 48, 620000000, time.UTC), result["creation_ts"].(time.Time))
	assert.Equal(t, int64(0), result["level"])
	assert.Equal(t, "{}", result["metadata"])
	assert.Equal(t, "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47", result["issuer_meta_serial_number"])
	assert.Equal(t, int64(0), result["issuer_meta_level"])
	assert.Equal(t, int64(1), result["key_strength_meta_type"])
	assert.Equal(t, int64(4096), result["key_strength_meta_bits"])
	assert.Equal(t, "HIGH", result["key_strength_meta_strength"])
	assertEqualD(t, time.Time(time.Date(1, time.January, 1, 1, 0, 0, 0, time.UTC)), result["revocation_timestamp"].(time.Time))
	assert.Equal(t, int64(0), result["revocation_reason"])
	assert.Equal(t, `{"type":"Duration","duration":"14w2d","time":""}`, result["issuance_expiration_ref"])
	assert.Equal(t, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY5RENDQTl5Z0F3SUJBZ0lSQU85dFIvVGx2Y2pqZ1dkMFlCTEJEMGN3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlJVTlRMVTFoYm5WbVlXTjBkWEpwYm1jd0hoY05NalF4TVRJMU1EazBOVFE0V2hjTgpNalV3T1RJeE1EazBOVFEwV2pBY01Sb3dHQVlEVlFRREV4RkZRMU10VFdGdWRXWmhZM1IxY21sdVp6Q0NBaUl3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFOQllQKytacmZNY2MzL1BiTXVVYjBVcklMMVEKb2Jtbm41TllWdXJkU1c2ZEhZMEF3ajQzbmhlTndtV3NPbGt5bmR3UGNmVWdpWnlsS1dpVzcxUlFsMGF1bWFZLworczFVcnhjQXhidFFCOGQ3c3dBd2xYZ0xoMk1XR3ppUm4wUjBuNDJkRDdxVFdZWXIwcFRnbkc1WG82LzV1ak5iCmlSVzZaWXA4ZzNuM1BCbWFhbFRRVmxmRWgzNHBIbFU5SThFUExUdmFvMnFXU01RSlY4WDM5Y1VDdjBib0RKVEwKa0daaWpxTVM0dEoyR3NRWHo4UE8yTk83UHlXVndLWlgvSE5tYTA1NWlZV0tzNi9GN2I3bEY3YkNEQVFMalVCdwphWldWOW00VmpwRWpCMEc0WTkzTm5VMFNqVUxzR2ZFYVRlblovVk5zMXBZZ3hJcHRXWFdtZUdBT3RJWi90bFJ0CmwyTitweTVZenFtQ2tYbjZxRlRpb3ZyN1huTjFWSkxRblJKMkhSZUxWVUJ6K21TWmMzSmRXOHd6QmgvWTVtYUgKK1RpZ0dyTnIrcFZVZi9vNTZ6ZS9pblAzWUUvdERoUG5FRk1PSVBCbGdyZktlcFRKOVd6dmtPWHNkb1hwR2RHYQp6QlIwNTl1N05uVFpEQzBsc3ByKzJWMTVGVVhIMXRyelg3Nmk4QSt5bVJRak45U2NhTWlhemlzWUdSU09XNVRTClhJZ0VkSVM0YXg4TWQ1Skd5TStFVVdyQ2pwaHRaamVlQzNvdjY0R25mSWdiL1lOTFNQUi9FeHhwekJwNjN4d3AKdS8wWnZaRTZVNVBNTExwNkF0RzkzY2h2NTFVdE1lVVAzYXlQaUF4OEhZTmp3L0djN2VHKzZ1cnhYMVFnakpHSQp1MWNqU3djTE00dFA4aXdMQWdNQkFBR2pnZ0V2TUlJQkt6QU9CZ05WSFE4QkFmOEVCQU1DQVpZd0hRWURWUjBsCkJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3TFFZRFZSME8KQkNZRUpEbGlaV1ZpWXpWaUxXSmhPR1F0Tkdaak1DMDVaVGszTFRVNE1qazVaRE13WVdVNVpqQXZCZ05WSFNNRQpLREFtZ0NRNVltVmxZbU0xWWkxaVlUaGtMVFJtWXpBdE9XVTVOeTAxT0RJNU9XUXpNR0ZsT1dZd053WUlLd1lCCkJRVUhBUUVFS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWoKYzNBd1VBWURWUjBmQkVrd1J6QkZvRU9nUVlZL2FIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dgpPV0psWldKak5XSXRZbUU0WkMwMFptTXdMVGxsT1RjdE5UZ3lPVGxrTXpCaFpUbG1NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElDQVFDQ1pTOG5pRStxeEdBYjJjSVhVWW4rRHNJVGRwZXFnM3BQRU1EZU5DR29rUUY4cGcwbkpOdjcKZURmaTR3TEp2ZlBRK0lzNjNLYnU4dVBoanpYcnVrWUE3VWgyTmJRZnJHM1d3L3JDUGlJTkVZNktjNmltdnk1RApyK2NIbFJKYkEyaE9yNTd3Tnc0b2RrMERsdkdIbVN6M2hOWXFxcWZJcEYxMEYwdUNTNllOV1AvUHU1VFVaN2V4CkFPTjF2aWZMdFBGcGFnYkxPd3k5K3JicStHUkZET0ZSRjlzYzdBUHdoWVpUZTdHSnFNblZKbklPOU1Qd01idDEKMW1KRHNJTzlqTkhNVkVMbzBGWVRhOE05K29EWE1CaThzRWN5aER0ZlN1ZUU5bU9wWkhFck1Wb2s5aTd6Y2FObwp4OEFBZTNHRFU5MDB1SlB1Y0t3TmprVjZpL21FMk1maXBCYTMxV3NHcUdNbjY3MDBoSjJhS00wcjVIRnhhK3l4CnMzMVArQ1hCZjF4THBaYTBPY3ZTTFJuTzJtSFhnTTlzRGRsdW5WZkEzOGFoU2Zna1ZBK1BQU1EvTTFZTVUxT1YKRTIvdlNvUjR0elF4QU9wU3RjaUxGUFpxczcrY0ZJbzlKSk5aZnNNR2ZKempDbFBlRU91VFJ0YklmR0FEc1VzeQp0MmdtdDZMeDhSc2M1V0NXanNGMjFjR3FKZjB3TlJHcloyb20xTnlRcjhDZTdmQ1Y1dWY0dlNJMEZkVGU3cE5WCjNKKzJwa3ZDV05TVUdyNktmUEw2OGw1YnhiVWl0d294N0doV0dZT2IwaEp5b2V4VC92MmNiQys2WWNDUXZCSFUKeUR6bU1EZVFVQkVJeXhFRk96bE5uZlZxRnNQbmVJT2ZhbWNNaHd1VkdRSUhMdWhIK0gwdDVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", result["certificate"])
	assert.Equal(t, "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47", result["key_id"])
}

func MigrationTest_CA_20241223183344_unified_ca_models(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, CADBName)

	caRepo, err := postgres.NewCAPostgresRepository(logger, con)
	if err != nil {
		t.Fatalf("could not create ca repository: %s", err)
	}

	certRepo, err := postgres.NewCertificateRepository(logger, con)
	if err != nil {
		t.Fatalf("could not create certificate repository: %s", err)
	}

	ctrCAs, err := caRepo.Count(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 0, ctrCAs)

	ctrCerts, err := certRepo.Count(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 0, ctrCerts)

	crtB64 := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY5RENDQTl5Z0F3SUJBZ0lSQU85dFIvVGx2Y2pqZ1dkMFlCTEJEMGN3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlJVTlRMVTFoYm5WbVlXTjBkWEpwYm1jd0hoY05NalF4TVRJMU1EazBOVFE0V2hjTgpNalV3T1RJeE1EazBOVFEwV2pBY01Sb3dHQVlEVlFRREV4RkZRMU10VFdGdWRXWmhZM1IxY21sdVp6Q0NBaUl3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFOQllQKytacmZNY2MzL1BiTXVVYjBVcklMMVEKb2Jtbm41TllWdXJkU1c2ZEhZMEF3ajQzbmhlTndtV3NPbGt5bmR3UGNmVWdpWnlsS1dpVzcxUlFsMGF1bWFZLworczFVcnhjQXhidFFCOGQ3c3dBd2xYZ0xoMk1XR3ppUm4wUjBuNDJkRDdxVFdZWXIwcFRnbkc1WG82LzV1ak5iCmlSVzZaWXA4ZzNuM1BCbWFhbFRRVmxmRWgzNHBIbFU5SThFUExUdmFvMnFXU01RSlY4WDM5Y1VDdjBib0RKVEwKa0daaWpxTVM0dEoyR3NRWHo4UE8yTk83UHlXVndLWlgvSE5tYTA1NWlZV0tzNi9GN2I3bEY3YkNEQVFMalVCdwphWldWOW00VmpwRWpCMEc0WTkzTm5VMFNqVUxzR2ZFYVRlblovVk5zMXBZZ3hJcHRXWFdtZUdBT3RJWi90bFJ0CmwyTitweTVZenFtQ2tYbjZxRlRpb3ZyN1huTjFWSkxRblJKMkhSZUxWVUJ6K21TWmMzSmRXOHd6QmgvWTVtYUgKK1RpZ0dyTnIrcFZVZi9vNTZ6ZS9pblAzWUUvdERoUG5FRk1PSVBCbGdyZktlcFRKOVd6dmtPWHNkb1hwR2RHYQp6QlIwNTl1N05uVFpEQzBsc3ByKzJWMTVGVVhIMXRyelg3Nmk4QSt5bVJRak45U2NhTWlhemlzWUdSU09XNVRTClhJZ0VkSVM0YXg4TWQ1Skd5TStFVVdyQ2pwaHRaamVlQzNvdjY0R25mSWdiL1lOTFNQUi9FeHhwekJwNjN4d3AKdS8wWnZaRTZVNVBNTExwNkF0RzkzY2h2NTFVdE1lVVAzYXlQaUF4OEhZTmp3L0djN2VHKzZ1cnhYMVFnakpHSQp1MWNqU3djTE00dFA4aXdMQWdNQkFBR2pnZ0V2TUlJQkt6QU9CZ05WSFE4QkFmOEVCQU1DQVpZd0hRWURWUjBsCkJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3TFFZRFZSME8KQkNZRUpEbGlaV1ZpWXpWaUxXSmhPR1F0Tkdaak1DMDVaVGszTFRVNE1qazVaRE13WVdVNVpqQXZCZ05WSFNNRQpLREFtZ0NRNVltVmxZbU0xWWkxaVlUaGtMVFJtWXpBdE9XVTVOeTAxT0RJNU9XUXpNR0ZsT1dZd053WUlLd1lCCkJRVUhBUUVFS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWoKYzNBd1VBWURWUjBmQkVrd1J6QkZvRU9nUVlZL2FIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dgpPV0psWldKak5XSXRZbUU0WkMwMFptTXdMVGxsT1RjdE5UZ3lPVGxrTXpCaFpUbG1NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElDQVFDQ1pTOG5pRStxeEdBYjJjSVhVWW4rRHNJVGRwZXFnM3BQRU1EZU5DR29rUUY4cGcwbkpOdjcKZURmaTR3TEp2ZlBRK0lzNjNLYnU4dVBoanpYcnVrWUE3VWgyTmJRZnJHM1d3L3JDUGlJTkVZNktjNmltdnk1RApyK2NIbFJKYkEyaE9yNTd3Tnc0b2RrMERsdkdIbVN6M2hOWXFxcWZJcEYxMEYwdUNTNllOV1AvUHU1VFVaN2V4CkFPTjF2aWZMdFBGcGFnYkxPd3k5K3JicStHUkZET0ZSRjlzYzdBUHdoWVpUZTdHSnFNblZKbklPOU1Qd01idDEKMW1KRHNJTzlqTkhNVkVMbzBGWVRhOE05K29EWE1CaThzRWN5aER0ZlN1ZUU5bU9wWkhFck1Wb2s5aTd6Y2FObwp4OEFBZTNHRFU5MDB1SlB1Y0t3TmprVjZpL21FMk1maXBCYTMxV3NHcUdNbjY3MDBoSjJhS00wcjVIRnhhK3l4CnMzMVArQ1hCZjF4THBaYTBPY3ZTTFJuTzJtSFhnTTlzRGRsdW5WZkEzOGFoU2Zna1ZBK1BQU1EvTTFZTVUxT1YKRTIvdlNvUjR0elF4QU9wU3RjaUxGUFpxczcrY0ZJbzlKSk5aZnNNR2ZKempDbFBlRU91VFJ0YklmR0FEc1VzeQp0MmdtdDZMeDhSc2M1V0NXanNGMjFjR3FKZjB3TlJHcloyb20xTnlRcjhDZTdmQ1Y1dWY0dlNJMEZkVGU3cE5WCjNKKzJwa3ZDV05TVUdyNktmUEw2OGw1YnhiVWl0d294N0doV0dZT2IwaEp5b2V4VC92MmNiQys2WWNDUXZCSFUKeUR6bU1EZVFVQkVJeXhFRk96bE5uZlZxRnNQbmVJT2ZhbWNNaHd1VkdRSUhMdWhIK0gwdDVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	crtBytes, err := base64.StdEncoding.DecodeString(crtB64)
	if err != nil {
		t.Fatalf("could not decode certificate: %s", err)
	}

	crt, err := helpers.ParseCertificate(string(crtBytes))
	if err != nil {
		t.Fatalf("could not parse certificate: %s", err)
	}

	_, err = caRepo.Insert(context.Background(), &models.CACertificate{
		ID: "1111-2222-3333-4444",
		Certificate: models.Certificate{
			Certificate:  (*models.X509Certificate)(crt),
			SerialNumber: "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47",
			KeyID:        "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47",
			Status:       models.StatusActive,
			Subject:      models.Subject{CommonName: "ECS-Manufacturing"},
			Metadata:     map[string]interface{}{},
			EngineID:     "filesystem-1",
			ValidFrom:    time.Date(2024, time.November, 25, 9, 45, 48, 0, time.UTC),
			ValidTo:      time.Date(2025, time.September, 21, 11, 45, 44, 0, time.UTC),
			Type:         models.CertificateTypeManaged,
			KeyMetadata:  models.KeyStrengthMetadata{Type: models.KeyType(x509.RSA), Bits: 4096, Strength: models.KeyStrengthHigh},
			IssuerCAMetadata: models.IssuerCAMetadata{
				SN:    "ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47",
				ID:    "1111-2222-3333-4444",
				Level: 0,
			},
		},
	})
	if err != nil {
		t.Fatalf("could not insert certificate: %s", err)
	}

	ctrCAs, err = caRepo.Count(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 1, ctrCAs)

	ctrCerts, err = certRepo.Count(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 1, ctrCerts)
}

func TestMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Trace, "test", "test")
	cleanup, con := RunDB(t, logger, CADBName)

	defer cleanup()

	MigrationTest_CA_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	MigrationTest_CA_20241215165048_add_key_id(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20241215165048_add_key_id")
	}

	CleanAllTables(t, logger, con)

	MigrationTest_CA_20241223183344_unified_ca_models(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20241223183344_unified_ca_models")
	}
}
