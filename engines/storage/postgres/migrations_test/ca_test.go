package migrationstest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
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

	certRepo, err := postgres.NewCertificateRepository(logger, con)
	if err != nil {
		t.Fatalf("could not create certificate repository: %s", err)
	}

	ctrCAs, err := certRepo.CountCA(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 0, ctrCAs)

	ctrCerts, err := certRepo.Count(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 0, ctrCerts)

	con.Exec(`INSERT INTO "certificates"
	("serial_number","key_id","metadata","status","certificate","key_meta_type","key_meta_bits","key_meta_strength","subject_common_name","subject_organization","subject_organization_unit","subject_country","subject_state","subject_locality","valid_from","issuer_meta_serial_number","issuer_meta_id","issuer_meta_level","valid_to","revocation_timestamp","revocation_reason","type","engine_id")
	VALUES ('ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47','ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47','{}','ACTIVE','LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY5RENDQTl5Z0F3SUJBZ0lSQU85dFIvVGx2Y2pqZ1dkMFlCTEJEMGN3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlJVTlRMVTFoYm5WbVlXTjBkWEpwYm1jd0hoY05NalF4TVRJMU1EazBOVFE0V2hjTgpNalV3T1RJeE1EazBOVFEwV2pBY01Sb3dHQVlEVlFRREV4RkZRMU10VFdGdWRXWmhZM1IxY21sdVp6Q0NBaUl3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFOQllQKytacmZNY2MzL1BiTXVVYjBVcklMMVEKb2Jtbm41TllWdXJkU1c2ZEhZMEF3ajQzbmhlTndtV3NPbGt5bmR3UGNmVWdpWnlsS1dpVzcxUlFsMGF1bWFZLworczFVcnhjQXhidFFCOGQ3c3dBd2xYZ0xoMk1XR3ppUm4wUjBuNDJkRDdxVFdZWXIwcFRnbkc1WG82LzV1ak5iCmlSVzZaWXA4ZzNuM1BCbWFhbFRRVmxmRWgzNHBIbFU5SThFUExUdmFvMnFXU01RSlY4WDM5Y1VDdjBib0RKVEwKa0daaWpxTVM0dEoyR3NRWHo4UE8yTk83UHlXVndLWlgvSE5tYTA1NWlZV0tzNi9GN2I3bEY3YkNEQVFMalVCdwphWldWOW00VmpwRWpCMEc0WTkzTm5VMFNqVUxzR2ZFYVRlblovVk5zMXBZZ3hJcHRXWFdtZUdBT3RJWi90bFJ0CmwyTitweTVZenFtQ2tYbjZxRlRpb3ZyN1huTjFWSkxRblJKMkhSZUxWVUJ6K21TWmMzSmRXOHd6QmgvWTVtYUgKK1RpZ0dyTnIrcFZVZi9vNTZ6ZS9pblAzWUUvdERoUG5FRk1PSVBCbGdyZktlcFRKOVd6dmtPWHNkb1hwR2RHYQp6QlIwNTl1N05uVFpEQzBsc3ByKzJWMTVGVVhIMXRyelg3Nmk4QSt5bVJRak45U2NhTWlhemlzWUdSU09XNVRTClhJZ0VkSVM0YXg4TWQ1Skd5TStFVVdyQ2pwaHRaamVlQzNvdjY0R25mSWdiL1lOTFNQUi9FeHhwekJwNjN4d3AKdS8wWnZaRTZVNVBNTExwNkF0RzkzY2h2NTFVdE1lVVAzYXlQaUF4OEhZTmp3L0djN2VHKzZ1cnhYMVFnakpHSQp1MWNqU3djTE00dFA4aXdMQWdNQkFBR2pnZ0V2TUlJQkt6QU9CZ05WSFE4QkFmOEVCQU1DQVpZd0hRWURWUjBsCkJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3TFFZRFZSME8KQkNZRUpEbGlaV1ZpWXpWaUxXSmhPR1F0Tkdaak1DMDVaVGszTFRVNE1qazVaRE13WVdVNVpqQXZCZ05WSFNNRQpLREFtZ0NRNVltVmxZbU0xWWkxaVlUaGtMVFJtWXpBdE9XVTVOeTAxT0RJNU9XUXpNR0ZsT1dZd053WUlLd1lCCkJRVUhBUUVFS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWoKYzNBd1VBWURWUjBmQkVrd1J6QkZvRU9nUVlZL2FIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dgpPV0psWldKak5XSXRZbUU0WkMwMFptTXdMVGxsT1RjdE5UZ3lPVGxrTXpCaFpUbG1NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElDQVFDQ1pTOG5pRStxeEdBYjJjSVhVWW4rRHNJVGRwZXFnM3BQRU1EZU5DR29rUUY4cGcwbkpOdjcKZURmaTR3TEp2ZlBRK0lzNjNLYnU4dVBoanpYcnVrWUE3VWgyTmJRZnJHM1d3L3JDUGlJTkVZNktjNmltdnk1RApyK2NIbFJKYkEyaE9yNTd3Tnc0b2RrMERsdkdIbVN6M2hOWXFxcWZJcEYxMEYwdUNTNllOV1AvUHU1VFVaN2V4CkFPTjF2aWZMdFBGcGFnYkxPd3k5K3JicStHUkZET0ZSRjlzYzdBUHdoWVpUZTdHSnFNblZKbklPOU1Qd01idDEKMW1KRHNJTzlqTkhNVkVMbzBGWVRhOE05K29EWE1CaThzRWN5aER0ZlN1ZUU5bU9wWkhFck1Wb2s5aTd6Y2FObwp4OEFBZTNHRFU5MDB1SlB1Y0t3TmprVjZpL21FMk1maXBCYTMxV3NHcUdNbjY3MDBoSjJhS00wcjVIRnhhK3l4CnMzMVArQ1hCZjF4THBaYTBPY3ZTTFJuTzJtSFhnTTlzRGRsdW5WZkEzOGFoU2Zna1ZBK1BQU1EvTTFZTVUxT1YKRTIvdlNvUjR0elF4QU9wU3RjaUxGUFpxczcrY0ZJbzlKSk5aZnNNR2ZKempDbFBlRU91VFJ0YklmR0FEc1VzeQp0MmdtdDZMeDhSc2M1V0NXanNGMjFjR3FKZjB3TlJHcloyb20xTnlRcjhDZTdmQ1Y1dWY0dlNJMEZkVGU3cE5WCjNKKzJwa3ZDV05TVUdyNktmUEw2OGw1YnhiVWl0d294N0doV0dZT2IwaEp5b2V4VC92MmNiQys2WWNDUXZCSFUKeUR6bU1EZVFVQkVJeXhFRk96bE5uZlZxRnNQbmVJT2ZhbWNNaHd1VkdRSUhMdWhIK0gwdDVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=','RSA',4096,'HIGH','ECS-Manufacturing','','','','','','2024-11-25 09:45:48','ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47','1111-2222-3333-4444',0,'2025-09-21 11:45:44','2025-11-03 15:51:41.000','Unspecified','MANAGED','filesystem-1')
	`)

	con.Exec(`INSERT INTO "ca_certificates" 
	("id","serial_number","metadata","validity_type","validity_duration","validity_time","creation_ts","level") 
	VALUES ('1111-2222-3333-4444','ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47',NULL,'','0s',NULL,NULL,0)
	`)

	ctrCAs, err = certRepo.CountCA(context.Background())
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

func MigrationTest_CA_20250107164937_add_is_ca(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	//Add 2 CAs (1 Root and SubCA)
	con.Exec(`INSERT INTO certificates
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id)
		VALUES('99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '{}', '99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '8b600c60-9eb3-4251-b6ce-c92d1beccc63', 0, 'ACTIVE', 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdPakNDQkNLZ0F3SUJBZ0lSQUpuZ0ptQkxrSTArVUplWXNCYmIxbmt3RFFZSktvWklodmNOQVFFTEJRQXcKRlRFVE1CRUdBMVVFQXhNS1VtOXZkQzFEUVMxV01UQWVGdzB5TlRBeE1EY3hORFV4TlRsYUZ3MHlOVEV4TURNeApORFV4TlRSYU1CVXhFekFSQmdOVkJBTVRDbEp2YjNRdFEwRXRWakV3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBCkE0SUNEd0F3Z2dJS0FvSUNBUUMzTTZYdDJNSWlVR21LNXpUUlVvZlZzazdtQ1ZZMWlkbXdLSythd0M0anZzWWoKM0JiZW5zZXVJaUo3NEg5TnZZdnhYZ0xDNVE3NXJ5UmJzNHN5TzBpV2YxUlJtamFVVUdxbHlkMmFLNVlIM3JWYgpXZ0htTkJMU2Q0dVlTRit3dno0Vk9Ic24zT1kvbFBTUkRwSm11ajJ3ekhYZ1p5RVR6M1Bzd1hhT0xXY3RsZFUvCm11eUJPWHE0bTFwNHh6dy83N0R2bW53Ni9mRXYwdG9iRVBYdVdvdlhSaS84NHQ2c0g5K1VDWmI5U3JTdFJWTHEKTGhsUEVQUC9SOXVveHBsVElTNllyQ2VHdWlPM2ViOGtmRVVETVdKS2pFbktueUx2b1RmbFVOMGE0K1docEFSSQp3WXgwSm9zQzhrb0xLV29ScFdJSlVlOC9hZStNWXRmWW1JNUdacGRIdnk1ZngzbXB5R2hseUJhWVRSOER2dkdvCmN1S0pabm16MVFuamYzM0syZFAxbk1RVHJhalJlWS9aMnd6bmRQbjg0SWdoWnJRc2NpSXYxcXg3Z3Y4Y3BuK0QKWTJuRUJUTHBPRHNIQXhKcmEyTGZZaXFYNnQzaUNCNEkrLzQ2djFBSitBWmJYMnRSVUpsakpSeHBqbkI5VnA1MApEQWFwNTN6dVhZdFhFYmJ0azI0djdodyt6cW5JYm9ueHZ6WVQ2c0Z4STdPYXdFNE5zQ2pjS2VOd2RBRmJPMmYzCkFqVURrUTdQTTE4OW9tRG5ZemxKWXFMWTFkZkNMcnhTTllZUzRwSUNPOE81dlVkQXJsWEI1MmhRWjcrLzdWWlYKOTRJbHpKVi9ZbzRGS2prMjJEZ0VyTk5sSGZHakhLbFBGMUhyUE81WkY2Z0ttTzd5SkJaeWx3SWVWODVoQXdJRApBUUFCbzRJQmd6Q0NBWDh3RGdZRFZSMFBBUUgvQkFRREFnR1dNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZCd01DCkJnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Fa0dBMVVkRGdSQ0JFQTROMlkyTURFelpHVXkKTW1GbU1tSm1NMlZqTm1GbU5XRmlNemc1WVRFek56STBaREJqT1RJM1lUTmxNamd3WVRobFlqQXhOVFU1TXpNNQpZakF5TnpjMk1Fc0dBMVVkSXdSRU1FS0FRRGczWmpZd01UTmtaVEl5WVdZeVltWXpaV00yWVdZMVlXSXpPRGxoCk1UTTNNalJrTUdNNU1qZGhNMlV5T0RCaE9HVmlNREUxTlRrek16bGlNREkzTnpZd053WUlLd1lCQlFVSEFRRUUKS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWpjM0F3YkFZRApWUjBmQkdVd1l6QmhvRitnWFlaYmFIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dk9EZG1OakF4Ck0yUmxNakpoWmpKaVpqTmxZelpoWmpWaFlqTTRPV0V4TXpjeU5HUXdZemt5TjJFelpUSTRNR0U0WldJd01UVTEKT1RNek9XSXdNamMzTmpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQWdFQUxpOGRBWHg3aGR3QmZtRDJSWjhxL2J2SQphN0dac0M2clQ2K05KaGxVVnI5cTZXWXBwYnV3VnJuTC81ZG01dTJ0bzBuVGIyQlQ1bXp1M2hFRkRGYlBFL1BWCmkxdGk2ZTdvdXVoNTFNc0c0ZEhCa2tRUjBUMDFjcnRURHBmU1VwTEREQXVDbU83OE0vMDFTcnV0UTk4ZE1WOHcKVkJqWTAzTTVoMEo3UWd5WjBTYmtXMFBYOTk5NEhUYnVMZXovaG9EVjZ1YmsxTU5Qa01UT2Y5T0V5dWViZzROWQpIM1FTdGxYV0FkMTFIM2U5a0UyVy9Jb2d1L3F5amRIK0RsLzM2WlhUMzdsRllnUUhOMHRTZ0FvQnAzRlQ2TDd2CnZNc1hkeGt1NGRLSHFOOG9RaHY5S09vM005d0cvV1NLUkVRZGdVc3dYOVRkRXBSS2FYMC9vb3RJYVFQTlE5TWIKeU9DMEhlN3g4ZUtVMHNFenBpZjV0cGJZNGxuNVplZXRPbyttampvb3N1Y0Q5SnhkK3BpRGlBay9NeTdJcjFZQQpDZ21ZcUxSZXJBdGFtVWw4TzNmSWg3Y1J0TDlqcVRhckM1TGp1bnV6cExZd2lHSWFUZkxCZGZrTFNkRDhHeXE3CmZvQ2IvbjBadEZaOENHTHJDZGd3N1Z6MmVQbUwvL3dva2s5SHUxbkVPQVJqTGM5SFV5OXlHTlU1UHkvRXJHKzEKUDNSNk9ieHNpMFVXS1oyT1BlRnpjeS94VGEwSlBjZzNUdXFrcmFacUlTOWovREEraEpkaVk2c0YxcW9KQk0rLwpoNy9IV3VBL2t5K3dnL2dlVWZCWHlxSmw3S1J3WklBVTRkYzl1TG00aE1LVDZxTFNBM1R4dzl1N3lVZHZlcFRMCk50OGtheVJCY0M0YmMxNkpucGs9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K', 'RSA', 4096, 'HIGH', 'Root-CA-V1', '', '', '', '', '', '2025-01-07 15:51:59.000', '2025-11-03 15:51:54.000', '0001-01-01 01:00:00.000', 'Unspecified', 'MANAGED', 'aws-sm-ikerlan-zpd', '87f6013de22af2bf3ec6af5ab389a13724d0c927a3e280a8eb01559339b02776');
	`)

	con.Exec(`INSERT INTO ca_certificates
		(serial_number, metadata, id, creation_ts, "level", validity_type, validity_time, validity_duration)
		VALUES('99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '{}', '8b600c60-9eb3-4251-b6ce-c92d1beccc63', '2025-01-07 15:51:59.774', 0, 'Duration', '2025-11-03 15:51:41.000', '14w2d');
	`)

	con.Exec(`INSERT INTO certificates
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id)
		VALUES('de-25-2c-7d-5a-c4-b2-3d-dd-fd-b6-c6-e0-43-16-4f', '{}', '99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '8b600c60-9eb3-4251-b6ce-c92d1beccc63', 0, 'ACTIVE', 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdQVENDQkNXZ0F3SUJBZ0lSQU40bExIMWF4TEk5M2YyMnh1QkRGazh3RFFZSktvWklodmNOQVFFTEJRQXcKRlRFVE1CRUdBMVVFQXhNS1VtOXZkQzFEUVMxV01UQWVGdzB5TlRBeE1EY3hORFV5TWpWYUZ3MHlOVEEzTWpZeApORFV5TWpOYU1CZ3hGakFVQmdOVkJBTVREVWx1ZEdWeUxVTkJMVXhXVERJd2dnSWlNQTBHQ1NxR1NJYjNEUUVCCkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDNVFFM0hUVkNYYlhqZ21CR3JiMGROSXpOc21WdDZWQm5vVHZRYVVvY2kKcmhWRjhMVjRLV3RWREp5SG9yWDltSFRmeHlOTFZGcXFpdU4xbXBrUHhvNzF0bGVjL0xVK2txNWdYaVZOc2hjVAptTEMrNFowQ3ZOTUx1bkx1Y3lHRTZpdG13eGVuL0dzcXoxK1k1c1FIK2k3SklDbkJZY2tFMFhYbFBYRjJ1Sm93CnpTZnkyQnIvVWhNMGFVdXl4UkFSc1lmMlV0TFQrdlFCbE82UTI4TWw5aGgyVXZjTUVyZ0xWYmZSTmxQY2NyNjMKUkhQTzFzYWQ5V3liYWZLUndsTkNLOU9QZzNudmtQOWxQNDZxY0JLUk44T3g3MVBVY2NoVnMvMVZHM0s0YnBpUgpCSk1sdkZWajNUNFNXUnIxZndyM3VUamxGT0pJVzZFQUQ3NE5SNVlmb2VDeVdjZi9TWWhrSGFCN051ZW11U3pPCjJTeUtZSitHTjFJRlF2QmE2RkhqYWZncUs4Q2c4Yi93ZzNtQmVVeVY4WkZ0RGgyT0VBWHZ6M3VNa0JvTnpVblAKN21PaWZlRUJEVXNOdGtTTjZCWHhMSkpqVGVOcUsyWDRSTXcwSEVMUDRWSGdvV3dEWE10Ni9ha01PcFU4N2srUgo5MEJYQzFXTXBSZXl1NEdJR2lSa3BUbHlDeW1Sd0EwaFBtMllOV0VJZzlUaTB6a00yYmlqV2J4OXRWRzkvUHpwClUwNkFMWnZQem5xb2FoVTVaZEpnMmFENVRtcis1dzZpa2p4YmI4N2pDSm8yWDNKc0NnbjVzYkhXVTdwSVo3SU4KeWdDaFVBM09nZXNsbjFTeWkzNFUwU1FEaTBTNTlTQTRSSUxNQUkwZDZ0Rkg4cE9HdzZUekd1OEJGRXhpSjJTKworUUlEQVFBQm80SUJnekNDQVg4d0RnWURWUjBQQVFIL0JBUURBZ0dXTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGCkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NRWtHQTFVZERnUkNCRUJpTUdVNE9XWmsKTkRCbU5XRmxNRGs1TjJGbU9XWmxaall5TjJJeFpERTBOemxsTWpjMVpXTXlOMkkwTXpBNU9UUTNNamhpTmpWagpOMk5tWkRSaFkyRTFNRXNHQTFVZEl3UkVNRUtBUURnM1pqWXdNVE5rWlRJeVlXWXlZbVl6WldNMllXWTFZV0l6Ck9EbGhNVE0zTWpSa01HTTVNamRoTTJVeU9EQmhPR1ZpTURFMU5Ua3pNemxpTURJM056WXdOd1lJS3dZQkJRVUgKQVFFRUt6QXBNQ2NHQ0NzR0FRVUZCekFCaGh0b2RIUndjem92TDJ4aFlpNXNZVzFoYzNOMUxtbHZMMjlqYzNBdwpiQVlEVlIwZkJHVXdZekJob0YrZ1hZWmJhSFIwY0hNNkx5OXNZV0l1YkdGdFlYTnpkUzVwYnk5amNtd3ZZakJsCk9EbG1aRFF3WmpWaFpUQTVPVGRoWmpsbVpXWTJNamRpTVdReE5EYzVaVEkzTldWak1qZGlORE13T1RrME56STQKWWpZMVl6ZGpabVEwWVdOaE5UQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUFuRE9DVVFPMUlEWnExdnpVNkxSOQoyNE1VaCtWaVF6S3V2TVVGN1p4V1dLZVdRTmZsc2lmZDh5WHl4R0xQekE1Z0VJYzVPMWFCcnpleXBMUytSeU5sClBEc0xHamI5RXVRRitVNnYrWUhzMGNkWmpzcDREMlR3ZVBCRXMzOTJQVE5Gamp1ZW5uTzZGeHV4bWQ2cHJWNFkKWkhWcHFJZ3RWS0xKRXRiZjR0TXA1VU5PMUVEeFRELzdPSDhQa25OUTAwQmxCU2c3ckMyVk1ld3VaYnV1RHpxUgpNWUFVc215bHZEQ29vbDlVYUkxaXMzN0wxakpFNmptSmtSdmp3WVRNZng3OWNyNGVTSUU1aEFnRkRqZ2dReWN3ClY3ak1LdU91ZXRuWFRKaEt4a3NMRlBVWmhHTE9HUXhkYU9wQUdrYmZrOUR2SitSR0FyM2VGRFVHczIyU2dNTysKMHRuRWU2S293T2RpNUZWL295QnFkZWk2RUpzWko2TDRwbkRweDNHclBaeVpvNW5JV2s1eGN0V1JzSnIzOXJQLwpmblVSSDJ0SFE4WGlacmhUNTlGelZzUWUwTU1ER0RPWkRLSG04ei91YnVPaXlqdGdnMzZVdm5MbW1TZStaQlhYCjJFNHBkc0Z5TThycGdJQWRIb2pqeHU0Si9Fc3JWUUQrRGYybWVGa2hReGR1VjczNFY3SElBaDJnN1BCcm93ZEoKR3NYZWhlTFNFTlFKZjlzVno0NlFkK0JhcUNyaXFzNFlrbDFPSGJWbUFNTFRZOGNSRGZYOWM0ZGtPbzRtdnlMUApNWjlNT2MzZTlYUUJNVHErdWx1OGovR0Q1Y2hGRUdvZXU2a1NkVEZDRXhFQm45WCsvV2NtQmRWU2wvdzVCaldvCnZGR3BSazNuSzU0bU1vWlpwZ29hbGJjPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==', 'RSA', 4096, 'HIGH', 'Inter-CA-LVL2', '', '', '', '', '', '2025-01-07 15:52:25.000', '2025-07-26 16:52:23.000', '0001-01-01 01:00:00.000', 'Unspecified', 'MANAGED', 'aws-sm-ikerlan-zpd', 'b0e89fd40f5ae0997af9fef627b1d1479e275ec27b430994728b65c7cfd4aca5');
	`)

	con.Exec(`INSERT INTO ca_certificates
	(serial_number, metadata, id, creation_ts, "level", validity_type, validity_time, validity_duration)
	VALUES('de-25-2c-7d-5a-c4-b2-3d-dd-fd-b6-c6-e0-43-16-4f', '{}', '49b330d5-bbf7-46b4-87d2-27705f61a498', '2025-01-07 15:52:25.088', 1, 'Duration', '2025-11-03 15:52:05.000', '14w2d');
	`)

	//Add Non-CA certificate
	con.Exec(`INSERT INTO certificates
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id)
		VALUES('62-1f-5c-33-3e-ca-c1-c7-56-9e-49-78-45-e2-bd-f2', '{}', 'ef-6d-47-f4-e5-bd-c8-e3-81-67-74-60-12-c1-0f-47', '9beebc5b-ba8d-4fc0-9e97-58299d30ae9f', 0, 'ACTIVE', 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUV4RENDQXF5Z0F3SUJBZ0lRWWg5Y016N0t3Y2RXbmtsNFJlSzk4akFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGRlExTXRUV0Z1ZFdaaFkzUjFjbWx1WnpBZUZ3MHlOREV5TVRJd056SXpOVGRhRncweQpOVEF6TWpJd056SXpOVGRhTUNFeEh6QWRCZ05WQkFNVEZuVnBMV2RsYm1WeVlYUmxaQzFpYjI5MGMzUnlZWEF3CmdnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURCNkdQNk40YmExTUFTTUw5djVreFAKRmdnR3ZxaUVwQmVQUE5GYlhlNVNFLzVzK1NQV0RybmU5L2x3Mjh3SjdPdkhwaHpjVHBkZXFYeFFDMEt3REgyZQo4SmZrWlBsSG9SNzI4Ty9abER1aWNIa2xhL0huTzBVQlRTS2dYcStPRVZCNkJwTFJlYmhZcG1hTk9za1pmQXJmCkJSeXJRRUV4ay9TaUF0anpDdE5wN1FjNzNQbUtGekxtdk5XRElGM2xYWVlnZUxnb3A2MUs3ZEU3RGQ3SEdYWGMKdWxZdE9FaGpMVG1aZmtVME1hcUcwSWF3YUVtb3BFajg0ZE5PSmJKRnJseTMxcmNGa1RoN1ExeHI0Y25Xa3lxWQpGUEdhY1FSUXVQbDRkVXJYMTlXS3hIaU84Y2FXODJnQXRsNjBmZUJ5R24xWHFiK0hwdTdjRkpjdDhaSWJVcVc5CkFnTUJBQUdqZ2Z3d2dma3dEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CMEdBMVVkSlFRV01CUUdDQ3NHQVFVRkJ3TUMKQmdnckJnRUZCUWNEQVRBdkJnTlZIU01FS0RBbWdDUTVZbVZsWW1NMVlpMWlZVGhrTFRSbVl6QXRPV1U1TnkwMQpPREk1T1dRek1HRmxPV1l3UGdZSUt3WUJCUVVIQVFFRU1qQXdNQzRHQ0NzR0FRVUZCekFCaGlKb2RIUndjem92CkwyeGhZaTVzWVcxaGMzTjFMbWx2TDJGd2FTOTJZUzl2WTNOd01GY0dBMVVkSHdSUU1FNHdUS0JLb0VpR1JtaDAKZEhCek9pOHZiR0ZpTG14aGJXRnpjM1V1YVc4dllYQnBMM1poTDJOeWJDODVZbVZsWW1NMVlpMWlZVGhrTFRSbQpZekF0T1dVNU55MDFPREk1T1dRek1HRmxPV1l3RFFZSktvWklodmNOQVFFTEJRQURnZ0lCQUd5a0RYZHc3WVVLCklmcHNkd1crMkpDcXgvQUt6d0phdnh3bXIzendmNmkrR1grbnRjTExpUjRSeFBVRFM4cytUbUk4Qm1qaHJNRXEKZXFmSFg3OWlxdFZ0dkxHcnFSTjd3NGlXcnBtYnRiYlNoUzJPcFY1cyt2Y2x2RnFsSGpqWmNGcE03NXB0TERGUwpZdk56VThWTTA4aXkwNzlYLzNpSW5NL3piTUNNWGhHRE9JMDdpRzhvTVZWc0hieUhRTGZZank2UnV0dW5tTXpECi9yZm9JcGtsT0pwZmdWNnIvM20zdEp0WVZ6RUVWbkcyT1Znc00wTUMzYU50MkxwRjVxRndkQ1hyWm5LcGVYM20KdkEydnd6dnRrTWluR01GOGVUaVR3MWRqVU1KSTQzSHlFdmdJeVIvRnFobXpVZy9iMTZRWUZRdmd3Q01MaDc0UQpMK2MvQ0dCT2YwajR4TDhLRERzK2ZCeVJPTmh2WGw5b243NE1vc0E1VWZvSFdaRm0wTXZycTFFMW1oU3J0MHR2ClJadU5udXcxOS9yR0N0YXJ1RGN5dDBlRzNIalFUczZ6Nkd4T0RKQjRrVzV3d3pDV1JIaVlGTkpIdVBRSmdZOHkKbFhYSFRHbzhhR0lZcmtnRXFNSmUzUlduTlkwWk1wNWlEUzdQWk4yVWhEOUpKMVJIZFl2SmxlSHdLcVhhZ2tCWAozVmpYaE9qZ2FYZUlDQWFYK1FXeEgvK2FDdjNVMzRBZWgrYWM4ekVFSlpieDRWbDE3UE05ZER4aTNFeVB6RHloCmswWC9tRHlFQ0tPVmFrNUNGbG0zK2h0dER6b0k1ejBtNXZHUHZGQmxSSUYxZzZhUkN3NVMrTWpEVzd4YzZkZjEKQjdXRzc3cjJpTzNXa2gwZlhYRXFkREVZQXZ3SWt5dXAKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=', 'RSA', 2048, 'MEDIUM', 'ui-generated-bootstrap', '', '', '', '', '', '2024-12-12 08:23:57.000', '2025-03-22 08:23:57.000', '0001-01-01 01:00:00.000', 'Unspecified', 'EXTERNAL', '', NULL);
	`)

	ApplyMigration(t, logger, con, CADBName)

	certRepo, err := postgres.NewCertificateRepository(logger, con)
	if err != nil {
		t.Fatalf("could not create ca repository: %s", err)
	}

	ctr, err := certRepo.Count(context.Background())
	if err != nil {
		t.Fatalf("could not count certificates: %s", err)
	}

	assert.Equal(t, 3, ctr)

	var isCA bool
	//Check if Root CA is marked as CA
	tx := con.Table("certificates").Where("serial_number = '99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79'").Select("is_ca").Find(&isCA)
	if tx.Error != nil {
		t.Fatalf("failed to select row: %v", tx.Error)
	}

	assert.Equal(t, true, isCA)

	//Check if SubCA is marked as CA
	tx = con.Table("certificates").Where("serial_number = 'de-25-2c-7d-5a-c4-b2-3d-dd-fd-b6-c6-e0-43-16-4f'").Select("is_ca").Find(&isCA)
	if tx.Error != nil {
		t.Fatalf("failed to select row: %v", tx.Error)
	}

	assert.Equal(t, true, isCA)

	//Check if Non-CA certificate is not marked as CA
	tx = con.Table("certificates").Where("serial_number = '62-1f-5c-33-3e-ca-c1-c7-56-9e-49-78-45-e2-bd-f2'").Select("is_ca").Find(&isCA)
	if tx.Error != nil {
		t.Fatalf("failed to select row: %v", tx.Error)
	}

	assert.Equal(t, false, isCA)
}

func MigrationTest_CA_20250115095852_create_requests_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, CADBName)

	reqRepo, err := postgres.NewCACertRequestPostgresRepository(logger, con)
	if err != nil {
		t.Fatalf("could not create certificate repository: %s", err)
	}

	csrStr := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1hUQ0NBVVVDQVFBd0dERVdNQlFHQTFVRUF4TU5UWGxTWlhGMVpYTjBaV1JEUVRDQ0FTSXdEUVlKS29aSQpodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUx4VmcxT2RrUjVScjAyMUJWQzB1SzdMMDhjUG9MTDlCd1lxCmNjaGJxOWtIYTZQS0NmZldRZ2ZhaHNSMy9oT2U4cXdmRFhjZnFXMS9rWnRHRnVjQkMwNVpnNG9ZaXVockwvb2EKa05DWGIvNlZRdjk3b2VqcXBFOHdwbzc3UlArN0RQYU51TXA5UGlrclRuYmVWdVhLTnBPUTcvZlpWQmpuMGxqcApSa3BMN1gwdE9QU1FRNzEyeHY3elhoVCtJL2hCODJ2ZkRWRFRmRzdOaHlycW1nSEsvWXFNUGVEcUIvNjQvb29xCm43anJabjFWbVpQRzVXcUkrVTltYmtHUGpQbjUxTGdheTE0NGFPajE2aW9Uak56Z05BRnhoRUVlcVB1bXRmSWcKS2kxTnZXMTI0dWJSOGpNandoMmF2RDYxYVhOTHlQaERiUm9VdG9OU29VQzlyS3pxRTRFQ0F3RUFBYUFBTUEwRwpDU3FHU0liM0RRRUJDd1VBQTRJQkFRQmJZUlZVZk44TG9nNisySlNPTTBSNTVINHZ3OGxPOWRNeFZOc01ibG5VCnBTR0FoM3k0WHFDTm0zTllORUJ4TFQ4eDdON0xlSWJZZTJiUGZXbWduc0crb0dKelBaeU5hUmNMd1d1N3R0VlMKbml2Y2t4Ums4MGV0ZGkxcUlyM2JBVmRjcHZkWWJ5N2FySjl1Z2ZUNlQ4N3p5Rk1Ka2RvZWV4b2J0dlJ6dnZEMQp3WW1aVzQwRE1HbHBlMllIZFd3dXBaejFTSENtODBmdGxUV3M5aG1jUW1GU2hOVHViRzllQjgxL3pTdXVLbTl0Cnl2ekM5MFd6LysvSjFicW1XejZwcU1xSXJkVGVNeFRST0hibG1WMWFIdWtzT2FESFljNStPVkV3YUQ0clF3ZEoKS3MxeGFWT2lIcjIvVDBadUYrdzJHNGFNQ1k3TUp0QW16QmVsbTAvVHJwUmUKLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCg=="
	crtBytes, err := base64.StdEncoding.DecodeString(csrStr)
	if err != nil {
		t.Fatalf("could not decode certificate: %s", err)
	}

	csr, err := helpers.ParseCertificateRequest(string(crtBytes))
	if err != nil {
		t.Fatalf("could not parse certificate: %s", err)
	}

	_, err = reqRepo.Insert(context.Background(), &models.CACertificateRequest{
		ID:       "1111-2222-3333-4444",
		KeyId:    "1111-2222-3333-4444",
		EngineID: "filesystem-1",
		Status:   models.StatusRequestPending,
		Subject: models.Subject{
			CommonName:       "test",
			Organization:     "test",
			OrganizationUnit: "test",
			Country:          "test",
			Locality:         "test",
			State:            "test",
		},
		KeyMetadata: models.KeyStrengthMetadata{
			Type:     models.KeyType(x509.RSA),
			Bits:     4096,
			Strength: models.KeyStrengthHigh,
		},
		CSR:        models.X509CertificateRequest(*csr),
		Metadata:   map[string]interface{}{},
		CreationTS: time.Date(2024, time.November, 25, 9, 45, 48, 0, time.UTC),
	})

	if err != nil {
		t.Fatalf("could not insert certificate request: %s", err)
	}

	exists, _, err := reqRepo.SelectExistsByID(context.Background(), "1111-2222-3333-4444")
	if err != nil {
		t.Fatalf("could not check if certificate request exists: %s", err)
	}

	if !exists {
		t.Fatalf("certificate request does not exist")
	}
}

func MigrationTest_CA_20250123125500_ca_aws_metadata(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	currentMeta := `{"lamassu.io/iot/aws.123456789012":{"account":"123456789012","arn":"arn:aws:iot:eu-west-1:123456789012:cacert/d0f877e36a96c93c00d1c6ba7470acc04d6d31e88bfe646735844a7918177c9e","certificate_id":"d0f877e36a96c93c00d1c6ba7470acc04d6d31e88bfe646735844a7918177c9e","mqtt_endpoint":"axxxxxxxxxx-ats.iot.eu-west-1.amazonaws.com","region":"eu-west-1","register":true}}`
	expectedMeta := `{"lamassu.io/iot/aws.123456789012":{"account":"123456789012","arn":"arn:aws:iot:eu-west-1:123456789012:cacert/d0f877e36a96c93c00d1c6ba7470acc04d6d31e88bfe646735844a7918177c9e","certificate_id":"d0f877e36a96c93c00d1c6ba7470acc04d6d31e88bfe646735844a7918177c9e","mqtt_endpoint":"axxxxxxxxxx-ats.iot.eu-west-1.amazonaws.com","region":"eu-west-1","registration":{"error":"","primary_account":true,"registration_request_time":"1970-01-01T00:00:00Z","registration_time":"1970-01-01T00:00:00Z","status":"SUCCEEDED"}}}`

	con.Exec(`INSERT INTO certificates
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id, is_ca)
		VALUES('99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '{}', '99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '8b600c60-9eb3-4251-b6ce-c92d1beccc63', 0, 'ACTIVE', 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdPakNDQkNLZ0F3SUJBZ0lSQUpuZ0ptQkxrSTArVUplWXNCYmIxbmt3RFFZSktvWklodmNOQVFFTEJRQXcKRlRFVE1CRUdBMVVFQXhNS1VtOXZkQzFEUVMxV01UQWVGdzB5TlRBeE1EY3hORFV4TlRsYUZ3MHlOVEV4TURNeApORFV4TlRSYU1CVXhFekFSQmdOVkJBTVRDbEp2YjNRdFEwRXRWakV3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBCkE0SUNEd0F3Z2dJS0FvSUNBUUMzTTZYdDJNSWlVR21LNXpUUlVvZlZzazdtQ1ZZMWlkbXdLSythd0M0anZzWWoKM0JiZW5zZXVJaUo3NEg5TnZZdnhYZ0xDNVE3NXJ5UmJzNHN5TzBpV2YxUlJtamFVVUdxbHlkMmFLNVlIM3JWYgpXZ0htTkJMU2Q0dVlTRit3dno0Vk9Ic24zT1kvbFBTUkRwSm11ajJ3ekhYZ1p5RVR6M1Bzd1hhT0xXY3RsZFUvCm11eUJPWHE0bTFwNHh6dy83N0R2bW53Ni9mRXYwdG9iRVBYdVdvdlhSaS84NHQ2c0g5K1VDWmI5U3JTdFJWTHEKTGhsUEVQUC9SOXVveHBsVElTNllyQ2VHdWlPM2ViOGtmRVVETVdKS2pFbktueUx2b1RmbFVOMGE0K1docEFSSQp3WXgwSm9zQzhrb0xLV29ScFdJSlVlOC9hZStNWXRmWW1JNUdacGRIdnk1ZngzbXB5R2hseUJhWVRSOER2dkdvCmN1S0pabm16MVFuamYzM0syZFAxbk1RVHJhalJlWS9aMnd6bmRQbjg0SWdoWnJRc2NpSXYxcXg3Z3Y4Y3BuK0QKWTJuRUJUTHBPRHNIQXhKcmEyTGZZaXFYNnQzaUNCNEkrLzQ2djFBSitBWmJYMnRSVUpsakpSeHBqbkI5VnA1MApEQWFwNTN6dVhZdFhFYmJ0azI0djdodyt6cW5JYm9ueHZ6WVQ2c0Z4STdPYXdFNE5zQ2pjS2VOd2RBRmJPMmYzCkFqVURrUTdQTTE4OW9tRG5ZemxKWXFMWTFkZkNMcnhTTllZUzRwSUNPOE81dlVkQXJsWEI1MmhRWjcrLzdWWlYKOTRJbHpKVi9ZbzRGS2prMjJEZ0VyTk5sSGZHakhLbFBGMUhyUE81WkY2Z0ttTzd5SkJaeWx3SWVWODVoQXdJRApBUUFCbzRJQmd6Q0NBWDh3RGdZRFZSMFBBUUgvQkFRREFnR1dNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZCd01DCkJnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Fa0dBMVVkRGdSQ0JFQTROMlkyTURFelpHVXkKTW1GbU1tSm1NMlZqTm1GbU5XRmlNemc1WVRFek56STBaREJqT1RJM1lUTmxNamd3WVRobFlqQXhOVFU1TXpNNQpZakF5TnpjMk1Fc0dBMVVkSXdSRU1FS0FRRGczWmpZd01UTmtaVEl5WVdZeVltWXpaV00yWVdZMVlXSXpPRGxoCk1UTTNNalJrTUdNNU1qZGhNMlV5T0RCaE9HVmlNREUxTlRrek16bGlNREkzTnpZd053WUlLd1lCQlFVSEFRRUUKS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd2N6b3ZMMnhoWWk1c1lXMWhjM04xTG1sdkwyOWpjM0F3YkFZRApWUjBmQkdVd1l6QmhvRitnWFlaYmFIUjBjSE02THk5c1lXSXViR0Z0WVhOemRTNXBieTlqY213dk9EZG1OakF4Ck0yUmxNakpoWmpKaVpqTmxZelpoWmpWaFlqTTRPV0V4TXpjeU5HUXdZemt5TjJFelpUSTRNR0U0WldJd01UVTEKT1RNek9XSXdNamMzTmpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQWdFQUxpOGRBWHg3aGR3QmZtRDJSWjhxL2J2SQphN0dac0M2clQ2K05KaGxVVnI5cTZXWXBwYnV3VnJuTC81ZG01dTJ0bzBuVGIyQlQ1bXp1M2hFRkRGYlBFL1BWCmkxdGk2ZTdvdXVoNTFNc0c0ZEhCa2tRUjBUMDFjcnRURHBmU1VwTEREQXVDbU83OE0vMDFTcnV0UTk4ZE1WOHcKVkJqWTAzTTVoMEo3UWd5WjBTYmtXMFBYOTk5NEhUYnVMZXovaG9EVjZ1YmsxTU5Qa01UT2Y5T0V5dWViZzROWQpIM1FTdGxYV0FkMTFIM2U5a0UyVy9Jb2d1L3F5amRIK0RsLzM2WlhUMzdsRllnUUhOMHRTZ0FvQnAzRlQ2TDd2CnZNc1hkeGt1NGRLSHFOOG9RaHY5S09vM005d0cvV1NLUkVRZGdVc3dYOVRkRXBSS2FYMC9vb3RJYVFQTlE5TWIKeU9DMEhlN3g4ZUtVMHNFenBpZjV0cGJZNGxuNVplZXRPbyttampvb3N1Y0Q5SnhkK3BpRGlBay9NeTdJcjFZQQpDZ21ZcUxSZXJBdGFtVWw4TzNmSWg3Y1J0TDlqcVRhckM1TGp1bnV6cExZd2lHSWFUZkxCZGZrTFNkRDhHeXE3CmZvQ2IvbjBadEZaOENHTHJDZGd3N1Z6MmVQbUwvL3dva2s5SHUxbkVPQVJqTGM5SFV5OXlHTlU1UHkvRXJHKzEKUDNSNk9ieHNpMFVXS1oyT1BlRnpjeS94VGEwSlBjZzNUdXFrcmFacUlTOWovREEraEpkaVk2c0YxcW9KQk0rLwpoNy9IV3VBL2t5K3dnL2dlVWZCWHlxSmw3S1J3WklBVTRkYzl1TG00aE1LVDZxTFNBM1R4dzl1N3lVZHZlcFRMCk50OGtheVJCY0M0YmMxNkpucGs9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K', 'RSA', 4096, 'HIGH', 'Root-CA-V1', '', '', '', '', '', '2025-01-07 15:51:59.000', '2025-11-03 15:51:54.000', '0001-01-01 01:00:00.000', 'Unspecified', 'MANAGED', 'aws-sm-engine', '87f6013de22af2bf3ec6af5ab389a13724d0c927a3e280a8eb01559339b02776', true);
	`)

	con.Exec(fmt.Sprintf(`INSERT INTO ca_certificates
		(serial_number, metadata, id, creation_ts, "level", validity_type, validity_time, validity_duration)
		VALUES('99-e0-26-60-4b-90-8d-3e-50-97-98-b0-16-db-d6-79', '%s', '8b600c60-9eb3-4251-b6ce-c92d1beccc63', '2025-01-07 15:51:59.774', 0, 'Duration', '2025-11-03 15:51:41.000', '14w2d');
	`, currentMeta))

	ApplyMigration(t, logger, con, CADBName)

	var result string

	// Select iot1, should have the new keygen settings enabled and reenrollment_settings.revoke_on_reenrollment set to false
	tx := con.Table("ca_certificates").Where("id = '8b600c60-9eb3-4251-b6ce-c92d1beccc63'").Select("metadata").Find(&result)
	if tx.Error != nil {
		t.Fatalf("failed to select row: %v", tx.Error)
	}

	assert.Equal(t, expectedMeta, result)
}

func MigrationTest_CA_20250226114600_ca_add_kids(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	con.Exec(`INSERT INTO public.certificates 
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, type, engine_id, key_id, is_ca) 
		VALUES ('37-65-cd-86-f0-bf-c5-c8-1b-7f-10-f8-15-4e-4e-35-81-4c-d8-79', '{}', '37-65-cd-86-f0-bf-c5-c8-1b-7f-10-f8-15-4e-4e-35-81-4c-d8-79', 'b0db9cc7-2cce-45be-8085-88f7aff40ca2', 0, 'ACTIVE', 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURsRENDQW55Z0F3SUJBZ0lVTjJYTmh2Qy94Y2diZnhENEZVNU9OWUZNMkhrd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1hURUxNQWtHQTFVRUJoTUNWVk14RlRBVEJnTlZCQWdNREVWNFlXMXdiR1ZUZEdGMFpURVVNQklHQTFVRQpCd3dMUlhoaGJYQnNaVU5wZEhreER6QU5CZ05WQkFvTUJsSnZiM1JEUVRFUU1BNEdBMVVFQXd3SFVtOXZkQ0JEClFUQWVGdzB5TlRBeU1qVXhNelUwTVRoYUZ3MHpOVEF5TWpNeE16VTBNVGhhTUVZeEN6QUpCZ05WQkFZVEFsVlQKTVJVd0V3WURWUVFJREF4RmVHRnRjR3hsVTNSaGRHVXhEekFOQmdOVkJBb01CbEp2YjNSRFFURVBNQTBHQTFVRQpBd3dHVTNWaUlFTkJNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTJIay91Ri9VClJNdHAzengyYmltUllvSEFxMXJ6OUgyL1F3S2d0RTRkTkk1R01ISUh4ZWVJZk9sYnh4T2hyMVBhTUtTb3hJdjEKM1NqMWFycEloUUVGc2V0NDJ0WU9FS2dUTzB4NUtRSFFSbnNYOUY1dXVjNURyajZFNFUxcUF2MGtxQlMvN2NobQpqc3pwc1oyK1ExOWordjNHM0NNa2twT09ZWmFUQW8wWlBFdFJCYU5HM3hYMlg0akdidmlNMWFDeDZ2MmNDM0s4CnJmYXVoNzR4T3lLaldNME1PVm5kS2N0VUFzNW9VckZjTkM2c3BwOGtqQk1XcFhjQ3RjWStZTm5ISDVhRDcvTEIKakdaSmxaTkROS0NDdFIwR050d2xxUHZiQ3pUYnV2UHZqVkY2aFdQaEIwZFdYUDVqRTFuc05BUkxnWW51RTJXTQpoQWx5cU92bWdlaGZVUUlEQVFBQm8yTXdZVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTRHQTFVZER3RUIvd1FFCkF3SUJCakFkQmdOVkhRNEVGZ1FVSHV1UElDL2tVWVA2MHlzSGlMMTl2NTFyMUtFd0h3WURWUjBqQkJnd0ZvQVUKNUZpMVFQOFc5KzRSaS8wdFZFNENhaVg1cHY0d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFJdTFsQVp0ZVUrbgorNmwvd3VFb2V2K0FkOEQzVHZIREVqeHlIbll0RTRNZitITGsyU2d1WXZYSkpSRkZjOXVzRzNGbW1CMGhUUG14CktEck1rOVFPYmdIc1pIY05hZ3doQjZVcm4rRUtyai9ZVW5JSkUyVHJYL2JsRllvTUJQYXhiV3J3cm1GQWpLc2wKOHV1Sm9OWTY0RzZzT016SEJwZUVMaGRaVS94Z0Rzck5rK2RHeVZ0WUFqbWZrc1FMT1NnRjE0WFpuWEw5K3dQYwpqU200bjhXNVlRMHpzS0FaNVRtQjBWcFRDa3ZWUy9nR0RIb1pmZE8zOENTcnk0ejhuTTNXNHpka212bzc2RzhVCjJmdkMxMUZTWHh6UlZRcmJ4ZmFPTUVjZHpUMHUxd2NzUVF6TTQrdjBOanQzdlZ5K2dSbGptK0dtdDBEYzkvTGIKTzN2MkFmbWhQaVU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K', 'RSA', 2048, 'MEDIUM', 'Sub CA', 'RootCA', '', 'US', 'ExampleState', '', '2025-02-25 13:54:18+00', '2035-02-23 13:54:18+00', '0001-01-01 00:00:00+00', 'Unspecified', 'EXTERNAL', '', '1E:EB:8F:20:2F:E4:51:83:FA:D3:2B:07:88:BD:7D:BF:9D:6B:D4:A1', true);
	`)

	ApplyMigration(t, logger, con, CADBName)

	var result map[string]interface{}
	tx := con.Raw("SELECT * FROM certificates").Scan(&result)
	if tx.RowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", tx.RowsAffected)
	}

	assert.Equal(t, "1E:EB:8F:20:2F:E4:51:83:FA:D3:2B:07:88:BD:7D:BF:9D:6B:D4:A1", result["subject_key_id"])
	assert.Equal(t, "E4:58:B5:40:FF:16:F7:EE:11:8B:FD:2D:54:4E:02:6A:25:F9:A6:FE", result["authority_key_id"])
	assert.Equal(t, "Root CA", result["issuer_common_name"])
	assert.Equal(t, "RootCA", result["issuer_organization"])
	assert.Equal(t, "", result["issuer_organization_unit"])
	assert.Equal(t, "US", result["issuer_country"])
	assert.Equal(t, "ExampleState", result["issuer_state"])
	assert.Equal(t, "ExampleCity", result["issuer_locality"])
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

	CleanAllTables(t, logger, con)

	MigrationTest_CA_20250107164937_add_is_ca(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20250107164937_add_is_ca")
	}

	MigrationTest_CA_20250115095852_create_requests_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20250115095852_create_requests_table")
	}

	CleanAllTables(t, logger, con)

	MigrationTest_CA_20250123125500_ca_aws_metadata(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20250123125500_ca_aws_metadata")
	}

	CleanAllTables(t, logger, con)

	MigrationTest_CA_20250226114600_ca_add_kids(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20250226114600_ca_add_kids")
	}
}
