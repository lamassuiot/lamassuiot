package migrations

// Plan returns the ordered schema versions for a new Oracle installation.
func Plan() []Migration {
	return []Migration{KMSFoundation(), CertificateFoundation(), IssuanceProfiles(), ValidationAuthority(), DMS(), Alerts(), Devices(), JSONSortKey()}
}
