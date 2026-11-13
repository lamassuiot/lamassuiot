package upgradecheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParityWithMigrations proves that the checks and the migrations agree on every scenario: the problem a check
// reports is the error the v4 migrations abort with, and a 3.8 installation without problems upgrades.
func TestParityWithMigrations(t *testing.T) {
	for _, sc := range vaScenarios {
		t.Run(sc.name, func(t *testing.T) {
			f := newFixture(t)
			want := sc.setup(f)
			require.Equal(t, want, runVAChecks(t, f))

			err := migrateV4(t, f.cfg)
			if len(want) == 0 {
				require.NoError(t, err)
				return
			}
			require.Len(t, want, 1, "a parity scenario has a single problem: the migrations stop at the first")
			for _, problems := range want {
				require.Len(t, problems, 1)
				require.ErrorContains(t, err, problems[0])
			}
		})
	}
}
