// Package upgradecheck reports, before an upgrade, the conditions under which the upgrade migrations would abort.
// It only reads: it never writes database rows or keys.
package upgradecheck

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"gorm.io/gorm"
)

// Env is what the checks read from.
type Env struct {
	// Schema returns a connection with that schema as search_path.
	Schema func(schema string) (*gorm.DB, error)
	// Engines holds the crypto engines that started, by engine id. The crypto engines check fills it.
	Engines map[string]cryptoengines.CryptoEngine
}

// Check is one upgrade check.
type Check struct {
	Name string
	// Covers lists the migrations whose abort conditions the check reports, e.g. "va/20261111120000_crl_settings".
	Covers []string
	// Run returns the problems found, each naming the offending objects, or an error if the check could not run.
	Run func(ctx context.Context, env *Env) (problems []string, err error)
}

// Result is the outcome of one check.
type Result struct {
	Check    Check
	Problems []string
	Err      error
}

// RunChecks runs every check in order, even after one fails.
func RunChecks(ctx context.Context, env *Env, checks []Check) []Result {
	results := make([]Result, 0, len(checks))
	for _, check := range checks {
		problems, err := check.Run(ctx, env)
		results = append(results, Result{Check: check, Problems: problems, Err: err})
	}
	return results
}

// ExitCode is 0 when every check ran with no problem, 1 when every check ran and one found a problem, and 2 when
// a check could not run: then the absence of problems proves nothing.
func ExitCode(results []Result) int {
	code := 0
	for _, r := range results {
		if r.Err != nil {
			return 2
		}
		if len(r.Problems) > 0 {
			code = 1
		}
	}
	return code
}

// Report prints the problems and errors of every check, then the migrations the run covers.
func Report(w io.Writer, results []Result) {
	covered := []string{}
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(w, "[%s] could not run: %s\n", r.Check.Name, r.Err)
		case len(r.Problems) == 0:
			fmt.Fprintf(w, "[%s] ok\n", r.Check.Name)
		}
		for _, p := range r.Problems {
			fmt.Fprintf(w, "[%s] %s\n", r.Check.Name, p)
		}
		for _, m := range r.Check.Covers {
			if !slices.Contains(covered, m) {
				covered = append(covered, m)
			}
		}
	}
	fmt.Fprintf(w, "\nCovered migrations: %s\n", strings.Join(covered, ", "))
}
