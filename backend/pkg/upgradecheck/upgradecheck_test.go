package upgradecheck

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func fixedCheck(name string, covers []string, problems []string, err error) Check {
	return Check{
		Name:   name,
		Covers: covers,
		Run: func(context.Context, *Env) ([]string, error) {
			return problems, err
		},
	}
}

func TestRunChecksRunsEveryCheck(t *testing.T) {
	boom := errors.New("boom")
	results := RunChecks(context.Background(), &Env{}, []Check{
		fixedCheck("first", nil, []string{"p1"}, nil),
		fixedCheck("second", nil, nil, boom),
		fixedCheck("third", nil, []string{"p3"}, nil),
	})

	require.Len(t, results, 3)
	require.Equal(t, "first", results[0].Check.Name)
	require.Equal(t, []string{"p1"}, results[0].Problems)
	require.ErrorIs(t, results[1].Err, boom)
	require.Equal(t, "third", results[2].Check.Name)
	require.Equal(t, []string{"p3"}, results[2].Problems)
}

func TestExitCode(t *testing.T) {
	ok := Result{Check: Check{Name: "ok"}}
	problem := Result{Check: Check{Name: "problem"}, Problems: []string{"p"}}
	failed := Result{Check: Check{Name: "failed"}, Err: errors.New("boom")}

	for _, tc := range []struct {
		name    string
		results []Result
		want    int
	}{
		{"no results", nil, 0},
		{"no problems", []Result{ok}, 0},
		{"a problem", []Result{ok, problem}, 1},
		{"a check that could not run", []Result{ok, failed}, 2},
		{"a problem and a check that could not run", []Result{problem, failed}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ExitCode(tc.results))
		})
	}
}

func TestReportListsProblemsAndCoverage(t *testing.T) {
	results := RunChecks(context.Background(), &Env{}, []Check{
		fixedCheck("first", []string{"va/a"}, []string{"problem one", "problem two"}, nil),
		fixedCheck("second", []string{"va/b", "va/a"}, nil, errors.New("could not query")),
		fixedCheck("third", []string{"va/b"}, nil, nil),
	})

	var out bytes.Buffer
	Report(&out, results)

	text := out.String()
	require.Contains(t, text, "problem one")
	require.Contains(t, text, "problem two")
	require.Contains(t, text, "could not query")
	require.Contains(t, text, "\nCovered migrations: va/a, va/b\n")
}
