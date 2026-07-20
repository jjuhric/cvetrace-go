package cli

import (
	"reflect"
	"testing"

	"github.com/jjuhric/cvetrace-go/internal/trace"
)

// TestReorderFlagsFirst is a regression test for a real bug caught while
// building this: "cvetrace scan <path> --json" was silently ignoring --json,
// because Go's flag package stops looking for flags at the first positional
// argument, and <path> came first. See the comment on reorderFlagsFirst.
func TestReorderFlagsFirst(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag after the positional argument",
			in:   []string{"test/my-project", "--json"},
			want: []string{"--json", "test/my-project"},
		},
		{
			name: "flag already first, unchanged",
			in:   []string{"--json", "test/my-project"},
			want: []string{"--json", "test/my-project"},
		},
		{
			name: "no flags at all",
			in:   []string{"test/my-project"},
			want: []string{"test/my-project"},
		},
		{
			name: "a value-taking flag's two tokens move together",
			in:   []string{"test/my-project", "--fail-on", "critical"},
			want: []string{"--fail-on", "critical", "test/my-project"},
		},
		{
			name: "a value-taking flag using = syntax needs no pairing",
			in:   []string{"test/my-project", "--fail-on=critical"},
			want: []string{"--fail-on=critical", "test/my-project"},
		},
		{
			name: "repeated value-taking flags each keep their own value",
			in:   []string{"test/my-project", "--exclude", "test/**", "--exclude", "legacy/**"},
			want: []string{"--exclude", "test/**", "--exclude", "legacy/**", "test/my-project"},
		},
		{
			name: "a mix of a switch and a value-taking flag",
			in:   []string{"test/my-project", "--json", "--ignore", "CVE-2021-1"},
			want: []string{"--json", "--ignore", "CVE-2021-1", "test/my-project"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reorderFlagsFirst(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMeetsThreshold(t *testing.T) {
	vulns := []trace.Vulnerability{
		{Severity: "MODERATE"},
		{Severity: "HIGH"},
	}

	cases := []struct {
		name    string
		failOn  string
		want    bool
		wantErr bool
	}{
		{"threshold met exactly", "high", true, false},
		{"threshold met by exceeding it", "moderate", true, false},
		{"threshold not met", "critical", false, false},
		{"case-insensitive", "HIGH", true, false},
		{"medium is an alias for moderate", "medium", true, false},
		{"unknown severity name errors", "not-a-severity", false, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := meetsThreshold(vulns, c.failOn)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error for an unrecognized --fail-on value, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("meetsThreshold returned an unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
