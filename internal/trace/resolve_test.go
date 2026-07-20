package trace

import "testing"

// TestMinimumFixedVersionPicksTheIntervalContainingCurrentVersion is a
// regression test for a real bug found while building the Node version of
// this tool: minimumFixedVersion used to blend "fixed" versions across every
// disjoint affected-version range in an advisory and pick the global
// minimum. For log4j-core 2.14.1 (real, live OSV.dev data -- see
// GHSA-jfh8-c2jp-5v3q) that produced "2.3.1", an old release from a branch
// 2.14.1 was never even on, which doesn't fix the CVE at all. The real fix
// for that branch is 2.15.0.
func TestMinimumFixedVersionPicksTheIntervalContainingCurrentVersion(t *testing.T) {
	log4jShellDetail := &VulnDetail{
		Affected: []affected{
			{
				Package: packageRef{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"},
				Ranges: []versionRange{
					{Events: []event{{Introduced: "2.13.0"}, {Fixed: "2.15.0"}}},
				},
			},
			{
				Package: packageRef{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"},
				Ranges: []versionRange{
					{Events: []event{{Introduced: "2.0-beta9"}, {Fixed: "2.3.1"}}},
				},
			},
			{
				Package: packageRef{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"},
				Ranges: []versionRange{
					{Events: []event{{Introduced: "2.4"}, {Fixed: "2.12.2"}}},
				},
			},
		},
	}

	got := minimumFixedVersion(log4jShellDetail, "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
	if got != "2.15.0" {
		t.Errorf("got %q, want %q", got, "2.15.0")
	}
}

func TestMinimumFixedVersionReturnsEmptyWhenNoIntervalContainsTheVersion(t *testing.T) {
	detail := &VulnDetail{
		Affected: []affected{
			{
				Package: packageRef{Ecosystem: "npm", Name: "foo"},
				Ranges: []versionRange{
					{Events: []event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
				},
			},
		},
	}

	got := minimumFixedVersion(detail, "npm", "foo", "2.0.0")
	if got != "" {
		t.Errorf("got %q, want empty string (no known fix for this version)", got)
	}
}

func TestMinimumFixedVersionReturnsEmptyForAnIntervalWithNoKnownFixYet(t *testing.T) {
	detail := &VulnDetail{
		Affected: []affected{
			{
				Package: packageRef{Ecosystem: "npm", Name: "foo"},
				Ranges: []versionRange{
					// last_affected with no paired fixed event: the version
					// is known to be vulnerable, but no patched release
					// exists yet.
					{Events: []event{{Introduced: "0"}, {LastAffected: "1.5.0"}}},
				},
			},
		},
	}

	got := minimumFixedVersion(detail, "npm", "foo", "1.0.0")
	if got != "" {
		t.Errorf("got %q, want empty string (no fix published yet)", got)
	}
}

func TestParseVersionPartsHandlesAPreReleaseTagLeniently(t *testing.T) {
	parts, ok := parseVersionParts("2.0-beta9")
	if !ok {
		t.Fatal("expected parseVersionParts to succeed")
	}
	want := [3]int{2, 0, 0}
	if parts != want {
		t.Errorf("got %v, want %v", parts, want)
	}
}

func TestParseVersionPartsRejectsNonNumericInput(t *testing.T) {
	_, ok := parseVersionParts("not-a-version")
	if ok {
		t.Error("expected parseVersionParts to report failure for non-numeric input")
	}
}
