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

// TestDedupeByCVECollapsesGHSAAndPYSECRecords is a regression test for a
// real bug found while porting Python support to this Go version: OSV.dev
// indexes some PyPI CVEs under both a GHSA-* id and a PYSEC-* id, which
// showed up as the same CVE reported twice against pyyaml@5.3 in the actual
// fixture before this fix.
func TestDedupeByCVECollapsesGHSAAndPYSECRecords(t *testing.T) {
	vulns := []Vulnerability{
		{ManifestPath: "requirements.txt", Name: "pyyaml", CurrentVersion: "5.3", ID: "GHSA-xxxx", Aliases: []string{"CVE-2020-14343"}},
		{ManifestPath: "requirements.txt", Name: "pyyaml", CurrentVersion: "5.3", ID: "PYSEC-2021-142", Aliases: []string{"CVE-2020-14343"}},
	}

	got := dedupeByCVE(vulns)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (GHSA/PYSEC duplicates should collapse)", len(got))
	}
}

func TestDedupeByCVEKeepsTheSameCVEAcrossDifferentManifestsSeparate(t *testing.T) {
	vulns := []Vulnerability{
		{ManifestPath: "a/pom.xml", Name: "pkg", CurrentVersion: "1.0.0", ID: "GHSA-xxxx", Aliases: []string{"CVE-2021-1"}},
		{ManifestPath: "b/build.gradle", Name: "pkg", CurrentVersion: "1.0.0", ID: "GHSA-xxxx", Aliases: []string{"CVE-2021-1"}},
	}

	got := dedupeByCVE(vulns)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (same CVE, different manifests, both should be kept)", len(got))
	}
}

func TestClassifyVersionJump(t *testing.T) {
	cases := []struct {
		name, current, fixed, want string
	}{
		{"patch bump", "2.14.0", "2.14.1", "patch"},
		{"minor bump", "2.14.1", "2.15.0", "minor"},
		{"major bump", "1.9.9", "2.0.0", "major"},
		{"no known fix", "1.0.0", "", "unknown"},
		{"unparseable current version", "not-a-version", "2.0.0", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyVersionJump(c.current, c.fixed)
			if got != c.want {
				t.Errorf("classifyVersionJump(%q, %q) = %q, want %q", c.current, c.fixed, got, c.want)
			}
		})
	}
}

func TestClassifyRemediationTier(t *testing.T) {
	cases := []struct {
		name, fixedVersion, updateImpact, want string
	}{
		{"no fix yet", "", "unknown", "no-fix-available"},
		{"patch is safe", "1.2.4", "patch", "safe-to-update"},
		{"minor is safe", "1.3.0", "minor", "safe-to-update"},
		{"major needs approval", "2.0.0", "major", "needs-approval"},
		{"unparseable impact", "1.2.4", "unknown", "unknown-impact"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyRemediationTier(c.fixedVersion, c.updateImpact)
			if got != c.want {
				t.Errorf("classifyRemediationTier(%q, %q) = %q, want %q", c.fixedVersion, c.updateImpact, got, c.want)
			}
		})
	}
}

// TestAddRecommendedVersionsPicksTheHighestFixAcrossCVEsForTheSamePackage
// mirrors the real log4j-core fixture, which has several CVEs each with
// their own nearest fix -- RecommendedVersion should be the single highest
// one, so upgrading once clears every known issue for that package.
func TestAddRecommendedVersionsPicksTheHighestFixAcrossCVEsForTheSamePackage(t *testing.T) {
	vulns := []Vulnerability{
		{ManifestPath: "build.gradle", Name: "log4j-core", FixedVersion: "2.15.0"},
		{ManifestPath: "build.gradle", Name: "log4j-core", FixedVersion: "2.17.1"},
		{ManifestPath: "build.gradle", Name: "log4j-core", FixedVersion: ""}, // no fix published yet for this one
	}

	got := addRecommendedVersions(vulns)
	for _, v := range got {
		if v.RecommendedVersion != "2.17.1" {
			t.Errorf("got recommendedVersion %q for a record with fixedVersion %q, want %q",
				v.RecommendedVersion, v.FixedVersion, "2.17.1")
		}
	}
}

func TestAddRecommendedVersionsScopesByManifestPath(t *testing.T) {
	vulns := []Vulnerability{
		{ManifestPath: "a/pom.xml", Name: "pkg", FixedVersion: "1.5.0"},
		{ManifestPath: "b/build.gradle", Name: "pkg", FixedVersion: "9.0.0"},
	}

	got := addRecommendedVersions(vulns)
	if got[0].RecommendedVersion != "1.5.0" {
		t.Errorf("a/pom.xml: got recommendedVersion %q, want %q (shouldn't be influenced by b/build.gradle's fix)", got[0].RecommendedVersion, "1.5.0")
	}
	if got[1].RecommendedVersion != "9.0.0" {
		t.Errorf("b/build.gradle: got recommendedVersion %q, want %q", got[1].RecommendedVersion, "9.0.0")
	}
}
