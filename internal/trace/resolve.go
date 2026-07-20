package trace

import (
	"sort"
	"strconv"
	"strings"

	"github.com/jjuhric/cvetrace-go/internal/discover"
)

// Vulnerability is one known CVE/GHSA affecting one dependency, ready to
// report.
//
// Go note: the `json:"..."` tags control how this struct looks when
// marshaled by internal/report's JSON output -- e.g. Go's exported
// FixedVersion field becomes the JSON key "fixedVersion", matching the
// lowerCamelCase convention the rest of this project (and its Node
// counterpart) uses for JSON, even though Go itself uses UpperCamelCase for
// exported field names.
type Vulnerability struct {
	ManifestPath   string   `json:"manifestPath"`
	Ecosystem      string   `json:"ecosystem"`
	Name           string   `json:"name"`
	CurrentVersion string   `json:"currentVersion"`
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases"`
	Summary        string   `json:"summary"`
	Severity       string   `json:"severity"`
	FixedVersion   string   `json:"fixedVersion"` // "" means no known fix yet
	URL            string   `json:"url"`
}

// severityRank lets severities be compared/sorted, higher is worse. OSV.dev
// advisories sourced from GitHub Security Advisories carry this label
// (database_specific.severity) rather than always a parseable CVSS score.
var severityRank = map[string]int{
	"LOW":      1,
	"MODERATE": 2,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

// Resolve batch-queries OSV.dev for every discovered dependency and returns
// the matching vulnerabilities, sorted by severity (worst first).
func Resolve(deps []discover.Dependency) ([]Vulnerability, error) {
	idsPerDep, err := QueryBatch(deps)
	if err != nil {
		return nil, err
	}

	// Go note: Go has no built-in Set type, so "the unique ids we still need
	// to fetch full details for" is modeled as map[string]bool -- only the
	// key's presence matters, the boolean value itself is never read.
	needed := make(map[string]bool)
	for _, ids := range idsPerDep {
		for _, id := range ids {
			needed[id] = true
		}
	}

	details := make(map[string]*VulnDetail, len(needed))
	for id := range needed {
		detail, err := GetVulnDetails(id)
		if err != nil {
			return nil, err
		}
		details[id] = detail
	}

	var vulns []Vulnerability
	for i, ids := range idsPerDep {
		for _, id := range ids {
			vulns = append(vulns, buildVulnerability(deps[i], details[id]))
		}
	}

	vulns = dedupeByCVE(vulns)

	// Go note: sort.SliceStable takes the slice to sort and a "less"
	// function -- there's no built-in comparator interface for plain
	// slices the way some languages provide, you just tell it how to
	// compare any two elements by index. "Stable" means elements that
	// compare equal (same severity here) keep their original relative
	// order, rather than being shuffled arbitrarily.
	sort.SliceStable(vulns, func(i, j int) bool {
		return severityRank[vulns[i].Severity] > severityRank[vulns[j].Severity]
	})

	return vulns, nil
}

// dedupeByCVE collapses OSV.dev's habit of indexing the same underlying CVE
// under more than one id for some ecosystems -- e.g. PyPI advisories often
// exist as both a GHSA-* record (from GitHub's advisory database) and a
// PYSEC-* record (from the Python Packaging Authority's own advisory
// database) for the exact same CVE, which would otherwise show up as two
// separate findings for one real vulnerability. This was a real bug found
// while porting Python support to this Go version -- caught by actually
// running the tool against a real fixture, not just by reasoning about the
// code (see resolve_test.go for the regression test).
//
// The dedupe key is scoped per (ManifestPath, Name, CurrentVersion) so that
// the *same* CVE affecting the same package pinned in two different
// manifests still gets reported once per manifest, rather than the second
// occurrence being wrongly dropped too.
func dedupeByCVE(vulns []Vulnerability) []Vulnerability {
	seen := make(map[string]bool, len(vulns))
	out := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		key := v.ManifestPath + ":" + v.Name + "@" + v.CurrentVersion + ":" + cveOrID(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}

// cveOrID picks the CVE-* alias to key on when one exists (the two records
// OSV.dev might index the same vulnerability under both carry the same CVE
// alias, even though their own ids differ), falling back to the record's own
// id if it has no CVE alias at all.
func cveOrID(v Vulnerability) string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return v.ID
}

func buildVulnerability(dep discover.Dependency, detail *VulnDetail) Vulnerability {
	severity := detail.DatabaseSpecific.Severity
	if severity == "" {
		severity = "UNKNOWN"
	}

	url := ""
	for _, ref := range detail.References {
		if ref.Type == "ADVISORY" {
			url = ref.URL
			break
		}
	}
	if url == "" {
		url = "https://osv.dev/vulnerability/" + detail.ID
	}

	return Vulnerability{
		ManifestPath:   dep.ManifestPath,
		Ecosystem:      dep.Ecosystem,
		Name:           dep.Name,
		CurrentVersion: dep.Version,
		ID:             detail.ID,
		Aliases:        detail.Aliases,
		Summary:        detail.Summary,
		Severity:       severity,
		FixedVersion:   minimumFixedVersion(detail, dep.Ecosystem, dep.Name, dep.Version),
		URL:            url,
	}
}

// minimumFixedVersion finds the version that resolves this specific CVE for
// this specific package/version -- and gets right a subtlety that caused a
// real, confirmed bug while building the Node version of this tool: a single
// advisory can list several *disjoint* affected-version ranges for the same
// package (e.g. log4j-core has separate patched versions for its old
// 2.0-2.3.x line, its 2.4-2.11.x line, and its 2.13-2.14.x line). Blending
// "fixed" versions across all of them picks the global minimum, which can
// recommend a version from a release line the current version was never even
// on -- for log4j-core 2.14.1 that bug recommended "2.3.1" (a version that
// doesn't even fix the CVE for that line) instead of the correct 2.15.0. This
// only considers the range that actually contains currentVersion.
func minimumFixedVersion(detail *VulnDetail, ecosystem, name, currentVersion string) string {
	var candidates []string

	for _, aff := range detail.Affected {
		if aff.Package.Ecosystem != ecosystem || aff.Package.Name != name {
			continue
		}
		for _, r := range aff.Ranges {
			if fixed := fixedVersionIfApplicable(r.Events, currentVersion); fixed != "" {
				candidates = append(candidates, fixed)
			}
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	sort.Slice(candidates, func(i, j int) bool {
		return compareVersions(candidates[i], candidates[j]) < 0
	})
	return candidates[0]
}

// fixedVersionIfApplicable walks one range's ordered events, pairing each
// "introduced" with the next "fixed"/"last_affected" to form an interval,
// and returns the "fixed" version of whichever interval currentVersion
// actually falls in -- or "" if none does, or if the interval it's in has no
// known fix yet ("last_affected" with no paired "fixed" event).
//
// Go note: `switch` with no expression after it (just `switch {`) is Go's
// way of writing an if/else-if chain where each `case` is its own boolean
// condition -- functionally the same as JS's `if/else if/else if`, just
// Go's preferred spelling for it when there isn't one single value being
// compared against several options.
func fixedVersionIfApplicable(events []event, currentVersion string) string {
	introduced := ""
	haveIntroduced := false

	for _, e := range events {
		switch {
		case e.Introduced != "":
			introduced = e.Introduced
			haveIntroduced = true
		case e.Fixed != "":
			if haveIntroduced && isVersionInInterval(currentVersion, introduced, e.Fixed) {
				return e.Fixed
			}
			haveIntroduced = false
		case e.LastAffected != "":
			haveIntroduced = false
		}
	}
	return ""
}

// isVersionInInterval reports whether version falls within
// [introducedInclusive, fixedExclusive) -- the half-open interval OSV.dev's
// schema describes with a paired "introduced"/"fixed" event.
func isVersionInInterval(version, introducedInclusive, fixedExclusive string) bool {
	v, vOK := parseVersionParts(version)
	lo, loOK := parseVersionParts(introducedInclusive)
	hi, hiOK := parseVersionParts(fixedExclusive)
	if !vOK || !loOK || !hiOK {
		return false
	}
	return compareVersionParts(v, lo) >= 0 && compareVersionParts(v, hi) < 0
}

// parseVersionParts is a lenient dotted-numeric parser: it captures up to
// three numeric segments and stops at the first non-numeric character, so
// "2.0-beta9" parses as [2, 0, 0] -- enough for interval-boundary
// comparisons even though it discards the pre-release tag. Not real semver.
//
// Go note: returning (value, ok bool) instead of a special "invalid" sentinel
// (like JS's NaN, or null) is a common Go pattern -- "did this actually
// work" becomes an explicit, separate part of the return type that the
// compiler will complain about if a caller declares but never checks, rather
// than a value a caller might accidentally treat as valid.
func parseVersionParts(version string) ([3]int, bool) {
	var parts [3]int
	matchedAny := false

	segments := strings.SplitN(version, ".", 3)
	for i, seg := range segments {
		numeric := leadingDigits(seg)
		if numeric == "" {
			break
		}
		n, err := strconv.Atoi(numeric)
		if err != nil {
			break
		}
		parts[i] = n
		matchedAny = true
	}

	return parts, matchedAny
}

// leadingDigits returns the longest prefix of s made up of ASCII digits,
// e.g. "0-beta9" -> "0", "14" -> "14", "beta" -> "".
func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}

func compareVersionParts(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

// compareVersions is the minimal comparator sort.Slice needs above: negative
// if a < b, zero if equal, positive if a > b.
func compareVersions(a, b string) int {
	pa, _ := parseVersionParts(a)
	pb, _ := parseVersionParts(b)
	return compareVersionParts(pa, pb)
}
