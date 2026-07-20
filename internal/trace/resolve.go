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

	// AdvisoryDetails is OSV.dev's longer freeform advisory text -- often
	// includes a "Remediation Advice"/mitigation section beyond just
	// "upgrade to X" (e.g. Log4Shell's config-flag workaround for anyone who
	// can't upgrade immediately). "" when OSV has none.
	AdvisoryDetails string `json:"advisoryDetails,omitempty"`

	// RecommendedVersion is the single highest FixedVersion across every CVE
	// known for this exact (ManifestPath, Name) package instance -- set by
	// addRecommendedVersions after every Vulnerability for a scan has been
	// built, since it depends on seeing every finding for that package
	// first. "" until then, and "" if none of that package's findings have a
	// known fix yet.
	RecommendedVersion string `json:"recommendedVersion,omitempty"`

	// UpdateImpact is a semver-distance heuristic between CurrentVersion and
	// FixedVersion ("patch"/"minor"/"major"/"unknown") -- a signal for how
	// likely the fix is to be backwards-compatible, not a guarantee.
	UpdateImpact string `json:"updateImpact"`

	// RemediationTier collapses FixedVersion + UpdateImpact into one
	// decision an agent or human can branch on directly -- see
	// classifyRemediationTier's doc comment.
	RemediationTier string `json:"remediationTier"`

	// OverrideSnippet is set by ApplyOverrideSnippets, a separate pass run
	// after Resolve -- nil for every Vulnerability from Resolve itself, and
	// nil after ApplyOverrideSnippets too unless the finding is confidently
	// transitive with a known target version (see generateOverrideSnippet).
	OverrideSnippet *OverrideSnippet `json:"overrideSnippet,omitempty"`

	// PriorityScore/PriorityLabel are set by ApplyPriority, the pipeline's
	// last enrichment step -- see ComputePriority's doc comment. Both are
	// their zero values (0, "") on every Vulnerability from Resolve itself.
	PriorityScore float64 `json:"priorityScore"`
	PriorityLabel string  `json:"priorityLabel"`

	// DependencyScope/UsageContext/DependencyPath are carried straight
	// through from the discover.Dependency this Vulnerability was built
	// from -- see that struct's field docs for exactly what each means and
	// which ecosystems can/can't populate them precisely.
	DependencyScope string   `json:"dependencyScope"`
	UsageContext    string   `json:"usageContext"`
	DependencyPath  []string `json:"dependencyPath,omitempty"`

	// CodeReference is set by internal/trace's DetectCodeReferences, a
	// separate pass over the project's own source files run after Resolve --
	// every Vulnerability from Resolve itself starts with CodeReference
	// unset ("", rendered "unknown" everywhere it's displayed) until that
	// pass runs.
	CodeReference string `json:"codeReference"`
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

	vulns = addRecommendedVersions(dedupeByCVE(vulns))

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

// addRecommendedVersions aggregates each package instance's (ManifestPath +
// Name) individual CVE fixes into one RecommendedVersion: the highest
// FixedVersion among them, since upgrading to it satisfies every lower one
// too -- lets a human/AI jump straight to "upgrade to X, clears all N known
// issues" instead of reconciling N separate per-CVE fix versions (log4j-core
// alone has several in this project's own test fixture, each with its own
// nearest fix). A Vulnerability whose own FixedVersion is "" (no fix
// published yet for that specific CVE) is NOT resolved just by its package
// reaching a RecommendedVersion -- see AdvisoryDetails for mitigation
// guidance in that case instead.
func addRecommendedVersions(vulns []Vulnerability) []Vulnerability {
	maxFixedByPackage := make(map[string]string)
	for _, v := range vulns {
		if v.FixedVersion == "" {
			continue
		}
		key := v.ManifestPath + ":" + v.Name
		if current, ok := maxFixedByPackage[key]; !ok || compareVersions(v.FixedVersion, current) > 0 {
			maxFixedByPackage[key] = v.FixedVersion
		}
	}

	for i := range vulns {
		vulns[i].RecommendedVersion = maxFixedByPackage[vulns[i].ManifestPath+":"+vulns[i].Name]
	}
	return vulns
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

	dependencyScope := dep.DependencyScope
	if dependencyScope == "" {
		dependencyScope = "unknown"
	}
	usageContext := dep.UsageContext
	if usageContext == "" {
		usageContext = "unknown"
	}

	fixedVersion := minimumFixedVersion(detail, dep.Ecosystem, dep.Name, dep.Version)
	updateImpact := classifyVersionJump(dep.Version, fixedVersion)

	return Vulnerability{
		ManifestPath:    dep.ManifestPath,
		Ecosystem:       dep.Ecosystem,
		Name:            dep.Name,
		CurrentVersion:  dep.Version,
		ID:              detail.ID,
		Aliases:         detail.Aliases,
		Summary:         detail.Summary,
		AdvisoryDetails: detail.Details,
		Severity:        severity,
		FixedVersion:    fixedVersion,
		URL:             url,
		DependencyScope: dependencyScope,
		UsageContext:    usageContext,
		DependencyPath:  dep.DependencyPath,
		UpdateImpact:    updateImpact,
		RemediationTier: classifyRemediationTier(fixedVersion, updateImpact),
	}
}

// classifyVersionJump compares the first differing dotted-numeric segment
// between current and fixed. Not real semver (doesn't handle pre-release
// tags, and Maven/Gradle coordinates don't always follow semver conventions
// to begin with) -- a best-effort signal for triage, always to be read as
// "likely," never "guaranteed."
func classifyVersionJump(current, fixed string) string {
	if fixed == "" {
		return "unknown"
	}
	c, cOK := parseVersionParts(current)
	f, fOK := parseVersionParts(fixed)
	if !cOK || !fOK {
		return "unknown"
	}
	switch {
	case f[0] != c[0]:
		return "major"
	case f[1] != c[1]:
		return "minor"
	default:
		return "patch"
	}
}

// classifyRemediationTier collapses FixedVersion + UpdateImpact into one
// decision an agent or human can branch on directly, instead of everyone
// re-deriving the same three-way call from those two fields independently
// (and potentially disagreeing on edge cases):
//
//	"safe-to-update"    patch/minor bump, likely backwards-compatible -- apply it.
//	"needs-approval"    major bump, likely to need code changes -- propose a plan,
//	                    wait for a human to approve before touching anything.
//	"no-fix-available"  no version resolves this specific CVE yet -- see
//	                    AdvisoryDetails for a workaround/mitigation instead.
//	"unknown-impact"    a fix exists but current/fixed versions weren't both
//	                    parseable as dotted-numeric, so the size of the jump
//	                    can't be classified -- treated like needs-approval:
//	                    safety can't be confirmed either way.
//
// Still a heuristic layered on other heuristics, not a safety guarantee --
// see classifyVersionJump's own caveat above.
func classifyRemediationTier(fixedVersion, updateImpact string) string {
	switch {
	case fixedVersion == "":
		return "no-fix-available"
	case updateImpact == "patch" || updateImpact == "minor":
		return "safe-to-update"
	case updateImpact == "major":
		return "needs-approval"
	default:
		return "unknown-impact"
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
