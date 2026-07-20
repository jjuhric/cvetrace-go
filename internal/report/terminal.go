// Package report turns a slice of trace.Vulnerability values into either a
// colorized terminal listing or a JSON document.
package report

import (
	"fmt"
	"strings"

	"github.com/jjuhric/cvetrace-go/internal/trace"
)

// ANSI escape codes for terminal color.
//
// Go note: these are ordinary string constants -- Go has no special
// "template literal" syntax like JS's `${x}`, so building colored output
// below is done with fmt.Printf's %s placeholders instead.
const (
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorYellow = "\x1b[33m"
	colorGreen  = "\x1b[32m"
	colorGray   = "\x1b[90m"
	colorCyan   = "\x1b[36m"
	colorBold   = "\x1b[1m"
)

var severityColor = map[string]string{
	"CRITICAL": colorRed,
	"HIGH":     colorRed,
	"MODERATE": colorYellow,
	"MEDIUM":   colorYellow,
	"LOW":      colorGray,
	"UNKNOWN":  colorGray,
}

var codeReferenceLabel = map[string]string{
	"found":     "used in code",
	"not-found": "no code reference found",
	"unknown":   "code usage unknown",
}

var updateImpactLabel = map[string]string{
	"patch":   "patch bump, likely safe",
	"minor":   "minor bump, likely safe",
	"major":   "major bump — review before applying",
	"unknown": "fix version unknown",
}

// remediationAction is the single call-to-action per finding -- see
// trace.classifyRemediationTier's doc comment for exactly what each tier
// means and doesn't guarantee. Meant to be actionable by a human or an AI
// agent without needing to cross-reference UpdateImpact/FixedVersion itself.
var remediationAction = map[string]string{
	"safe-to-update":   "safe to auto-update",
	"needs-approval":   "needs approval before updating (major version bump)",
	"no-fix-available": "no fix published yet -- see advisory for mitigation guidance",
	"unknown-impact":   "fix version unparseable -- treat like needs-approval",
}

var remediationColor = map[string]string{
	"safe-to-update":   colorGreen,
	"needs-approval":   colorYellow,
	"no-fix-available": colorGray,
	"unknown-impact":   colorGray,
}

var priorityColor = map[string]string{
	"P1": colorRed,
	"P2": colorRed,
	"P3": colorYellow,
	"P4": colorGray,
}

// PrintTerminal writes a human-readable, colorized report to stdout, flat and
// sorted by PriorityScore descending (already sorted by trace.ApplyPriority)
// -- priority mixes findings across manifests deliberately, so this is no
// longer grouped by manifest file; each line names its own manifest instead.
// Meant to be worked top-down.
func PrintTerminal(vulns []trace.Vulnerability) {
	if len(vulns) == 0 {
		fmt.Println(colorGray + "No known vulnerabilities found." + colorReset)
		return
	}

	for _, v := range vulns {
		paint := severityColor[v.Severity]
		if paint == "" {
			paint = colorGray
		}
		priorityPaint := priorityColor[v.PriorityLabel]
		if priorityPaint == "" {
			priorityPaint = colorGray
		}

		fixed := v.FixedVersion
		if fixed == "" {
			fixed = "unknown"
		}

		fmt.Printf("%s[%s]%s %s%s%s %s@%s [%s%s%s] -> fix: %s\n",
			priorityPaint, v.PriorityLabel, colorReset,
			colorRed, preferredLabel(v), colorReset,
			v.Name, v.CurrentVersion,
			paint, v.Severity, colorReset,
			fixed,
		)

		action := remediationAction[v.RemediationTier]
		if action == "" {
			action = v.RemediationTier
		}
		remediationPaint := remediationColor[v.RemediationTier]
		if remediationPaint == "" {
			remediationPaint = colorGray
		}
		fmt.Println("  " + remediationPaint + "-> " + action + colorReset)

		fmt.Println("  " + colorGray + v.ManifestPath + colorReset)
		fmt.Println("  " + colorGray + describeContext(v) + colorReset)
		if v.RecommendedVersion != "" && v.RecommendedVersion != v.FixedVersion {
			fmt.Println("  " + colorGray +
				"recommended target: " + v.RecommendedVersion + " (clears every known issue for this package)" +
				colorReset)
		}
		if v.OverrideSnippet != nil {
			fmt.Println("  " + colorGray +
				"override available (edit " + v.OverrideSnippet.File + ") without waiting on the parent -- see --json for the exact snippet" +
				colorReset)
		}
		if v.Summary != "" {
			fmt.Println("  " + colorGray + v.Summary + colorReset)
		}
		fmt.Println("  " + colorCyan + v.URL + colorReset)
		fmt.Println()
	}

	noun := "vulnerabilities"
	if len(vulns) == 1 {
		noun = "vulnerability"
	}
	fmt.Printf("%s%d %s found.%s\n", colorBold, len(vulns), noun, colorReset)
}

// preferredLabel picks the CVE-* alias to display if the advisory has one
// (more recognizable than an OSV/GHSA id), falling back to the raw id
// otherwise.
func preferredLabel(v trace.Vulnerability) string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return v.ID
}

// describeContext builds a one-line triage summary from the heuristic scope/
// usage/code-reference/update-impact fields -- "transitive (via a > b) ·
// production · used in code · minor bump, likely safe", etc. None of this is
// proof of anything: dependencyScope/usageContext/codeReference are noise-
// reduction signals for prioritizing what to look at first, and updateImpact
// is a semver-distance signal, not a safety guarantee -- see
// classifyRemediationTier's doc comment in internal/trace/resolve.go.
func describeContext(v trace.Vulnerability) string {
	var parts []string

	if v.DependencyScope == "transitive" && len(v.DependencyPath) > 1 {
		via := strings.Join(v.DependencyPath[:len(v.DependencyPath)-1], " > ")
		parts = append(parts, "transitive (via "+via+")")
	} else if v.DependencyScope != "" && v.DependencyScope != "unknown" {
		parts = append(parts, v.DependencyScope)
	}

	if v.UsageContext != "" && v.UsageContext != "unknown" {
		parts = append(parts, v.UsageContext)
	}

	codeRefLabel, ok := codeReferenceLabel[v.CodeReference]
	if !ok {
		codeRefLabel = codeReferenceLabel["unknown"]
	}
	parts = append(parts, codeRefLabel)

	impactLabel, ok := updateImpactLabel[v.UpdateImpact]
	if !ok {
		impactLabel = updateImpactLabel["unknown"]
	}
	parts = append(parts, impactLabel)

	return strings.Join(parts, " · ")
}
