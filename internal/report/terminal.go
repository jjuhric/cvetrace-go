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

// PrintTerminal writes a human-readable, colorized report to stdout.
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

		fixed := v.FixedVersion
		if fixed == "" {
			fixed = "unknown"
		}

		fmt.Printf("%s%s%s %s@%s [%s%s%s] -> fix: %s\n",
			colorRed, preferredLabel(v), colorReset,
			v.Name, v.CurrentVersion,
			paint, v.Severity, colorReset,
			fixed,
		)
		fmt.Println("  " + colorGray + v.ManifestPath + colorReset)
		if context := describeContext(v); context != "" {
			fmt.Println("  " + colorGray + context + colorReset)
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
// usage fields -- "transitive (via a > b)", "production", etc. None of this
// is proof of anything: dependencyScope/usageContext are noise-reduction
// signals for prioritizing what to look at first, not a reachability
// guarantee. Returns "" when there's nothing informative to say (both fields
// unknown), so the terminal report doesn't print an empty line for every
// finding from a source that can't determine either.
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

	return strings.Join(parts, " · ")
}
