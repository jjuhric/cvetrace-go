package trace

import (
	"math"
	"sort"
)

// contextMultiplier/usageMultiplier/effortBonus mirror the Node version's
// src/trace/priority.js tables exactly -- see ComputePriority's doc comment
// for what they're combined into.
var contextMultiplier = map[string]float64{
	"production":  1.0,
	"development": 0.3,
	"unknown":     0.7,
}

var usageMultiplier = map[string]float64{
	"found":     1.0,
	"not-found": 0.4,
	"unknown":   0.85,
}

var effortBonus = map[string]float64{
	"patch": 0.3,
	"minor": 0.15,
	"major": 0,
	// "unknown" is deliberately absent: a Go map lookup for a missing key
	// returns the zero value for float64 (0), which is exactly the bonus
	// this case wants -- no need to write it out explicitly the way the
	// Node version's object literal does.
}

// ComputePriority combines Severity, UsageContext, and CodeReference (plus a
// small UpdateImpact tiebreak favoring easy wins) into one sortable
// priorityScore and a P1-P4 priorityLabel -- deliberately different wording
// from Severity (the CVE's own CVSS-derived rating) so that e.g. "severity:
// CRITICAL, priority: P4" (a critical CVE in dev-only code with no detected
// usage) reads as a sensible triage call, not a contradiction. Must run
// after UsageContext (internal/discover) and CodeReference
// (internal/trace/usage.go) are both known.
//
// This is cvetrace's own synthesis for triage *ordering*, not an
// authoritative risk score -- read it the same way as the fields it's built
// from: a heuristic aid for working through a pile of findings top-down, not
// a verdict on any single one.
func ComputePriority(v Vulnerability) (priorityScore float64, priorityLabel string) {
	severityWeight := float64(SeverityRank[v.Severity])

	ctxMult, ok := contextMultiplier[v.UsageContext]
	if !ok {
		ctxMult = contextMultiplier["unknown"]
	}
	useMult, ok := usageMultiplier[v.CodeReference]
	if !ok {
		useMult = usageMultiplier["unknown"]
	}

	raw := severityWeight*ctxMult*useMult + effortBonus[v.UpdateImpact]
	// Go note: math.Round(x*100)/100 is the standard idiom for rounding a
	// float64 to two decimal places -- Go's math package has no built-in
	// "round to N decimals" the way some languages do, since floating-point
	// numbers don't actually have a fixed number of decimal digits to round
	// to internally; this is the same scale-round-unscale trick
	// `Math.round(x * 100) / 100` performs in the Node version.
	priorityScore = math.Round(raw*100) / 100

	return priorityScore, labelFor(priorityScore)
}

func labelFor(score float64) string {
	switch {
	case score >= 3.0:
		return "P1"
	case score >= 1.8:
		return "P2"
	case score >= 0.8:
		return "P3"
	default:
		return "P4"
	}
}

// ApplyPriority sets PriorityScore/PriorityLabel on every Vulnerability and
// re-sorts the slice by PriorityScore descending -- this becomes the
// pipeline's final ordering (superseding Resolve's earlier, coarser
// severity-only sort), so it needs UsageContext, CodeReference, and
// UpdateImpact already computed on every record first.
func ApplyPriority(vulns []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, len(vulns))
	for i, v := range vulns {
		v.PriorityScore, v.PriorityLabel = ComputePriority(v)
		out[i] = v
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].PriorityScore > out[j].PriorityScore
	})
	return out
}
