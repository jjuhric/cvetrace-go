package trace

import (
	"os"
	"path/filepath"
	"strings"
)

// IgnoreRule is one entry dismissing a specific CVE/GHSA/etc. id, either
// loaded from a .cvetraceignore file or passed via --ignore.
type IgnoreRule struct {
	ID     string
	Reason string // "" if none given
	Source string // ".cvetraceignore" or "--ignore"
}

// LoadIgnoreFile parses a .cvetraceignore file at the scan target's root:
// one CVE/GHSA/PYSEC id per line, blank lines and full-line "#" comments
// skipped, an optional trailing "# reason" captured for the audit trail.
// Mirrors how Nexus IQ/Dependabot let you dismiss a reviewed-and-accepted
// finding so it doesn't get re-flagged on every run. Returns (nil, nil) if
// no .cvetraceignore file exists.
func LoadIgnoreFile(targetPath string) ([]IgnoreRule, error) {
	raw, err := os.ReadFile(filepath.Join(targetPath, ".cvetraceignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var rules []IgnoreRule
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		id, reason := line, ""
		if hashIndex := strings.Index(line, "#"); hashIndex != -1 {
			id = strings.TrimSpace(line[:hashIndex])
			reason = strings.TrimSpace(line[hashIndex+1:])
		}
		if id != "" {
			rules = append(rules, IgnoreRule{ID: id, Reason: reason, Source: ".cvetraceignore"})
		}
	}
	return rules, nil
}

// IgnoredVulnerability is a Vulnerability that matched an ignore rule, kept
// around (rather than silently dropped) so --json can show a full audit
// trail of what was suppressed and why.
//
// Go note: embedding Vulnerability (a field with no name, just its type) is
// how Go expresses "this struct has all of Vulnerability's fields, plus
// these two more" -- the closest equivalent to JS's object-spread
// `{ ...finding, ignoredReason, ignoredVia }`. encoding/json marshals an
// embedded struct's fields inline at the same level as the outer struct's
// own fields, rather than nesting them under a "Vulnerability" key, which is
// what makes the JSON output actually look flat like the spread does.
type IgnoredVulnerability struct {
	Vulnerability
	IgnoredReason string `json:"ignoredReason,omitempty"`
	IgnoredVia    string `json:"ignoredVia"`
}

// ApplyIgnoreRules merges fileRules with cliIDs (--ignore values, which
// carry no reason), then splits vulns into (kept, ignored). A finding
// matches if its own id or any of its aliases matches a rule.
func ApplyIgnoreRules(vulns []Vulnerability, fileRules []IgnoreRule, cliIDs []string) (kept []Vulnerability, ignored []IgnoredVulnerability) {
	ruleByID := make(map[string]IgnoreRule, len(fileRules)+len(cliIDs))
	for _, rule := range fileRules {
		ruleByID[rule.ID] = rule
	}
	for _, id := range cliIDs {
		ruleByID[id] = IgnoreRule{ID: id, Source: "--ignore"}
	}

	for _, v := range vulns {
		matched, ok := matchIgnoreRule(v, ruleByID)
		if !ok {
			kept = append(kept, v)
			continue
		}
		ignored = append(ignored, IgnoredVulnerability{
			Vulnerability: v,
			IgnoredReason: matched.Reason,
			IgnoredVia:    matched.Source,
		})
	}
	return kept, ignored
}

// matchIgnoreRule checks v's own id first, then each of its aliases in
// order, returning the first rule found -- matching the Node version's
// `[finding.id, ...finding.aliases].map(...).find(Boolean)`.
func matchIgnoreRule(v Vulnerability, ruleByID map[string]IgnoreRule) (IgnoreRule, bool) {
	if rule, ok := ruleByID[v.ID]; ok {
		return rule, true
	}
	for _, alias := range v.Aliases {
		if rule, ok := ruleByID[alias]; ok {
			return rule, true
		}
	}
	return IgnoreRule{}, false
}
