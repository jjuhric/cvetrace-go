package report

import (
	"encoding/json"
	"time"

	"github.com/jjuhric/cvetrace-go/internal/trace"
)

// jsonReport is the top-level shape of --json output. It's unexported
// (lowercase) since nothing outside this package needs to name the type
// directly -- callers only ever see the []byte that BuildJSON returns.
type jsonReport struct {
	GeneratedAt        string                `json:"generatedAt"`
	VulnerabilityCount int                   `json:"vulnerabilityCount"`
	Vulnerabilities    []trace.Vulnerability `json:"vulnerabilities"`
}

// BuildJSON renders vulns as an indented JSON document, matching the shape
// (if not yet every field -- see the project README for what's deliberately
// not ported over yet) of the Node version's --json output.
//
// Go note: json.MarshalIndent (and encoding/json generally) uses each
// struct's field tags to decide JSON key names and nesting -- there's no
// separate "schema" to define; the Go struct *is* the schema.
func BuildJSON(vulns []trace.Vulnerability) ([]byte, error) {
	report := jsonReport{
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		VulnerabilityCount: len(vulns),
		Vulnerabilities:    vulns,
	}
	return json.MarshalIndent(report, "", "  ")
}
