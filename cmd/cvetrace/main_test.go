package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanReportsKnownCVEs runs the actual CLI (via "go run", the same way a
// user would run it during development) against the fixture project and
// checks the output for both known CVEs -- an end-to-end check that the
// whole pipeline (discover -> trace -> report) works together, not just
// each package in isolation. Needs network access (OSV.dev) and the "go"
// command on PATH.
func TestScanReportsKnownCVEs(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan failed: %v\noutput:\n%s", err, out)
	}

	output := string(out)
	for _, want := range []string{"CVE-2020-7598", "CVE-2021-44906"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %s in output, got:\n%s", want, output)
		}
	}
}

// TestScanJSONFlagWorksAfterThePath is the end-to-end counterpart to
// internal/cli's TestReorderFlagsFirst -- proves the real CLI, not just the
// helper function in isolation, produces valid JSON when --json comes after
// the path (the order a user coming from the Node version's commander.js
// CLI would naturally type).
func TestScanJSONFlagWorksAfterThePath(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture, "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan --json failed: %v\noutput:\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, `"vulnerabilityCount"`) {
		t.Errorf("expected JSON output, got:\n%s", output)
	}
}
