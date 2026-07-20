package main

import (
	"encoding/json"
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

func TestScanReportsKnownCVEInJavaFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "java-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan failed: %v\noutput:\n%s", err, out)
	}

	if !strings.Contains(string(out), "CVE-2021-44228") {
		t.Errorf("expected Log4Shell (CVE-2021-44228) in output, got:\n%s", out)
	}
}

func TestScanReportsKnownCVEInPythonFixtureWithoutDuplicates(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "python-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture, "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan --json failed: %v\noutput:\n%s", err, out)
	}

	// Go note: decoding into an anonymous struct with just the one field this
	// test cares about works fine -- encoding/json ignores every other key
	// present in the actual JSON, the same way it ignores unrecognized
	// fields when decoding OSV.dev's responses elsewhere in this project.
	var report struct {
		Vulnerabilities []struct {
			Aliases []string `json:"aliases"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("could not parse output as JSON: %v\noutput:\n%s", err, out)
	}

	// Regression check for the GHSA/PYSEC duplicate-record bug: exactly one
	// *record* should carry the CVE-2020-14343 alias, not two.
	matches := 0
	for _, v := range report.Vulnerabilities {
		for _, alias := range v.Aliases {
			if alias == "CVE-2020-14343" {
				matches++
			}
		}
	}
	if matches != 1 {
		t.Errorf("expected exactly 1 record with alias CVE-2020-14343, got %d:\n%s", matches, out)
	}
}

func TestScanWalksAMixedDirectoryAndFindsAllThreeEcosystems(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "test", "fixtures")

	cmd := exec.Command("go", "run", ".", "scan", fixturesDir, "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan --json failed: %v\noutput:\n%s", err, out)
	}

	output := string(out)
	for _, want := range []string{`"ecosystem": "npm"`, `"ecosystem": "Maven"`, `"ecosystem": "PyPI"`} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %s in output", want)
		}
	}
}
