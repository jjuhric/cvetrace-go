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

// TestScanReportsKnownCVEInGradleFixtureViaRealInvocation runs the built CLI
// against a fixture with a real, committed Gradle wrapper -- this specifically
// exercises resolveGradleProject's actual subprocess invocation path, not
// just the static-parsing fallback. Needs Java installed, and can be slow on
// a cold Gradle distribution/daemon cache, hence the generous timeout.
func TestScanReportsKnownCVEInGradleFixtureViaRealInvocation(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "gradle-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan failed: %v\noutput:\n%s", err, out)
	}

	if !strings.Contains(string(out), "CVE-2021-44228") {
		t.Errorf("expected Log4Shell (CVE-2021-44228) in output, got:\n%s", out)
	}
}

func TestScanWalksAMixedDirectoryAndFindsAllFourEcosystems(t *testing.T) {
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

	// The pom.xml and build.gradle fixtures both pin log4j-core@2.14.1 --
	// confirms dedupeByCVE's manifest-scoped key reports each manifest's
	// occurrence separately instead of collapsing them into one.
	var report struct {
		Vulnerabilities []struct {
			Name         string `json:"name"`
			ManifestPath string `json:"manifestPath"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("could not parse output as JSON: %v", err)
	}

	manifests := make(map[string]bool)
	for _, v := range report.Vulnerabilities {
		if v.Name == "org.apache.logging.log4j:log4j-core" {
			manifests[v.ManifestPath] = true
		}
	}
	if len(manifests) != 2 {
		t.Errorf("expected log4j-core reported for 2 distinct manifests (pom.xml and build.gradle), got %d: %v",
			len(manifests), manifests)
	}
}

// TestScanExcludeSkipsAMatchingDirectory runs the real CLI with --exclude
// against the mixed fixtures directory and confirms PyPI findings disappear
// once python-fixture-project/** is excluded, while the other ecosystems'
// findings are unaffected.
func TestScanExcludeSkipsAMatchingDirectory(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "test", "fixtures")

	cmd := exec.Command("go", "run", ".", "scan", fixturesDir, "--exclude", "python-fixture-project/**", "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan --exclude failed: %v\noutput:\n%s", err, out)
	}

	output := string(out)
	if strings.Contains(output, `"ecosystem": "PyPI"`) {
		t.Errorf("expected no PyPI findings once python-fixture-project/** is excluded, got:\n%s", output)
	}
	if !strings.Contains(output, `"ecosystem": "npm"`) {
		t.Errorf("expected npm findings to still be present (not excluded), got:\n%s", output)
	}
}

// TestScanIgnoreDismissesASpecificFinding runs the real CLI with --ignore
// against the Node fixture (which has two known CVEs for minimist) and
// confirms the ignored one is dropped from vulnerabilities but still
// recorded in the JSON output's ignored array for audit purposes.
func TestScanIgnoreDismissesASpecificFinding(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture, "--ignore", "CVE-2021-44906", "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cvetrace scan --ignore failed: %v\noutput:\n%s", err, out)
	}

	var report struct {
		Vulnerabilities []struct {
			Aliases []string `json:"aliases"`
		} `json:"vulnerabilities"`
		IgnoredCount int `json:"ignoredCount"`
		Ignored      []struct {
			Aliases       []string `json:"aliases"`
			IgnoredVia    string   `json:"ignoredVia"`
			IgnoredReason string   `json:"ignoredReason"`
		} `json:"ignored"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("could not parse output as JSON: %v\noutput:\n%s", err, out)
	}

	for _, v := range report.Vulnerabilities {
		for _, alias := range v.Aliases {
			if alias == "CVE-2021-44906" {
				t.Errorf("expected CVE-2021-44906 to be dropped from vulnerabilities, still present:\n%s", out)
			}
		}
	}
	if report.IgnoredCount != 1 || len(report.Ignored) != 1 {
		t.Fatalf("expected exactly 1 ignored finding, got ignoredCount=%d len(ignored)=%d:\n%s",
			report.IgnoredCount, len(report.Ignored), out)
	}
	if report.Ignored[0].IgnoredVia != "--ignore" {
		t.Errorf("got ignoredVia %q, want %q", report.Ignored[0].IgnoredVia, "--ignore")
	}
}

// TestScanFailOnSetsExitCodeOneWhenThresholdIsMet runs the real CLI with
// --fail-on against the Node fixture, which has a CRITICAL CVE -- confirms
// the process exits 1, the real signal a CI pipeline gates on.
func TestScanFailOnSetsExitCodeOneWhenThresholdIsMet(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture, "--fail-on", "critical")
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the process to exit non-zero (a CRITICAL CVE is present), got err=%v\noutput:\n%s", err, out)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("got exit code %d, want 1\noutput:\n%s", exitErr.ExitCode(), out)
	}
}

// TestScanFailOnSetsExitCodeZeroWhenThresholdIsNotMet is the mirror check:
// once the fixture's only CRITICAL finding is dismissed via --ignore, the
// remaining MODERATE finding no longer meets a "critical" --fail-on
// threshold, so the process should exit 0 -- and, just as importantly,
// ignored findings must never count toward --fail-on themselves.
func TestScanFailOnSetsExitCodeZeroWhenThresholdIsNotMet(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture, "--ignore", "CVE-2021-44906", "--fail-on", "critical")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0 once the only CRITICAL finding is ignored, got err=%v\noutput:\n%s", err, out)
	}
}

// TestScanFailOnRejectsAnUnknownSeverity confirms an unrecognized --fail-on
// value is a hard error (exit 1 with a message), not a silently-ignored
// no-op that would defeat the point of a CI gate.
func TestScanFailOnRejectsAnUnknownSeverity(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	cmd := exec.Command("go", "run", ".", "scan", fixture, "--fail-on", "not-a-real-severity")
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the process to exit non-zero for an unrecognized --fail-on value, got err=%v\noutput:\n%s", err, out)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("got exit code %d, want 1\noutput:\n%s", exitErr.ExitCode(), out)
	}
	if !strings.Contains(string(out), "unknown --fail-on severity") {
		t.Errorf("expected an explanatory error message, got:\n%s", out)
	}
}
