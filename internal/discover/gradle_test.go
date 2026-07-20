package discover

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseGradleOutput is a pure test (no real Gradle process needed) for
// the flat CVETRACE_DIRECT/CVETRACE_DEP|... line format the init script
// produces -- deduplicates repeats (the same coordinate reached via two
// configurations) and derives the group:artifact name correctly.
func TestParseGradleOutputParsesAndDedupes(t *testing.T) {
	output := "CVETRACE_DIRECT|/proj|org.example:lib\n" +
		"CVETRACE_DEP|/proj|implementation|org.example:lib:1.0.0\n" +
		"CVETRACE_DEP|/proj|testImplementation|org.example:lib:1.0.0\n" + // duplicate coordinate, second configuration
		"CVETRACE_DEP|/proj|implementation|org.example:other:2.0.0\n" +
		"not a CVETRACE line, should be ignored\n"

	deps := parseGradleOutput(output)
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2 (duplicate should be collapsed)", len(deps))
	}

	names := make(map[string]string, len(deps))
	for _, d := range deps {
		names[d.Name] = d.Version
	}
	if names["org.example:lib"] != "1.0.0" {
		t.Errorf("got lib version %q, want %q", names["org.example:lib"], "1.0.0")
	}
	if names["org.example:other"] != "2.0.0" {
		t.Errorf("got other version %q, want %q", names["org.example:other"], "2.0.0")
	}
}

// TestParseGradleOutputClassifiesScopeAndUsage checks the scope/usage/path
// fields the init script's new CVETRACE_DIRECT lines and per-configuration
// chains make possible: a first-level dependency declared directly in a
// `dependencies {}` block is "direct"; anything only reached transitively
// (via another dependency's own children) is "transitive" with a
// DependencyPath; a coordinate seen only under a test-ish configuration name
// is "development", otherwise "production".
func TestParseGradleOutputClassifiesScopeAndUsage(t *testing.T) {
	output := "CVETRACE_DIRECT|/proj|org.example:direct-lib\n" +
		"CVETRACE_DEP|/proj|implementation|org.example:direct-lib:1.0.0\n" +
		"CVETRACE_DEP|/proj|implementation|org.example:direct-lib:1.0.0>org.example:transitive-lib:2.0.0\n" +
		"CVETRACE_DEP|/proj|testImplementation|org.example:test-only-lib:3.0.0\n"

	deps := parseGradleOutput(output)
	byName := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	direct, ok := byName["org.example:direct-lib"]
	if !ok {
		t.Fatal("expected org.example:direct-lib in output")
	}
	if direct.DependencyScope != "direct" {
		t.Errorf("direct-lib: got dependencyScope %q, want %q", direct.DependencyScope, "direct")
	}
	if direct.UsageContext != "production" {
		t.Errorf("direct-lib: got usageContext %q, want %q", direct.UsageContext, "production")
	}
	if direct.DependencyPath != nil {
		t.Errorf("direct-lib: got dependencyPath %v, want nil (direct deps have no chain)", direct.DependencyPath)
	}

	transitive, ok := byName["org.example:transitive-lib"]
	if !ok {
		t.Fatal("expected org.example:transitive-lib in output")
	}
	if transitive.DependencyScope != "transitive" {
		t.Errorf("transitive-lib: got dependencyScope %q, want %q", transitive.DependencyScope, "transitive")
	}
	wantPath := []string{"org.example:direct-lib", "org.example:transitive-lib"}
	if !equalStringSlices(transitive.DependencyPath, wantPath) {
		t.Errorf("transitive-lib: got dependencyPath %v, want %v", transitive.DependencyPath, wantPath)
	}

	testOnly, ok := byName["org.example:test-only-lib"]
	if !ok {
		t.Fatal("expected org.example:test-only-lib in output")
	}
	if testOnly.UsageContext != "development" {
		t.Errorf("test-only-lib: got usageContext %q, want %q", testOnly.UsageContext, "development")
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFindGradleRootFindsTheNearestMarker uses a real temp directory tree
// (no Gradle invocation) to check the ancestor-search logic in isolation.
//
// Go note: t.TempDir() creates a fresh temporary directory and registers it
// for automatic cleanup when the test finishes -- no manual defer os.
// RemoveAll needed, unlike the mkdtemp+defer rm pattern this project's Node
// version uses in its own tests.
func TestFindGradleRootFindsTheNearestMarker(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub", "module")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("failed to set up temp dirs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "settings.gradle"), nil, 0o644); err != nil {
		t.Fatalf("failed to write settings.gradle: %v", err)
	}

	got := findGradleRoot(sub, root)
	if got != root {
		t.Errorf("got %q, want %q (nearest ancestor with settings.gradle)", got, root)
	}
}

func TestFindGradleRootFallsBackToStartDirWhenNoMarkerExists(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("failed to set up temp dirs: %v", err)
	}

	got := findGradleRoot(sub, root)
	if got != sub {
		t.Errorf("got %q, want %q (no marker anywhere, should fall back to startDir)", got, sub)
	}
}

// TestStaticGradleFallbackParsesLiteralCoordinates verifies the regex-based
// fallback used only when Gradle genuinely can't be invoked.
func TestStaticGradleFallbackParsesLiteralCoordinates(t *testing.T) {
	dir := t.TempDir()
	content := "dependencies {\n    implementation 'org.example:lib:1.2.3'\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write build.gradle: %v", err)
	}

	deps := staticGradleFallback(dir)
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1", len(deps))
	}
	if deps[0].Name != "org.example:lib" || deps[0].Version != "1.2.3" {
		t.Errorf("got %+v, want org.example:lib@1.2.3", deps[0])
	}
}
