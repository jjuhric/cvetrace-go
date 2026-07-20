package discover

import (
	"os"
	"path/filepath"
	"testing"
)

// Go note: a test function must be named TestXxx, take a single *testing.T
// parameter, and live in a file ending in "_test.go" -- `go test` finds these
// by that naming convention alone, no test framework, config file, or import
// of anything beyond the standard "testing" package required.
func TestWalkFindsFixtureDependency(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	deps, err := Walk(fixture, nil)
	if err != nil {
		// t.Fatalf both logs the message and stops this test immediately --
		// there's no point checking anything else if Walk itself failed.
		t.Fatalf("Walk returned an error: %v", err)
	}

	var minimist *Dependency
	for i := range deps {
		if deps[i].Name == "minimist" {
			minimist = &deps[i]
			break
		}
	}

	if minimist == nil {
		t.Fatal("expected minimist to be discovered")
	}
	if minimist.Ecosystem != "npm" {
		t.Errorf("got ecosystem %q, want %q", minimist.Ecosystem, "npm")
	}
	if minimist.Version != "0.0.8" {
		t.Errorf("got version %q, want %q", minimist.Version, "0.0.8")
	}
	if filepath.Base(minimist.ManifestPath) != "package-lock.json" {
		t.Errorf("got manifest %q, want it to end in package-lock.json", minimist.ManifestPath)
	}
}

// TestWalkSkipsExcludedDirectories builds a synthetic project with two
// separate Node manifests, one inside a directory matched by an --exclude
// glob, and checks that only the non-excluded one is discovered.
func TestWalkSkipsExcludedDirectories(t *testing.T) {
	root := t.TempDir()

	kept := filepath.Join(root, "app")
	skipped := filepath.Join(root, "vendor", "legacy")
	if err := os.MkdirAll(kept, 0o755); err != nil {
		t.Fatalf("failed to create %s: %v", kept, err)
	}
	if err := os.MkdirAll(skipped, 0o755); err != nil {
		t.Fatalf("failed to create %s: %v", skipped, err)
	}

	writeManifest := func(dir, name string) {
		content := `{"name":"` + name + `","version":"1.0.0","dependencies":{"` + name + `":"1.0.0"}}`
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write package.json in %s: %v", dir, err)
		}
	}
	writeManifest(kept, "kept-pkg")
	writeManifest(skipped, "skipped-pkg")

	deps, err := Walk(root, []string{"vendor/**"})
	if err != nil {
		t.Fatalf("Walk returned an error: %v", err)
	}

	names := make(map[string]bool, len(deps))
	for _, d := range deps {
		names[d.Name] = true
	}
	if !names["kept-pkg"] {
		t.Error("expected kept-pkg (outside the excluded tree) to be discovered")
	}
	if names["skipped-pkg"] {
		t.Error("expected skipped-pkg (inside vendor/**, excluded) not to be discovered")
	}
}
