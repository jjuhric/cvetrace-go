package discover

import (
	"path/filepath"
	"testing"
)

// Go note: a test function must be named TestXxx, take a single *testing.T
// parameter, and live in a file ending in "_test.go" -- `go test` finds these
// by that naming convention alone, no test framework, config file, or import
// of anything beyond the standard "testing" package required.
func TestWalkFindsFixtureDependency(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "node-fixture-project")

	deps, err := Walk(fixture)
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
