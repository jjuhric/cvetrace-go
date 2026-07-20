package discover

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverNodeClassifiesDirectTransitiveAndDevScope builds a synthetic
// lockfile (webpack -> loader-utils -> vulnerable-pkg, plus a standalone dev
// dependency) to exercise buildNodeScopeMap's BFS directly, since the real
// node-fixture-project fixture only has one direct, production dependency
// and so can't exercise the transitive/dev-only paths.
func TestDiscoverNodeClassifiesDirectTransitiveAndDevScope(t *testing.T) {
	dir := t.TempDir()

	lockJSON := `{
		"packages": {
			"": {
				"name": "root",
				"version": "1.0.0",
				"dependencies": { "webpack": "5.0.0" },
				"devDependencies": { "eslint": "8.0.0" }
			},
			"node_modules/webpack": {
				"version": "5.0.0",
				"dependencies": { "loader-utils": "2.0.0" }
			},
			"node_modules/loader-utils": {
				"version": "2.0.0",
				"dependencies": { "vulnerable-pkg": "1.2.3" }
			},
			"node_modules/vulnerable-pkg": {
				"version": "1.2.3"
			},
			"node_modules/eslint": {
				"version": "8.0.0"
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"root"}`), 0o644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	deps, err := discoverNode(dir)
	if err != nil {
		t.Fatalf("discoverNode returned an error: %v", err)
	}
	byName := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	webpack, ok := byName["webpack"]
	if !ok {
		t.Fatal("expected webpack in output")
	}
	if webpack.DependencyScope != "direct" || webpack.UsageContext != "production" {
		t.Errorf("webpack: got scope=%q usage=%q, want direct/production", webpack.DependencyScope, webpack.UsageContext)
	}
	if webpack.DependencyPath != nil {
		t.Errorf("webpack: got dependencyPath %v, want nil (direct deps have no chain)", webpack.DependencyPath)
	}

	vulnerable, ok := byName["vulnerable-pkg"]
	if !ok {
		t.Fatal("expected vulnerable-pkg in output")
	}
	if vulnerable.DependencyScope != "transitive" {
		t.Errorf("vulnerable-pkg: got dependencyScope %q, want %q", vulnerable.DependencyScope, "transitive")
	}
	if vulnerable.UsageContext != "production" {
		t.Errorf("vulnerable-pkg: got usageContext %q, want %q (reachable from a prod dependency)", vulnerable.UsageContext, "production")
	}
	wantPath := []string{"webpack", "loader-utils", "vulnerable-pkg"}
	if !equalStringSlices(vulnerable.DependencyPath, wantPath) {
		t.Errorf("vulnerable-pkg: got dependencyPath %v, want %v", vulnerable.DependencyPath, wantPath)
	}

	eslint, ok := byName["eslint"]
	if !ok {
		t.Fatal("expected eslint in output")
	}
	if eslint.DependencyScope != "direct" || eslint.UsageContext != "development" {
		t.Errorf("eslint: got scope=%q usage=%q, want direct/development", eslint.DependencyScope, eslint.UsageContext)
	}
}
