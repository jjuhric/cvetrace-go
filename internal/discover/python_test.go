package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverPythonResolvesRequirementsTXTAndNormalizesName(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "python-fixture-project")

	deps, err := discoverPython(fixture)
	if err != nil {
		t.Fatalf("discoverPython returned an error: %v", err)
	}

	var pyyaml *Dependency
	for i := range deps {
		if deps[i].Name == "pyyaml" {
			pyyaml = &deps[i]
			break
		}
	}

	if pyyaml == nil {
		t.Fatal("expected PyYAML to be discovered under its normalized name")
	}
	if pyyaml.Ecosystem != "PyPI" {
		t.Errorf("got ecosystem %q, want %q", pyyaml.Ecosystem, "PyPI")
	}
	if pyyaml.Version != "5.3" {
		t.Errorf("got version %q, want %q", pyyaml.Version, "5.3")
	}
}

func TestDiscoverPipfileLockSplitsDefaultAndDevelop(t *testing.T) {
	raw := `{
		"default": {"flask": {"version": "==2.0.0"}},
		"develop": {"pytest": {"version": "==7.0.0"}}
	}`

	deps, err := discoverPipfileLock(raw, "Pipfile.lock")
	if err != nil {
		t.Fatalf("discoverPipfileLock returned an error: %v", err)
	}

	byName := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	flask, ok := byName["flask"]
	if !ok || flask.Version != "2.0.0" {
		t.Errorf("got flask %+v, want version %q", flask, "2.0.0")
	}
	if flask.UsageContext != "production" {
		t.Errorf("flask: got usageContext %q, want %q (from the \"default\" group)", flask.UsageContext, "production")
	}
	if flask.DependencyScope != "unknown" {
		t.Errorf("flask: got dependencyScope %q, want %q (Pipfile.lock doesn't retain direct-vs-transitive)", flask.DependencyScope, "unknown")
	}

	pytest, ok := byName["pytest"]
	if !ok || pytest.Version != "7.0.0" {
		t.Errorf("got pytest %+v, want version %q", pytest, "7.0.0")
	}
	if pytest.UsageContext != "development" {
		t.Errorf("pytest: got usageContext %q, want %q (from the \"develop\" group)", pytest.UsageContext, "development")
	}
}

func TestDiscoverPythonReadsDevRequirementsFileAsDevelopment(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.25.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write requirements.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements-dev.txt"), []byte("pytest==7.0.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write requirements-dev.txt: %v", err)
	}

	deps, err := discoverPython(dir)
	if err != nil {
		t.Fatalf("discoverPython returned an error: %v", err)
	}

	byName := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	if requests, ok := byName["requests"]; !ok || requests.UsageContext != "production" {
		t.Errorf("requests: got %+v, want usageContext %q", requests, "production")
	}
	if pytest, ok := byName["pytest"]; !ok || pytest.UsageContext != "development" {
		t.Errorf("pytest: got %+v, want usageContext %q (declared in requirements-dev.txt)", pytest, "development")
	}
}

func TestDiscoverPyprojectTOMLHandlesPEP621AndPoetry(t *testing.T) {
	raw := `
[project]
name = "example"
dependencies = [
  "requests>=2.25.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=7.0.0",
]

[tool.poetry.dependencies]
python = "^3.10"
flask = "^2.0"

[tool.poetry.group.docs.dependencies]
sphinx = "^5.0"
`

	deps := discoverPyprojectTOML(raw, "pyproject.toml")
	byName := make(map[string]Dependency, len(deps))
	for _, d := range deps {
		byName[d.Name] = d
	}

	if requests, ok := byName["requests"]; !ok || requests.Version != "2.25.0" {
		t.Errorf("got requests %+v, want version %q", requests, "2.25.0")
	} else if requests.UsageContext != "production" {
		t.Errorf("requests: got usageContext %q, want %q", requests.UsageContext, "production")
	}

	if flask, ok := byName["flask"]; !ok || flask.Version != "2.0" {
		t.Errorf("got flask %+v, want version %q", flask, "2.0")
	} else if flask.UsageContext != "production" {
		t.Errorf("flask: got usageContext %q, want %q", flask.UsageContext, "production")
	}

	if _, hasPython := byName["python"]; hasPython {
		t.Error("expected the 'python' entry itself to be excluded, it's not a dependency")
	}

	// "dev" (PEP 621 optional-dependencies group) and "docs" (Poetry
	// dependency group) both match devGroupRE, so both should be tagged
	// usageContext "development" even though neither came from a
	// requirements-dev.txt-style filename.
	if pytest, ok := byName["pytest"]; !ok || pytest.UsageContext != "development" {
		t.Errorf("pytest: got %+v, want usageContext %q (from the PEP 621 \"dev\" optional-dependencies group)", pytest, "development")
	}
	if sphinx, ok := byName["sphinx"]; !ok || sphinx.UsageContext != "development" {
		t.Errorf("sphinx: got %+v, want usageContext %q (from the Poetry \"docs\" dependency group)", sphinx, "development")
	}
}
