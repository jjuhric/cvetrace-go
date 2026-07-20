package discover

import (
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

	names := make(map[string]string, len(deps))
	for _, d := range deps {
		names[d.Name] = d.Version
	}

	if names["flask"] != "2.0.0" {
		t.Errorf("got flask version %q, want %q", names["flask"], "2.0.0")
	}
	if names["pytest"] != "7.0.0" {
		t.Errorf("got pytest version %q, want %q", names["pytest"], "7.0.0")
	}
}

func TestDiscoverPyprojectTOMLHandlesPEP621AndPoetry(t *testing.T) {
	raw := `
[project]
name = "example"
dependencies = [
  "requests>=2.25.0",
]

[tool.poetry.dependencies]
python = "^3.10"
flask = "^2.0"
`

	deps := discoverPyprojectTOML(raw, "pyproject.toml")
	names := make(map[string]string, len(deps))
	for _, d := range deps {
		names[d.Name] = d.Version
	}

	if names["requests"] != "2.25.0" {
		t.Errorf("got requests version %q, want %q", names["requests"], "2.25.0")
	}
	if names["flask"] != "2.0" {
		t.Errorf("got flask version %q, want %q", names["flask"], "2.0")
	}
	if _, hasPython := names["python"]; hasPython {
		t.Error("expected the 'python' entry itself to be excluded, it's not a dependency")
	}
}
