package discover

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// pipfileLock mirrors just the parts of a Pipfile.lock this project reads.
// Both the "default" (production) and "develop" (dev-only) groups are read
// -- this slice doesn't yet distinguish between them the way the Node
// version's usageContext field does (that's a later, not-yet-ported
// addition), it just reports every pinned package from either group.
type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}

// requirementsLineRE matches a pinned/ranged requirement line, e.g.
// "PyYAML==5.3" or "requests>=2.25.0". Capture groups: (1) package name,
// (2) the comparison operator, (3) the version itself.
//
// Go note: Go's regexp package implements RE2 syntax, a different engine
// than JS's regex -- RE2 deliberately has no backreferences or lookahead/
// lookbehind, in exchange for guaranteeing matching always runs in time
// linear to the input length (no catastrophic backtracking possible). This
// pattern doesn't need either unsupported feature, so it's unaffected.
var requirementsLineRE = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;,]+)`)

var pypiNameSeparatorRE = regexp.MustCompile(`[-_.]+`)

// discoverPython parses Python dependency manifests in dir, preferring the
// most resolved source available: Pipfile.lock (fully resolved) >
// requirements.txt (usually pinned) > pyproject.toml (declared ranges,
// best-effort -- see discoverPyprojectTOML). Only one source is read per
// directory, in that priority order, matching the Node version's own choice.
func discoverPython(dir string) ([]Dependency, error) {
	lockPath := filepath.Join(dir, "Pipfile.lock")
	if content, ok, err := readIfExists(lockPath); err != nil {
		return nil, err
	} else if ok {
		return discoverPipfileLock(content, lockPath)
	}

	reqPath := filepath.Join(dir, "requirements.txt")
	if content, ok, err := readIfExists(reqPath); err != nil {
		return nil, err
	} else if ok {
		return dedupe(discoverRequirementsTXT(content, reqPath)), nil
	}

	tomlPath := filepath.Join(dir, "pyproject.toml")
	if content, ok, err := readIfExists(tomlPath); err != nil {
		return nil, err
	} else if ok {
		return dedupe(discoverPyprojectTOML(content, tomlPath)), nil
	}

	return nil, nil
}

func discoverPipfileLock(raw, manifestPath string) ([]Dependency, error) {
	var lock pipfileLock
	if err := json.Unmarshal([]byte(raw), &lock); err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, group := range []map[string]pipfilePackage{lock.Default, lock.Develop} {
		for name, pkg := range group {
			version := strings.TrimPrefix(pkg.Version, "==")
			if version == "" {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem:    "PyPI",
				Name:         normalizePyPIName(name),
				Version:      version,
				ManifestPath: manifestPath,
			})
		}
	}
	return dedupe(deps), nil
}

func discoverRequirementsTXT(raw, manifestPath string) []Dependency {
	var deps []Dependency
	for _, rawLine := range strings.Split(raw, "\n") {
		line := rawLine
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}

		match := requirementsLineRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		deps = append(deps, Dependency{
			Ecosystem:    "PyPI",
			Name:         normalizePyPIName(match[1]),
			Version:      match[3],
			ManifestPath: manifestPath,
		})
	}
	return deps
}

// pep621ArrayRE finds a top-level `dependencies = [...]` array (PEP 621).
// poetryTableRE finds a `[tool.poetry.dependencies]` table and grabs
// everything up to the next table header (or end of file).
//
// Go note: "(?s)" makes "." match newlines too (Go calls this flag "s" for
// single-line mode, meaning treat the whole input as one line for "." to
// span, which is a slightly confusing name for what it does -- it's the same
// idea as JS regex's "s"/dotAll flag). Without it, "." wouldn't match across
// the multiple lines a dependencies array or a TOML table normally spans.
var pep621ArrayRE = regexp.MustCompile(`(?s)\bdependencies\s*=\s*\[(.*?)\]`)
var quotedStringRE = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
var poetryTableRE = regexp.MustCompile(`(?s)\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\z)`)
var poetryLineRE = regexp.MustCompile(`(?m)^([A-Za-z0-9._-]+)\s*=\s*"([^"]+)"`)

// discoverPyprojectTOML is a best-effort scan for two common shapes --
// PEP 621's `dependencies = [...]` array and Poetry's
// `[tool.poetry.dependencies]` table -- not a real TOML parser. Go's
// standard library has no TOML support at all (unlike JSON or XML), and the
// Node version of this tool's own pyproject.toml handling was already
// best-effort rather than a full parser, so this stays consistent with that
// rather than pulling in this project's first third-party dependency for
// only-partial TOML coverage.
func discoverPyprojectTOML(raw, manifestPath string) []Dependency {
	var deps []Dependency

	if m := pep621ArrayRE.FindStringSubmatch(raw); m != nil {
		for _, quoted := range quotedStringRE.FindAllStringSubmatch(m[1], -1) {
			spec := quoted[1]
			if spec == "" {
				spec = quoted[2]
			}
			match := requirementsLineRE.FindStringSubmatch(spec)
			if match == nil {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem:    "PyPI",
				Name:         normalizePyPIName(match[1]),
				Version:      match[3],
				ManifestPath: manifestPath,
			})
		}
	}

	if m := poetryTableRE.FindStringSubmatch(raw); m != nil {
		for _, line := range poetryLineRE.FindAllStringSubmatch(m[1], -1) {
			name := line[1]
			if strings.EqualFold(name, "python") {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem:    "PyPI",
				Name:         normalizePyPIName(name),
				Version:      stripRangePrefix(line[2]),
				ManifestPath: manifestPath,
			})
		}
	}

	return deps
}

// normalizePyPIName applies PEP 503 normalization, since OSV.dev/PyPI treat
// e.g. "PyYAML" and "pyyaml" as the same package.
func normalizePyPIName(name string) string {
	return pypiNameSeparatorRE.ReplaceAllString(strings.ToLower(name), "-")
}
