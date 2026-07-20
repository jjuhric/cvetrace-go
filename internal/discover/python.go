package discover

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// devGroupRE matches a dependency-group name that, by common convention,
// holds development-only packages (pyproject.toml optional-dependencies
// groups, Poetry dependency groups) -- e.g. "dev", "test", "docs", "lint",
// "typing". A heuristic, not a guarantee: a project is free to name its
// groups anything.
var devGroupRE = regexp.MustCompile(`(?i)^(dev|test|docs?|lint|typing)`)

// devRequirementsFiles lists requirements.txt sibling filenames that, by
// common convention, hold development-only packages -- read in addition to
// requirements.txt itself (see discoverPython) and tagged usageContext
// "development".
var devRequirementsFiles = []string{"requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt"}

// pipfileLock mirrors just the parts of a Pipfile.lock this project reads.
// The "default" (production) and "develop" (dev-only) groups map directly to
// usageContext; dependencyScope is always "unknown" for entries from this
// source (see discoverPipfileLock's doc comment for why).
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
// When requirements.txt is the source, any of devRequirementsFiles present
// alongside it is also read and tagged usageContext "development".
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
		deps := discoverRequirementsTXT(content, reqPath, "production")
		for _, devFile := range devRequirementsFiles {
			devPath := filepath.Join(dir, devFile)
			if devContent, ok, err := readIfExists(devPath); err != nil {
				return nil, err
			} else if ok {
				deps = append(deps, discoverRequirementsTXT(devContent, devPath, "development")...)
			}
		}
		return dedupe(deps), nil
	}

	tomlPath := filepath.Join(dir, "pyproject.toml")
	if content, ok, err := readIfExists(tomlPath); err != nil {
		return nil, err
	} else if ok {
		return dedupe(discoverPyprojectTOML(content, tomlPath)), nil
	}

	return nil, nil
}

// discoverPipfileLock tags every entry dependencyScope "unknown" rather than
// "direct" or "transitive": Pipfile.lock's default/develop split is reliable
// for usageContext, but the lock format itself doesn't retain which entries
// were originally declared in the Pipfile versus pulled in transitively --
// unlike npm's lockfile, which keeps each package's own "dependencies" list
// and so lets discoverNode's buildNodeScopeMap reconstruct that distinction.
func discoverPipfileLock(raw, manifestPath string) ([]Dependency, error) {
	var lock pipfileLock
	if err := json.Unmarshal([]byte(raw), &lock); err != nil {
		return nil, err
	}

	groups := []struct {
		packages     map[string]pipfilePackage
		usageContext string
	}{
		{lock.Default, "production"},
		{lock.Develop, "development"},
	}

	var deps []Dependency
	for _, group := range groups {
		for name, pkg := range group.packages {
			version := strings.TrimPrefix(pkg.Version, "==")
			if version == "" {
				continue
			}
			deps = append(deps, Dependency{
				Ecosystem:       "PyPI",
				Name:            normalizePyPIName(name),
				Version:         version,
				ManifestPath:    manifestPath,
				DependencyScope: "unknown",
				UsageContext:    group.usageContext,
			})
		}
	}
	return dedupe(deps), nil
}

func discoverRequirementsTXT(raw, manifestPath, usageContext string) []Dependency {
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
			Ecosystem:       "PyPI",
			Name:            normalizePyPIName(match[1]),
			Version:         match[3],
			ManifestPath:    manifestPath,
			DependencyScope: "direct",
			UsageContext:    usageContext,
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

// pep621OptionalRE finds the single [project.optional-dependencies] table;
// pep621GroupRE then finds each `group = [...]` array within it, e.g. `dev =
// [...]`, `test = [...]` -- the standard PEP 621 shape for optional/extra
// dependency groups.
var pep621OptionalRE = regexp.MustCompile(`(?s)\[project\.optional-dependencies\](.*?)(?:\n\[|\z)`)
var pep621GroupRE = regexp.MustCompile(`(?s)([\w-]+)\s*=\s*\[(.*?)\]`)

// poetryLegacyDevRE finds Poetry's older `[tool.poetry.dev-dependencies]`
// table (superseded by dependency groups, but still seen in the wild).
// poetryGroupRE finds each `[tool.poetry.group.<name>.dependencies]` table --
// Poetry's current mechanism for named dependency groups (dev, test, docs).
var poetryLegacyDevRE = regexp.MustCompile(`(?s)\[tool\.poetry\.dev-dependencies\](.*?)(?:\n\[|\z)`)
var poetryGroupRE = regexp.MustCompile(`(?s)\[tool\.poetry\.group\.([\w-]+)\.dependencies\](.*?)(?:\n\[|\z)`)

// discoverPyprojectTOML is a best-effort scan for PEP 621's `dependencies =
// [...]` array (plus its `[project.optional-dependencies]` groups) and
// Poetry's `[tool.poetry.dependencies]` table (plus its legacy
// dev-dependencies table and current named dependency groups) -- not a real
// TOML parser. Go's standard library has no TOML support at all (unlike JSON
// or XML), and the Node version of this tool's own pyproject.toml handling
// was already best-effort rather than a full parser, so this stays
// consistent with that rather than pulling in this project's first
// third-party dependency for only-partial TOML coverage.
//
// Every group's usageContext is decided by devGroupRE matching the group
// name (e.g. "dev", "test", "docs") -- a naming convention, not something
// TOML itself encodes, so an unconventionally-named dev group will be
// (harmlessly) tagged "production" instead.
func discoverPyprojectTOML(raw, manifestPath string) []Dependency {
	var deps []Dependency

	if m := pep621ArrayRE.FindStringSubmatch(raw); m != nil {
		deps = append(deps, parseTomlStringArray(m[1], manifestPath, "production")...)
	}

	if m := pep621OptionalRE.FindStringSubmatch(raw); m != nil {
		for _, group := range pep621GroupRE.FindAllStringSubmatch(m[1], -1) {
			groupName, arrayBody := group[1], group[2]
			deps = append(deps, parseTomlStringArray(arrayBody, manifestPath, usageContextForGroup(groupName))...)
		}
	}

	if m := poetryTableRE.FindStringSubmatch(raw); m != nil {
		deps = append(deps, parsePoetryTable(m[1], manifestPath, "production")...)
	}
	if m := poetryLegacyDevRE.FindStringSubmatch(raw); m != nil {
		deps = append(deps, parsePoetryTable(m[1], manifestPath, "development")...)
	}
	for _, group := range poetryGroupRE.FindAllStringSubmatch(raw, -1) {
		groupName, body := group[1], group[2]
		deps = append(deps, parsePoetryTable(body, manifestPath, usageContextForGroup(groupName))...)
	}

	return deps
}

func usageContextForGroup(groupName string) string {
	if devGroupRE.MatchString(groupName) {
		return "development"
	}
	return "production"
}

func parseTomlStringArray(source, manifestPath, usageContext string) []Dependency {
	var deps []Dependency
	for _, quoted := range quotedStringRE.FindAllStringSubmatch(source, -1) {
		spec := quoted[1]
		if spec == "" {
			spec = quoted[2]
		}
		match := requirementsLineRE.FindStringSubmatch(spec)
		if match == nil {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem:       "PyPI",
			Name:            normalizePyPIName(match[1]),
			Version:         match[3],
			ManifestPath:    manifestPath,
			DependencyScope: "direct",
			UsageContext:    usageContext,
		})
	}
	return deps
}

func parsePoetryTable(source, manifestPath, usageContext string) []Dependency {
	var deps []Dependency
	for _, line := range poetryLineRE.FindAllStringSubmatch(source, -1) {
		name := line[1]
		if strings.EqualFold(name, "python") {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem:       "PyPI",
			Name:            normalizePyPIName(name),
			Version:         stripRangePrefix(line[2]),
			ManifestPath:    manifestPath,
			DependencyScope: "direct",
			UsageContext:    usageContext,
		})
	}
	return deps
}

// normalizePyPIName applies PEP 503 normalization, since OSV.dev/PyPI treat
// e.g. "PyYAML" and "pyyaml" as the same package.
func normalizePyPIName(name string) string {
	return pypiNameSeparatorRE.ReplaceAllString(strings.ToLower(name), "-")
}
