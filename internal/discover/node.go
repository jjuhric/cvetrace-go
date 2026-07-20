package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// lockfile mirrors just the parts of an npm package-lock.json (lockfile v2/v3)
// this project reads. encoding/json only fills in the fields declared here --
// anything else present in the actual JSON file is silently ignored, so this
// doesn't need to model the entire lockfile format, only the slice of it we
// care about.
//
// Go note: the text after each field, e.g. `json:"packages"`, is a "struct
// tag" -- metadata read by encoding/json to know which JSON key maps to which
// Go field. Go field names must start with a capital letter to be visible
// outside their own package (Packages is exported, packages would not be),
// and JSON keys are conventionally lowercase, so most JSON-facing structs
// need tags like this to bridge the two naming styles.
type lockfile struct {
	Packages map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// packageJSON mirrors just the parts of package.json this project reads --
// used only as a fallback when there's no lockfile (see discoverNode).
type packageJSON struct {
	Dependencies map[string]string `json:"dependencies"`
}

// discoverNode parses package.json + package-lock.json in dir into
// Dependency values. The lockfile is preferred when present, since it has
// fully resolved exact versions (including transitive dependencies);
// package.json alone only declares version *ranges* (e.g. "^1.2.3"), so it's
// used only as a fallback, and is a less accurate best-effort guess as a
// result.
func discoverNode(dir string) ([]Dependency, error) {
	lockPath := filepath.Join(dir, "package-lock.json")
	lockBytes, err := os.ReadFile(lockPath)

	// Go note: os.ReadFile returns an error you inspect, not a special
	// sentinel value the way some languages represent "file not found." A
	// missing lockfile isn't unusual here (plenty of projects don't have
	// one), so os.IsNotExist(err) is used to tell "no lockfile, fall back"
	// apart from a real problem (e.g. a permissions error), which is
	// propagated to the caller instead of silently ignored.
	if err != nil {
		if os.IsNotExist(err) {
			return discoverNodeFromPackageJSON(dir)
		}
		return nil, err
	}

	var lock lockfile
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		return nil, err
	}
	if lock.Packages == nil {
		// A package-lock.json exists but isn't the "packages" shape this
		// project understands (e.g. a very old lockfile v1) -- fall back
		// rather than silently returning nothing.
		return discoverNodeFromPackageJSON(dir)
	}

	var deps []Dependency
	for entryPath, pkg := range lock.Packages {
		if entryPath == "" || pkg.Version == "" {
			// The "" key is the lockfile's own root project entry, not a
			// dependency.
			continue
		}
		name := pkg.Name
		if name == "" {
			name = packageNameFromPath(entryPath)
		}
		deps = append(deps, Dependency{
			Ecosystem:    "npm",
			Name:         name,
			Version:      pkg.Version,
			ManifestPath: lockPath,
		})
	}

	return dedupe(deps), nil
}

// packageNameFromPath derives a package name from its lockfile entry path
// when the entry itself doesn't carry an explicit "name" field, e.g.
// "node_modules/minimist" -> "minimist", or for a nested/transitive package
// "node_modules/foo/node_modules/bar" -> "bar" (the name after the *last*
// "node_modules/" segment, since that's the package actually being
// described).
func packageNameFromPath(entryPath string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(entryPath, marker)
	if idx == -1 {
		return entryPath
	}
	return entryPath[idx+len(marker):]
}

// discoverNodeFromPackageJSON is used only when there's no package-lock.json.
// It reports the *declared* version ranges from package.json (e.g.
// "^1.2.3"), stripped down to a bare version number as a best-effort guess.
// This is less accurate than reading a lockfile, since the range doesn't say
// which exact version is actually installed.
func discoverNodeFromPackageJSON(dir string) ([]Dependency, error) {
	manifestPath := filepath.Join(dir, "package.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No package.json either -- this directory just isn't a Node
			// project. Returning (nil, nil) rather than an error, since
			// "nothing found here" isn't a failure.
			return nil, nil
		}
		return nil, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency
	for name, rangeSpec := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Ecosystem:    "npm",
			Name:         name,
			Version:      stripRangePrefix(rangeSpec),
			ManifestPath: manifestPath,
		})
	}

	return dedupe(deps), nil
}

// stripRangePrefix removes a leading semver range operator from a declared
// version, e.g. "^1.2.3" -> "1.2.3". Not a real semver-range parser --
// just enough to get a plausible bare version number for display.
func stripRangePrefix(rangeSpec string) string {
	return strings.TrimLeft(rangeSpec, "^~>=< ")
}

// dedupe removes duplicate (name, version) pairs, which the lockfile walk can
// otherwise produce (the same resolved package can appear at multiple nested
// paths in npm's dependency tree).
func dedupe(deps []Dependency) []Dependency {
	seen := make(map[string]struct{}, len(deps))
	out := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		key := dep.Name + "@" + dep.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, dep)
	}
	return out
}
