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

// lockPackage's Dependencies/DevDependencies/PeerDependencies/
// OptionalDependencies fields do double duty: on the root ("") entry,
// Dependencies/DevDependencies are the project's own direct dependency
// declarations; on every other entry, all four maps are that *package's own*
// requirements, used below to walk the dependency graph. npm's lockfile
// format reuses the same JSON shape for both, so one Go struct covers both
// uses too.
type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// packageJSON mirrors just the parts of package.json this project reads --
// used only as a fallback when there's no lockfile (see discoverNode).
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
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

	scope := buildNodeScopeMap(lock.Packages)

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
		dependencyScope, usageContext, dependencyPath := scope.classify(name)
		deps = append(deps, Dependency{
			Ecosystem:       "npm",
			Name:            name,
			Version:         pkg.Version,
			ManifestPath:    lockPath,
			DependencyScope: dependencyScope,
			UsageContext:    usageContext,
			DependencyPath:  dependencyPath,
		})
	}

	return dedupe(deps), nil
}

// nodeScopeMap answers, for every package name found in a lockfile, whether
// it's direct or transitive, whether it's reachable from production
// dependencies, dev dependencies, or neither, and -- for transitive packages
// -- the shortest chain from a direct dependency down to it. Built once per
// lockfile by buildNodeScopeMap and then queried once per package via
// classify.
type nodeScopeMap struct {
	prodDirect      map[string]bool
	devDirect       map[string]bool
	prodPredecessor map[string]*string
	devPredecessor  map[string]*string
}

// buildNodeScopeMap walks the lockfile's own per-package "dependencies" (plus
// peer/optional) declarations as a name-keyed graph, via breadth-first search
// seeded from the root entry's declared dependencies/devDependencies. This is
// name-based (not per-resolved-instance), so it can be imprecise if a project
// resolves multiple versions of the same package name -- rare in practice
// given npm's default deduplication, and the same simplification the Node
// version of this tool makes.
func buildNodeScopeMap(packages map[string]lockPackage) *nodeScopeMap {
	root := packages[""]
	prodDirect := setFromKeys(root.Dependencies)
	devDirect := setFromKeys(root.DevDependencies)

	requiresByName := make(map[string]map[string]bool)
	for entryPath, pkg := range packages {
		if entryPath == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = packageNameFromPath(entryPath)
		}
		if requiresByName[name] == nil {
			requiresByName[name] = make(map[string]bool)
		}
		for dep := range pkg.Dependencies {
			requiresByName[name][dep] = true
		}
		for dep := range pkg.PeerDependencies {
			requiresByName[name][dep] = true
		}
		for dep := range pkg.OptionalDependencies {
			requiresByName[name][dep] = true
		}
	}

	return &nodeScopeMap{
		prodDirect:      prodDirect,
		devDirect:       devDirect,
		prodPredecessor: bfsPredecessors(prodDirect, requiresByName),
		devPredecessor:  bfsPredecessors(devDirect, requiresByName),
	}
}

func setFromKeys(m map[string]string) map[string]bool {
	set := make(map[string]bool, len(m))
	for k := range m {
		set[k] = true
	}
	return set
}

// bfsPredecessors runs a breadth-first search over requiresByName starting
// from every name in seed simultaneously, returning each reached name's
// predecessor (the name that pulled it in) -- nil for a seed itself. BFS
// guarantees each predecessor recorded is on a *shortest* path back to some
// seed, regardless of the (non-deterministic) order Go iterates over map
// keys in, since it processes the queue strictly in the order names were
// first discovered.
//
// Go note: the map's value type is *string (a pointer), not string, so a
// seed's predecessor can be represented as nil -- a plain string has no
// "there is no predecessor" value distinct from the empty string "", which a
// real package name could never collide with in practice, but a pointer
// makes "no predecessor" and "predecessor happens to be ”" impossible to
// confuse by construction.
func bfsPredecessors(seed map[string]bool, requiresByName map[string]map[string]bool) map[string]*string {
	predecessorOf := make(map[string]*string, len(seed))
	queue := make([]string, 0, len(seed))
	for name := range seed {
		predecessorOf[name] = nil
		queue = append(queue, name)
	}

	for head := 0; head < len(queue); head++ {
		name := queue[head]
		for dep := range requiresByName[name] {
			if _, alreadyReached := predecessorOf[dep]; !alreadyReached {
				n := name // local copy: &name would alias the loop variable
				predecessorOf[dep] = &n
				queue = append(queue, dep)
			}
		}
	}
	return predecessorOf
}

// reconstructNodePath walks predecessorOf backwards from name to a seed,
// returning the chain in root-to-leaf order (e.g. ["webpack",
// "loader-utils", "vulnerable-pkg"]), or nil if name was never reached at
// all.
func reconstructNodePath(name string, predecessorOf map[string]*string) []string {
	if _, reached := predecessorOf[name]; !reached {
		return nil
	}
	var chain []string
	for current := name; ; {
		chain = append([]string{current}, chain...)
		pred := predecessorOf[current]
		if pred == nil {
			break
		}
		current = *pred
	}
	return chain
}

// classify reports name's dependencyScope, usageContext, and (for transitive
// packages only) dependencyPath, matching the Node version's buildScopeMap
// return shape.
func (s *nodeScopeMap) classify(name string) (dependencyScope, usageContext string, dependencyPath []string) {
	if s.prodDirect[name] || s.devDirect[name] {
		dependencyScope = "direct"
	} else {
		dependencyScope = "transitive"
	}

	var predecessors map[string]*string
	switch {
	case isReachable(name, s.prodPredecessor):
		usageContext = "production"
		predecessors = s.prodPredecessor
	case isReachable(name, s.devPredecessor):
		usageContext = "development"
		predecessors = s.devPredecessor
	default:
		usageContext = "unknown"
	}

	if dependencyScope == "transitive" && predecessors != nil {
		dependencyPath = reconstructNodePath(name, predecessors)
	}
	return
}

func isReachable(name string, predecessorOf map[string]*string) bool {
	_, ok := predecessorOf[name]
	return ok
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
			Ecosystem:       "npm",
			Name:            name,
			Version:         stripRangePrefix(rangeSpec),
			ManifestPath:    manifestPath,
			DependencyScope: "direct",
			UsageContext:    "production",
		})
	}
	for name, rangeSpec := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Ecosystem:       "npm",
			Name:            name,
			Version:         stripRangePrefix(rangeSpec),
			ManifestPath:    manifestPath,
			DependencyScope: "direct",
			UsageContext:    "development",
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
