package discover

import (
	"os"
	"path/filepath"
)

// skipDirs lists directory names the walk never descends into --
// dependency caches and VCS metadata that are never useful to scan and can
// be enormous (node_modules especially).
//
// Go note: this is a map used purely as a set (only the keys matter; the
// value type struct{} takes zero bytes). Go has no built-in set type, so
// "map[T]struct{}" is the idiomatic way to write "a set of T" -- you'll see
// this pattern throughout Go codebases.
var skipDirs = map[string]struct{}{
	"node_modules": {},
	".git":         {},
	"venv":         {},
	".venv":        {},
	"target":       {},
	"build":        {},
	"dist":         {},
	"__pycache__":  {},
}

// pythonManifestNames lists every filename that should trigger discoverPython
// for its directory. discoverPython itself decides which of these (if
// several are present) to actually prefer -- see its doc comment -- so the
// walk below only needs to know "was any of these seen," not which one.
var pythonManifestNames = map[string]struct{}{
	"Pipfile.lock":     {},
	"requirements.txt": {},
	"pyproject.toml":   {},
}

// Walk finds every dependency declared or resolved anywhere under root:
// Node (package.json/package-lock.json), Java/Maven (pom.xml), and Python
// (Pipfile.lock/requirements.txt/pyproject.toml). Gradle and full transitive
// resolution for Java/Python are planned future additions, not implemented
// yet -- see the project README. Directories listed in skipDirs are never
// descended into.
//
// Go note: functions that can fail return an error as their *last* return
// value, instead of throwing an exception the way JS's try/catch expects.
// Callers are expected to check "if err != nil" after every call that might
// fail -- there's no way to silently ignore an error the way a missing catch
// block in JS would swallow one; you have to explicitly decide to ignore it
// (by assigning it to "_") if that's really what you want.
func Walk(root string) ([]Dependency, error) {
	var deps []Dependency

	// Go note: a directory can have more than one Python manifest present
	// (e.g. both requirements.txt and pyproject.toml), but discoverPython
	// should only run once per directory, not once per matching filename.
	// pythonVisited tracks which directories have already been handled --
	// captured by the closure below the same way deps is, since a Go closure
	// (the anonymous func passed to WalkDir) can read and modify variables
	// declared in its enclosing function.
	pythonVisited := make(map[string]bool)

	// filepath.WalkDir visits every file and directory under root, calling
	// the function below once per entry. Returning filepath.SkipDir from
	// inside that function tells it "don't descend into this directory,"
	// which is how skipDirs is enforced.
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// A previous step of the walk itself failed (e.g. a permissions
			// error reading a directory) -- propagate it rather than
			// silently continuing as if nothing happened.
			return err
		}

		if d.IsDir() {
			if _, shouldSkip := skipDirs[d.Name()]; shouldSkip && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		dir := filepath.Dir(path)

		switch {
		case d.Name() == "package.json":
			found, err := discoverNode(dir)
			if err != nil {
				return err
			}
			deps = append(deps, found...)

		case d.Name() == "pom.xml":
			found, err := discoverJava(dir)
			if err != nil {
				return err
			}
			deps = append(deps, found...)

		default:
			if _, isPythonManifest := pythonManifestNames[d.Name()]; isPythonManifest && !pythonVisited[dir] {
				pythonVisited[dir] = true
				found, err := discoverPython(dir)
				if err != nil {
					return err
				}
				deps = append(deps, found...)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return deps, nil
}

// readIfExists reads path, returning ("", false, nil) if it doesn't exist --
// letting a caller write "if content, ok, err := readIfExists(p); err != nil
// { ... } else if ok { ... }" instead of repeating the os.IsNotExist check
// (see node.go, java.go) inline every time a manifest file is merely
// optional rather than required.
func readIfExists(path string) (string, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return string(raw), true, nil
}
