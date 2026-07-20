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

// Walk finds every dependency declared or resolved anywhere under root. Right
// now that means looking for package.json/package-lock.json (Node); more
// ecosystems (Java, Python) are a planned future addition, not implemented
// yet. Directories listed in skipDirs are never descended into.
//
// Go note: functions that can fail return an error as their *last* return
// value, instead of throwing an exception the way JS's try/catch expects.
// Callers are expected to check "if err != nil" after every call that might
// fail -- there's no way to silently ignore an error the way a missing catch
// block in JS would swallow one; you have to explicitly decide to ignore it
// (by assigning it to "_") if that's really what you want.
func Walk(root string) ([]Dependency, error) {
	var deps []Dependency

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

		if d.Name() == "package.json" {
			dir := filepath.Dir(path)
			found, err := discoverNode(dir)
			if err != nil {
				return err
			}
			deps = append(deps, found...)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return deps, nil
}
