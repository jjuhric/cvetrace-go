package trace

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// usageSkipDirs mirrors internal/discover's own skipDirs -- duplicated here
// (rather than exported and shared) because this is a different, unrelated
// walk: discover.Walk looks for manifest files, this one looks for *source*
// files to scan for import/require references. The Node version of this tool
// makes the same choice (src/trace/usage.js declares its own SKIP_DIRS
// independently of src/discover/index.js's).
var usageSkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"venv":         true,
	".venv":        true,
	"target":       true,
	"build":        true,
	"dist":         true,
	"__pycache__":  true,
}

// maxSourceFileSize skips anything oddly large (generated/binary-ish) rather
// than reading a multi-hundred-megabyte file into memory just to regex-scan
// it for an import statement.
const maxSourceFileSize = 2 * 1024 * 1024

// extensionsByEcosystem lists which source file extensions are worth
// scanning for a reference to a package from each ecosystem.
var extensionsByEcosystem = map[string][]string{
	"npm":   {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
	"Maven": {".java", ".kt", ".kts", ".groovy", ".scala"},
	"PyPI":  {".py"},
}

// DetectCodeReferences walks targetPath once, collecting source file
// contents bucketed by ecosystem-relevant extension, then tags every
// Vulnerability's CodeReference field ("found"/"not-found"/"unknown"):
// whether that package is actually imported/required anywhere in the
// project's own source -- not just declared in a manifest.
//
// This is a usage signal, not reachability analysis: "found" means the
// package is referenced somewhere, not that the specific vulnerable function
// is called; "not-found" means no reference was detected with this
// heuristic, not proof the code is unused (dynamic requires, reflection,
// string-built imports, etc. are all missed). Java/Kotlin detection is
// itself a heuristic -- it checks for "import <groupId>", which assumes the
// library's Java package matches its Maven/Gradle groupId (usually true, not
// guaranteed). Python detection checks for the PyPI distribution name
// directly, which misses packages whose import name differs from their
// published name (e.g. PyYAML is `import yaml`) -- a known, documented gap,
// not silently "handled".
func DetectCodeReferences(targetPath string, vulns []Vulnerability) ([]Vulnerability, error) {
	ecosystems := make(map[string]bool)
	relevantExtensions := make(map[string]bool)
	for _, v := range vulns {
		ecosystems[v.Ecosystem] = true
		for _, ext := range extensionsByEcosystem[v.Ecosystem] {
			relevantExtensions[ext] = true
		}
	}

	filesByEcosystem := make(map[string][]string, len(ecosystems))
	if len(relevantExtensions) > 0 {
		collected, err := walkSource(targetPath, relevantExtensions)
		if err != nil {
			return nil, err
		}
		for eco := range ecosystems {
			exts := extensionsByEcosystem[eco]
			var contents []string
			for _, file := range collected {
				if containsString(exts, file.ext) {
					contents = append(contents, file.content)
				}
			}
			filesByEcosystem[eco] = contents
		}
	}

	out := make([]Vulnerability, len(vulns))
	for i, v := range vulns {
		v.CodeReference = checkReference(v, filesByEcosystem[v.Ecosystem])
		out[i] = v
	}
	return out, nil
}

type sourceFile struct {
	ext     string
	content string
}

// walkSource collects the content of every file under root whose extension
// is in relevantExtensions, skipping usageSkipDirs. Unlike discover.Walk,
// this is deliberately best-effort: codeReference is a secondary, heuristic
// signal, not something a single unreadable file or permission-denied
// subdirectory should be able to abort the whole scan over -- so a per-entry
// error here is skipped rather than propagated, matching the Node version's
// own try/catch-and-continue in walkSource.
func walkSource(root string, relevantExtensions map[string]bool) ([]sourceFile, error) {
	var files []sourceFile

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if usageSkipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(d.Name())
		if !relevantExtensions[ext] {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() > maxSourceFileSize {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files = append(files, sourceFile{ext: ext, content: string(content)})
		return nil
	})
	// filepath.WalkDir only returns a non-nil error here if root itself
	// couldn't be walked at all (e.g. it doesn't exist) -- every per-entry
	// error above is already swallowed by returning nil from the callback.
	if err != nil {
		return nil, err
	}
	return files, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func checkReference(v Vulnerability, files []string) string {
	if len(files) == 0 {
		return "unknown"
	}
	pattern := referencePattern(v)
	if pattern == nil {
		return "unknown"
	}
	for _, content := range files {
		if pattern.MatchString(content) {
			return "found"
		}
	}
	return "not-found"
}

// referencePattern builds the regex that decides "found" for v's ecosystem.
// Each ecosystem's language has its own import/require syntax, so each gets
// its own pattern -- ported directly from the Node version's referencePattern
// in src/trace/usage.js.
func referencePattern(v Vulnerability) *regexp.Regexp {
	switch v.Ecosystem {
	case "npm":
		name := regexp.QuoteMeta(v.Name)
		return regexp.MustCompile(
			`require\(\s*['"]` + name + `(?:/[^'"]*)?['"]|` +
				`from\s+['"]` + name + `(?:/[^'"]*)?['"]|` +
				`import\(\s*['"]` + name + `(?:/[^'"]*)?['"]|` +
				`import\s+['"]` + name + `(?:/[^'"]*)?['"]`,
		)

	case "Maven":
		groupID := strings.SplitN(v.Name, ":", 2)[0]
		if groupID == "" {
			return nil
		}
		return regexp.MustCompile(`import\s+` + regexp.QuoteMeta(groupID))

	case "PyPI":
		name := regexp.QuoteMeta(v.Name)
		return regexp.MustCompile(`(?m)^\s*(?:import\s+` + name + `\b|from\s+` + name + `(?:\.[\w.]+)?\s+import)`)

	default:
		return nil
	}
}
