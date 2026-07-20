// Package discover finds every dependency declared or resolved in a project
// directory, without yet knowing whether any of them have known
// vulnerabilities -- that's the job of the internal/trace package. discover
// only answers "what packages, at what versions, does this project depend
// on, and which file did that come from."
package discover

// Dependency describes one package version found while walking a project.
//
// Go note for JS readers: this is a "struct" -- Go's equivalent of a plain JS
// object shape, except the shape is fixed and declared up front instead of
// inferred from whatever properties happen to get set at runtime. Every
// Dependency value always has exactly these fields, no more, no fewer.
type Dependency struct {
	// Ecosystem identifies which package registry this dependency belongs
	// to, using the same names OSV.dev's API uses ("npm", "PyPI", "Maven",
	// ...) so a Dependency can be handed straight to internal/trace's
	// OSV.dev query without any translation step.
	Ecosystem string

	// Name is the package's name as published to its registry, e.g.
	// "minimist".
	Name string

	// Version is the exact resolved version string, e.g. "0.0.8".
	Version string

	// ManifestPath is the file this dependency was discovered in, e.g.
	// "test/fixtures/node-fixture-project/package-lock.json" -- reported
	// back to the user so they know which file to edit to fix something.
	ManifestPath string

	// DependencyScope is "direct" (declared by the project's own manifest),
	// "transitive" (pulled in only because some direct dependency needs it),
	// or "unknown" when a discoverer genuinely can't tell the two apart --
	// e.g. Python's Pipfile.lock, whose default/develop split doesn't retain
	// which entries were originally declared versus pulled in transitively.
	DependencyScope string

	// UsageContext is "production", "development" (test-only, build tooling,
	// etc. -- never shipped), or "unknown".
	UsageContext string

	// DependencyPath is the chain of package names from a direct dependency
	// down to this one, e.g. []string{"webpack", "loader-utils",
	// "vulnerable-pkg"} -- nil for direct dependencies (there's no chain to
	// show) and for ecosystems that don't resolve transitively at all.
	DependencyPath []string
}
