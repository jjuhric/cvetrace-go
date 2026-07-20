package trace

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// OverrideSnippet is the exact fix for forcing a transitive dependency to a
// patched version without waiting for its direct parent to publish an
// update -- often the fastest real fix for a transitive CVE.
type OverrideSnippet struct {
	File         string `json:"file"`
	Instructions string `json:"instructions"`
	Snippet      string `json:"snippet"`
}

var gradleManifestRE = regexp.MustCompile(`build\.gradle(\.kts)?$`)

// ApplyOverrideSnippets sets OverrideSnippet on every Vulnerability where one
// can be generated, returning a new slice (the input isn't mutated).
func ApplyOverrideSnippets(vulns []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, len(vulns))
	for i, v := range vulns {
		v.OverrideSnippet = generateOverrideSnippet(v)
		out[i] = v
	}
	return out
}

// generateOverrideSnippet is only produced when the finding is confidently
// transitive (DependencyScope == "transitive") and a target version is
// known; the mechanism differs by ecosystem/build tool, and isn't attempted
// at all for ecosystems where this project doesn't currently resolve
// transitive dependencies (Maven's pom.xml, Python), since a "transitive"
// tag never occurs there in the first place -- see internal/discover's
// per-ecosystem doc comments.
func generateOverrideSnippet(v Vulnerability) *OverrideSnippet {
	if v.DependencyScope != "transitive" {
		return nil
	}

	targetVersion := v.RecommendedVersion
	if targetVersion == "" {
		targetVersion = v.FixedVersion
	}
	if targetVersion == "" {
		return nil
	}

	switch {
	case v.Ecosystem == "npm":
		return npmOverride(v.Name, targetVersion)
	case v.Ecosystem == "Maven" && strings.HasSuffix(v.ManifestPath, "pom.xml"):
		// Unreachable today (discoverJava never tags a finding
		// "transitive" -- pom.xml isn't resolved transitively yet), but
		// kept ready for when Maven support grows that far, the same way
		// the Node version does.
		return mavenOverride(v.Name, targetVersion)
	case v.Ecosystem == "Maven" && gradleManifestRE.MatchString(v.ManifestPath):
		return gradleOverride(v.Name, targetVersion, v.ManifestPath)
	default:
		return nil
	}
}

func npmOverride(name, version string) *OverrideSnippet {
	// Go note: the inner {name: version} composite literal doesn't repeat
	// "map[string]string" -- Go infers an element's type from its container
	// when it's unambiguous, the same way JS lets you nest object literals
	// without re-declaring a type for each level.
	payload := map[string]map[string]string{"overrides": {name: version}}
	snippet, _ := json.MarshalIndent(payload, "", "  ")

	return &OverrideSnippet{
		File: "package.json",
		Instructions: fmt.Sprintf(
			"Force %s@%s regardless of what pulls it in, without waiting for the parent package to publish an update (npm 8.3+; yarn uses a \"resolutions\" field of the same shape instead).",
			name, version,
		),
		Snippet: string(snippet),
	}
}

func mavenOverride(coordinate, version string) *OverrideSnippet {
	groupID, artifactID, _ := strings.Cut(coordinate, ":")

	snippet := strings.Join([]string{
		"<dependencyManagement>",
		"  <dependencies>",
		"    <dependency>",
		"      <groupId>" + groupID + "</groupId>",
		"      <artifactId>" + artifactID + "</artifactId>",
		"      <version>" + version + "</version>",
		"    </dependency>",
		"  </dependencies>",
		"</dependencyManagement>",
	}, "\n")

	return &OverrideSnippet{
		File: "pom.xml",
		Instructions: fmt.Sprintf(
			"Force %s:%s via <dependencyManagement>, without waiting for the parent artifact to publish an update.",
			coordinate, version,
		),
		Snippet: snippet,
	}
}

func gradleOverride(coordinate, version, manifestPath string) *OverrideSnippet {
	snippet := strings.Join([]string{
		"configurations.all {",
		fmt.Sprintf("    resolutionStrategy.force '%s:%s'", coordinate, version),
		"}",
	}, "\n")

	return &OverrideSnippet{
		File: filepath.Base(manifestPath),
		Instructions: fmt.Sprintf(
			"Force %s:%s across all configurations, without waiting for the parent dependency to publish an update.",
			coordinate, version,
		),
		Snippet: snippet,
	}
}
