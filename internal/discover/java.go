package discover

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// mavenProject mirrors just the parts of a Maven pom.xml this project reads.
//
// Go note: encoding/xml is part of the standard library -- unlike the Node
// version of this tool (which had to fall back to regular expressions to
// scrape pom.xml, since JavaScript has no built-in XML parser), Go can
// decode the file directly into these structs. xml.Unmarshal matches struct
// tags to XML element names *by local name only* when no namespace is given
// in the tag, so this still works correctly even though this fixture's
// <project> element declares a default XML namespace
// (xmlns="http://maven.apache.org/POM/4.0.0") that technically puts every
// element in that namespace.
type mavenProject struct {
	Properties struct {
		// Go note: `xml:",any"` is a catch-all -- it captures every child
		// element that isn't matched by another field, regardless of its
		// tag name. That's needed here because <properties>'s children have
		// *arbitrary*, project-defined names (e.g. <log4j.version>2.14.1
		// </log4j.version> -- the tag name itself is the property name),
		// which can't be declared as fixed struct fields the way
		// <dependency>'s children (always named groupId/artifactId/version)
		// can be below.
		Entries []mavenProperty `xml:",any"`
	} `xml:"properties"`

	Dependencies struct {
		Dependency []mavenDependency `xml:"dependency"`
	} `xml:"dependencies"`
}

type mavenProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// discoverJava parses pom.xml in dir, resolving simple ${property} version
// references against the same pom's <properties> block. Only directly
// declared dependencies are reported -- there's no transitive resolution
// here (that would mean actually invoking Maven, which this project doesn't
// do yet), so every Dependency this returns has an exact literal version,
// never a property reference left unresolved.
func discoverJava(dir string) ([]Dependency, error) {
	manifestPath := filepath.Join(dir, "pom.xml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var project mavenProject
	if err := xml.Unmarshal(raw, &project); err != nil {
		return nil, err
	}

	properties := make(map[string]string, len(project.Properties.Entries))
	for _, prop := range project.Properties.Entries {
		properties[prop.XMLName.Local] = strings.TrimSpace(prop.Value)
	}

	var deps []Dependency
	for _, mavenDep := range project.Dependencies.Dependency {
		if mavenDep.GroupID == "" || mavenDep.ArtifactID == "" || mavenDep.Version == "" {
			continue
		}

		version := resolveMavenProperty(mavenDep.Version, properties)
		if strings.Contains(version, "$") {
			// Still an unresolved ${...} reference (e.g. to a property this
			// pom.xml doesn't declare, or one only known to a parent POM
			// this project doesn't read) -- skip it rather than report a
			// bogus literal "${...}" as if it were a real version.
			continue
		}

		deps = append(deps, Dependency{
			Ecosystem:    "Maven",
			Name:         mavenDep.GroupID + ":" + mavenDep.ArtifactID,
			Version:      version,
			ManifestPath: manifestPath,
		})
	}

	return deps, nil
}

func resolveMavenProperty(version string, properties map[string]string) string {
	version = strings.TrimSpace(version)
	if !strings.HasPrefix(version, "${") || !strings.HasSuffix(version, "}") {
		return version
	}
	key := version[2 : len(version)-1]
	if resolved, ok := properties[key]; ok {
		return resolved
	}
	return version
}
