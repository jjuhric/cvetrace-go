package discover

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// gradleInitScript is a throwaway Gradle init script that, for every project
// in the build, walks each resolvable configuration's dependency tree from
// its first-level (directly declared) dependencies down through
// ResolvedDependency.children, printing each node reached together with the
// chain of coordinates from the first-level dependency down to it -- that
// chain is what DependencyPath is built from in parseGradleOutput. A node is
// only visited once per configuration (pathFound), which bounds the walk to
// one path per node instead of every path through a diamond-shaped graph,
// and avoids the exponential blowup of printing every possible path. It also
// emits which coordinates are *directly* declared in a `dependencies {}`
// block, via config.dependencies -- that's how DependencyScope is decided.
// Running this forces the same configuration-phase evaluation (and
// dependency resolution) that `gradle dependencies` relies on, but in a
// flat, easy-to-parse line format instead of Gradle's indented tree output.
// "help" is used as the task to run because it exists in every Gradle
// project and doesn't otherwise build or test anything.
//
// Go note: this is Groovy code, not Go -- it's written to a temp file and
// handed to a real `gradle`/`gradlew` process to execute, the same way the
// Node version of this tool does. Go's job here is just process management
// (write the file, run the command, parse its stdout), not understanding
// Groovy itself.
const gradleInitScript = `
allprojects { proj ->
  proj.afterEvaluate {
    proj.configurations.each { config ->
      config.dependencies.each { dep ->
        if (dep.group != null) {
          println("CVETRACE_DIRECT|" + proj.projectDir.absolutePath + "|" + dep.group + ":" + dep.name)
        }
      }
      if (config.canBeResolved) {
        try {
          def pathFound = new HashSet()
          def visit
          visit = { resolvedDep, chain ->
            def coord = resolvedDep.moduleGroup + ":" + resolvedDep.moduleName + ":" + resolvedDep.moduleVersion
            def key = config.name + "|" + coord
            if (pathFound.contains(key)) {
              return
            }
            pathFound.add(key)
            def newChain = chain + [coord]
            println("CVETRACE_DEP|" + proj.projectDir.absolutePath + "|" + config.name + "|" + newChain.join(">"))
            resolvedDep.children.each { child -> visit(child, newChain) }
          }
          config.resolvedConfiguration.lenientConfiguration.firstLevelModuleDependencies.each { topLevel ->
            visit(topLevel, [])
          }
        } catch (ignored) {
        }
      }
    }
  }
}
`

// testConfigRE matches a Gradle configuration name containing "test"
// (testImplementation, testRuntimeClasspath, androidTestImplementation, ...)
// -- Gradle's standard convention for test-only dependencies. compileOnly is
// treated as production since it's still needed to compile and is
// ship-adjacent even though it isn't bundled, erring toward not hiding a
// real production-relevant CVE behind a wrong "development" tag.
var testConfigRE = regexp.MustCompile(`(?i)test`)

const gradleTimeout = 5 * time.Minute

// discoverGradle groups every directory found to contain a build.gradle/
// build.gradle.kts by its actual Gradle build root (the nearest ancestor,
// bounded by scanRoot, that looks like an invocable root: has a wrapper or a
// settings.gradle[.kts]) and invokes Gradle once per unique root -- a multi-
// module build must be evaluated from its root, and doing this once per
// root (not once per member directory) avoids redundant Gradle invocations
// for what is really one build.
func discoverGradle(gradleDirs []string, scanRoot string) []Dependency {
	rootToMembers := make(map[string][]string)
	for _, dir := range gradleDirs {
		root := findGradleRoot(dir, scanRoot)
		rootToMembers[root] = append(rootToMembers[root], dir)
	}

	var deps []Dependency
	for root, members := range rootToMembers {
		found, err := resolveGradleProject(root)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"cvetrace: couldn't invoke Gradle for %s (%v); falling back to best-effort static parsing of build.gradle.\n",
				root, err)
			for _, dir := range members {
				deps = append(deps, staticGradleFallback(dir)...)
			}
			continue
		}
		deps = append(deps, found...)
	}
	return deps
}

func findGradleRoot(startDir, scanRoot string) string {
	boundary, err := filepath.Abs(scanRoot)
	if err != nil {
		boundary = scanRoot
	}
	dir, err := filepath.Abs(startDir)
	if err != nil {
		dir = startDir
	}

	for {
		if hasAnyFile(dir, "gradlew", "gradlew.bat", "settings.gradle", "settings.gradle.kts") {
			return dir
		}
		if dir == boundary {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached the filesystem root without finding a marker or
			// hitting scanRoot exactly (can happen with certain relative
			// path inputs) -- stop rather than loop forever.
			break
		}
		dir = parent
	}
	return startDir
}

func hasAnyFile(dir string, names ...string) bool {
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// resolveGradleProject writes the init script to a temp file, invokes
// Gradle with it, and parses the result. context.WithTimeout is Go's
// standard mechanism for "give this operation at most N to finish, then
// give up" -- exec.CommandContext ties the spawned process's lifetime to
// that context, so if gradleTimeout elapses the process is killed
// automatically, the same safety net the Node version's manual
// setTimeout+kill achieves by hand.
func resolveGradleProject(rootDir string) ([]Dependency, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gradleTimeout)
	defer cancel()

	initScript, err := os.CreateTemp("", "cvetrace-init-*.gradle")
	if err != nil {
		return nil, err
	}
	defer os.Remove(initScript.Name())

	if _, err := initScript.WriteString(gradleInitScript); err != nil {
		initScript.Close()
		return nil, err
	}
	if err := initScript.Close(); err != nil {
		return nil, err
	}

	command, args := gradleCommand(rootDir)
	args = append(args, "help", "--init-script", initScript.Name(), "--quiet", "--console=plain")

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = rootDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.Output()
	if err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if len(stderrText) > 300 {
			stderrText = stderrText[:300]
		}
		// Go note: "%w" (as opposed to "%s" or "%v") wraps the original
		// error inside the new one, rather than just formatting its
		// message into a plain string -- callers can still recover the
		// original error with errors.Is/errors.As if they need to inspect
		// it (e.g. to check whether it was specifically a "command not
		// found" error), which a %s/%v formatting would have thrown away.
		return nil, fmt.Errorf("gradle exited with an error (%w): %s", err, stderrText)
	}

	return parseGradleOutput(string(stdout)), nil
}

// gradleCommand decides how to invoke Gradle for rootDir: the project's own
// wrapper if it has one (preferred, since it pins an exact Gradle version),
// falling back to a system-installed `gradle` on PATH otherwise.
func gradleCommand(dir string) (string, []string) {
	isWindows := runtime.GOOS == "windows"

	wrapperName := "gradlew"
	if isWindows {
		wrapperName = "gradlew.bat"
	}
	wrapperPath := filepath.Join(dir, wrapperName)

	if _, err := os.Stat(wrapperPath); err == nil {
		if isWindows {
			return "cmd.exe", []string{"/c", wrapperPath}
		}
		// Go note: invoking `sh <path>` rather than the wrapper script
		// directly sidesteps needing the file to have its executable bit
		// set -- a real, easy way for a wrapper to lose that bit (a zip
		// download, certain git configurations) that would otherwise make
		// an otherwise-correct wrapper fail to run.
		return "sh", []string{wrapperPath}
	}

	if isWindows {
		return "cmd.exe", []string{"/c", "gradle.bat"}
	}
	return "gradle", nil
}

// gradleResolvedDep accumulates everything parseGradleOutput learns about one
// resolved module coordinate before it can decide that dependency's final
// DependencyScope/UsageContext -- a coordinate can appear under more than one
// configuration (e.g. both "implementation" and "testImplementation"), so
// this is built up incrementally across every CVETRACE_DEP line for the same
// coordinate before being turned into a single Dependency at the end.
type gradleResolvedDep struct {
	projectDir     string
	name           string
	version        string
	configs        map[string]bool
	dependencyPath []string
}

// parseGradleOutput turns gradleInitScript's flat CVETRACE_DIRECT/
// CVETRACE_DEP lines back into Dependency values. Exported findings are
// order-stable (first CVETRACE_DEP line seen for a given coordinate decides
// its position in the result), which matters for tests asserting on output
// order.
func parseGradleOutput(output string) []Dependency {
	directDeclared := make(map[string]bool) // "projectDir|group:artifact"
	resolved := make(map[string]*gradleResolvedDep)
	var order []string // insertion order of `resolved`'s keys

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)

		switch {
		case strings.HasPrefix(line, "CVETRACE_DIRECT|"):
			parts := strings.SplitN(line, "|", 3)
			if len(parts) != 3 {
				continue
			}
			projectDir, name := parts[1], parts[2]
			directDeclared[projectDir+"|"+name] = true

		case strings.HasPrefix(line, "CVETRACE_DEP|"):
			parts := strings.SplitN(line, "|", 4)
			if len(parts) != 4 {
				continue
			}
			projectDir, configName, chainStr := parts[1], parts[2], parts[3]
			chain := strings.Split(chainStr, ">")

			coordParts := strings.SplitN(chain[len(chain)-1], ":", 3)
			if len(coordParts) != 3 {
				continue
			}
			group, artifact, version := coordParts[0], coordParts[1], coordParts[2]

			key := projectDir + "|" + group + ":" + artifact + ":" + version
			entry, exists := resolved[key]
			if !exists {
				entry = &gradleResolvedDep{
					projectDir:     projectDir,
					name:           group + ":" + artifact,
					version:        version,
					configs:        make(map[string]bool),
					dependencyPath: gradleDependencyPath(chain),
				}
				resolved[key] = entry
				order = append(order, key)
			}
			entry.configs[configName] = true
		}
	}

	var deps []Dependency
	for _, key := range order {
		entry := resolved[key]
		isDirect := directDeclared[entry.projectDir+"|"+entry.name]

		isProduction := false
		for config := range entry.configs {
			if !testConfigRE.MatchString(config) {
				isProduction = true
				break
			}
		}

		dependencyScope, usageContext := "transitive", "development"
		if isDirect {
			dependencyScope = "direct"
		}
		if isProduction {
			usageContext = "production"
		}

		var dependencyPath []string
		if !isDirect {
			// A first-level (chain length 1) dependency that Gradle didn't
			// report via config.dependencies (isDirect false) has no real
			// chain to show either -- gradleDependencyPath already returns
			// nil for that case.
			dependencyPath = entry.dependencyPath
		}

		deps = append(deps, Dependency{
			Ecosystem: "Maven",
			Name:      entry.name,
			Version:   entry.version,
			// Gradle always reports projectDir as absolute; relativize to
			// the current working directory so manifestPath reads
			// consistently with the other discoverers.
			ManifestPath:    filepath.Join(relativizeToCWD(entry.projectDir), "build.gradle"),
			DependencyScope: dependencyScope,
			UsageContext:    usageContext,
			DependencyPath:  dependencyPath,
		})
	}

	return deps
}

// gradleDependencyPath turns a chain of full coordinates (e.g.
// ["org.a:root:1.0", "org.b:mid:2.0", "org.c:leaf:3.0"]) into a
// DependencyPath of just "group:artifact" names, dropping each hop's
// version the same way this project's manifestPath/name fields elsewhere
// never carry a version inline. A single-element chain means the dependency
// itself is first-level, which doesn't need a path -- nil is returned for
// that case exactly like it is for every other ecosystem's direct
// dependencies.
func gradleDependencyPath(chain []string) []string {
	if len(chain) <= 1 {
		return nil
	}
	path := make([]string, len(chain))
	for i, coord := range chain {
		bits := strings.SplitN(coord, ":", 3)
		if len(bits) >= 2 {
			path[i] = bits[0] + ":" + bits[1]
		}
	}
	return path
}

func relativizeToCWD(absPath string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return absPath
	}
	rel, err := filepath.Rel(cwd, absPath)
	if err != nil {
		return absPath
	}
	return rel
}

// gradleDepRE matches literal "group:artifact:version" dependency
// declarations, e.g. implementation("org.example:lib:1.0.0"), capturing the
// directive keyword itself (group 1) so staticGradleFallback can guess
// usageContext from it the same way testConfigRE does for a real Gradle
// invocation's configuration names. Used only when Gradle itself can't be
// invoked at all (no wrapper, no system install, or the invocation failed/
// timed out) -- it misses anything using variables, ext {} properties, or
// version catalogs, since correctly handling those requires actually
// evaluating the build script the way resolveGradleProject does.
var gradleDepRE = regexp.MustCompile(
	`(implementation|api|compile|runtimeOnly|testImplementation)\s*\(?\s*["']([\w.-]+):([\w.-]+):([\w.\-+]+)["']`,
)

func staticGradleFallback(dir string) []Dependency {
	for _, filename := range []string{"build.gradle", "build.gradle.kts"} {
		path := filepath.Join(dir, filename)
		content, ok, err := readIfExists(path)
		if err != nil || !ok {
			continue
		}

		var deps []Dependency
		for _, m := range gradleDepRE.FindAllStringSubmatch(content, -1) {
			directive, group, artifact, version := m[1], m[2], m[3], m[4]
			usageContext := "production"
			if testConfigRE.MatchString(directive) {
				usageContext = "development"
			}
			deps = append(deps, Dependency{
				Ecosystem:       "Maven",
				Name:            group + ":" + artifact,
				Version:         version,
				ManifestPath:    path,
				DependencyScope: "direct",
				UsageContext:    usageContext,
			})
		}
		return deps
	}
	return nil
}
