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
// in the build, walks each resolvable configuration and prints its fully
// resolved module coordinates. Running this forces the same configuration-
// phase evaluation (and dependency resolution) that `gradle dependencies`
// relies on, but in a flat, easy-to-parse line format instead of Gradle's
// indented tree output. "help" is used as the task to run because it exists
// in every Gradle project and doesn't otherwise build or test anything.
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
      if (config.canBeResolved) {
        try {
          config.resolvedConfiguration.lenientConfiguration.allModuleDependencies.each { dep ->
            println("CVETRACE_DEP|" + proj.projectDir.absolutePath + "|" + dep.moduleGroup + ":" + dep.moduleName + ":" + dep.moduleVersion)
          }
        } catch (ignored) {
        }
      }
    }
  }
}
`

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

func parseGradleOutput(output string) []Dependency {
	seen := make(map[string]bool)
	var deps []Dependency

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "CVETRACE_DEP|") {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		projectDir, coordinate := parts[1], parts[2]

		coordParts := strings.SplitN(coordinate, ":", 3)
		if len(coordParts) != 3 {
			continue
		}
		group, artifact, version := coordParts[0], coordParts[1], coordParts[2]

		// Gradle always reports projectDir as absolute; relativize to the
		// current working directory so manifestPath reads consistently
		// with the other discoverers.
		manifestPath := filepath.Join(relativizeToCWD(projectDir), "build.gradle")

		key := manifestPath + "|" + group + ":" + artifact + ":" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, Dependency{
			Ecosystem:    "Maven",
			Name:         group + ":" + artifact,
			Version:      version,
			ManifestPath: manifestPath,
		})
	}

	return deps
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
// declarations, e.g. implementation("org.example:lib:1.0.0"). Used only
// when Gradle itself can't be invoked at all (no wrapper, no system
// install, or the invocation failed/timed out) -- it misses anything using
// variables, ext {} properties, or version catalogs, since correctly
// handling those requires actually evaluating the build script the way
// resolveGradleProject does.
var gradleDepRE = regexp.MustCompile(
	`(?:implementation|api|compile|runtimeOnly|testImplementation)\s*\(?\s*["']([\w.-]+):([\w.-]+):([\w.\-+]+)["']`,
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
			deps = append(deps, Dependency{
				Ecosystem:    "Maven",
				Name:         m[1] + ":" + m[2],
				Version:      m[3],
				ManifestPath: path,
			})
		}
		return deps
	}
	return nil
}
