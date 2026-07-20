// Package cli parses command-line arguments and dispatches to the scan
// pipeline (internal/discover -> internal/trace -> internal/report).
package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jjuhric/cvetrace-go/internal/discover"
	"github.com/jjuhric/cvetrace-go/internal/report"
	"github.com/jjuhric/cvetrace-go/internal/trace"
)

// Version is the released version string (e.g. "v1.2.3"), reported by
// `cvetrace -v`/`--version`/`version`. It defaults to "dev" -- a locally
// built binary (go build/go run without extra flags) always identifies
// itself this way. The release workflow (.github/workflows/release.yml)
// overrides it at build time via `-ldflags "-X
// github.com/jjuhric/cvetrace-go/internal/cli.Version=v1.2.3"`.
//
// Go note: this is a genuinely compile-time trick, not something achievable
// with a plain Go assignment -- `-ldflags -X importpath.Var=value` tells
// the *linker* to overwrite an already-compiled package-level string
// variable's value while producing the final binary, after all of this
// project's own Go code has already been compiled. It only works on
// package-level `var` declarations of type string (not `const`, since a Go
// `const` is resolved entirely at compile time with no linker step left to
// intervene in). The closest JS equivalent is a bundler's build-time
// define/replace step (e.g. webpack's DefinePlugin substituting
// `process.env.NODE_ENV`) -- same idea of baking a value in at build time
// rather than reading it at runtime, just implemented at the linker level
// instead of a source-rewriting build step.
var Version = "dev"

const rootUsage = `cvetrace scans a Node.js/Java(Maven+Gradle)/Python project directory for
known CVEs in its dependencies, using the free OSV.dev vulnerability
database (no API key required).

DESCRIPTION
  cvetrace walks a project directory, identifies every dependency it can
  resolve (Node via package-lock.json; Java via Maven's pom.xml, or a real
  Gradle invocation for build.gradle/.kts; Python via Pipfile.lock,
  requirements.txt, or pyproject.toml), and batch-queries OSV.dev
  (https://osv.dev, no API key required) for known CVEs affecting each one.

  Every finding is enriched with triage signals -- is it actually reachable
  from production code, is it even imported anywhere, how big a version
  jump is the fix, is there a faster override -- and rolled into one
  priority score, so a pile of findings can be worked top-down instead of
  one by one.

  It never edits your files. Each finding's remediationTier field says what
  to do about it -- apply it directly, propose a plan and wait for
  approval, or fall back to a mitigation -- so the report is meant to be
  acted on: by you, or by an AI coding agent with real codebase access to
  judge and apply fixes safely.

REQUIREMENTS
  Outbound internet access to api.osv.dev, always. A JDK, additionally,
  only when scanning a project with a Gradle build.

QUICK START
  cvetrace scan .                     Scan the current directory
  cvetrace scan . --json              Machine-readable report
  cvetrace scan . --fail-on critical  Exit non-zero for CI gating
  cvetrace scan . --exclude test/**   Skip a directory tree
  cvetrace scan . --ignore CVE-2021-1 Dismiss a reviewed/accepted finding
  cvetrace --version                  Print the version and exit

Run 'cvetrace scan -h' for the full option reference.

SEE ALSO
  README   https://github.com/jjuhric/cvetrace-go
  OSV.dev  https://osv.dev
`

const scanUsage = `Usage:
  cvetrace scan <path> [options]

Options:
  --json               output a machine-readable JSON report instead of the
                        terminal report
  --fail-on <severity>  exit non-zero if a vulnerability at or above this
                        severity is found (low, moderate/medium, high,
                        critical)
  --exclude <glob>      glob pattern (relative to <path>) to skip, e.g.
                        'test/**' -- repeatable
  --ignore <id>         dismiss a specific CVE/GHSA/etc. id for this run --
                        repeatable (see IGNORING FINDINGS below for the
                        permanent .cvetraceignore option)

EXAMPLES
  cvetrace scan .
      Scan the current directory, colorized terminal report.

  cvetrace scan ../some-other-project --json
      Scan a different directory, JSON report instead.

  cvetrace scan . --fail-on high
      Exit 1 if anything HIGH or CRITICAL is found (also accepts
      low, moderate/medium, critical).

  cvetrace scan . --exclude test/** --exclude legacy/**
      Skip multiple directory trees -- repeat the flag as needed.

  cvetrace scan . --ignore CVE-2021-1234 --ignore GHSA-xxxx-xxxx-xxxx
      Dismiss specific findings for this run -- repeatable, same as
      --exclude. For a permanent dismissal, use a .cvetraceignore file
      in the scanned directory instead (see IGNORING FINDINGS below).

EXIT STATUS
  0  Scan completed. This is the default even when vulnerabilities are
     found -- cvetrace reports, it doesn't judge, unless asked to via
     --fail-on. Ignored findings never count toward --fail-on.
  1  A vulnerability at or above the --fail-on threshold was found, or
     an unrecognized --fail-on value was given, or the scan itself failed.

REPORT FIELDS
  Every finding carries triage fields beyond the CVE id, severity, and fix
  version -- none of these are proof of anything; they're heuristics for
  working through a pile of findings, not a verdict on any single one:

    remediationTier                safe-to-update | needs-approval |
                                    no-fix-available | unknown-impact --
                                    the field to branch on for "what do I
                                    do about this".
    priorityScore / priorityLabel  cvetrace's own P1-P4 triage ranking,
                                    combining everything below. Worded
                                    differently from severity on purpose: a
                                    CRITICAL CVE in unused dev-only code
                                    can still land at P4.
    dependencyScope                direct | transitive | unknown
    usageContext                   production | development | unknown
    dependencyPath                 for transitive findings (Node/Gradle
                                    only): the chain from a direct
                                    dependency down to this package
    codeReference                  found | not-found | unknown -- is the
                                    package actually imported/required
                                    anywhere in your source, not just
                                    declared in a manifest
    updateImpact                   patch | minor | major | unknown
    recommendedVersion             the single version that clears every
                                    known CVE for this exact package, not
                                    just this one
    overrideSnippet                for transitive findings: the exact
                                    npm/Gradle/Maven snippet to force the
                                    patched version without waiting on the
                                    parent dependency (JSON output only)
    advisoryDetails                OSV.dev's full advisory text, which
                                    often has mitigation/workaround
                                    guidance beyond "upgrade" (JSON output
                                    only)

IGNORING FINDINGS
  Two ways to dismiss a reviewed-and-accepted finding so it stops showing
  up (mirrors Nexus IQ/Dependabot's "dismiss"):

    --ignore <id>         one-off, this run only
    .cvetraceignore file   permanent, in the directory being scanned: one
                           CVE/GHSA/etc. id per line, blank lines and
                           full-line "#" comments ignored, an optional
                           trailing "# reason" captured for the record.

  Ignored findings are dropped from the main report and don't count toward
  --fail-on, but are never silently discarded -- run with --json to see
  the full "ignored" array (id, reason, and which mechanism matched).

SEE ALSO
  cvetrace -h
  README  https://github.com/jjuhric/cvetrace-go
`

// stringSliceFlag collects every occurrence of a repeatable flag (--exclude,
// --ignore) into a slice, in the order given.
//
// Go note: this is how the standard flag package supports a flag that can
// be passed more than once -- there's no built-in "repeatable" flag type
// the way some CLI libraries provide (commander.js's own repeatable-flag
// support, which the Node version of this tool uses, works similarly under
// the hood: an accumulator function called once per occurrence). Any type
// implementing the two-method flag.Value interface (String() and
// Set(string) error) can be registered with fs.Var and used as a flag's
// backing storage; Set is called once per occurrence of the flag on the
// command line, so appending there is exactly what's needed here.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Run is the program's entrypoint, called from cmd/cvetrace/main.go with the
// raw command-line arguments (os.Args). It returns an exit code rather than
// calling os.Exit itself.
//
// Go note: keeping exit-code decisions here instead of calling os.Exit
// directly makes Run testable -- a test can call Run and check the returned
// int, whereas os.Exit would kill the whole test process immediately. Only
// cmd/cvetrace/main.go, the actual program entrypoint, ever calls os.Exit.
func Run(args []string) int {
	if len(args) < 2 {
		fmt.Print(rootUsage)
		return 0
	}

	switch args[1] {
	case "scan":
		return runScan(args[2:])
	case "-h", "--help", "help":
		fmt.Print(rootUsage)
		return 0
	case "-v", "--version", "version":
		fmt.Println("cvetrace " + Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "cvetrace: unknown command %q\n\n%s", args[1], rootUsage)
		return 1
	}
}

func runScan(args []string) int {
	// Go note: flag.NewFlagSet (rather than the package-level flag.String,
	// flag.Bool, etc.) creates a flag set scoped to just this subcommand, so
	// "cvetrace scan --json" doesn't have to share a single global flag
	// namespace with any other subcommand this program might grow later.
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.Usage = func() { fmt.Print(scanUsage) }

	jsonOutput := fs.Bool("json", false, "output a machine-readable JSON report")
	failOn := fs.String("fail-on", "", "exit non-zero if a vulnerability at or above this severity is found")
	var excludes stringSliceFlag
	fs.Var(&excludes, "exclude", "glob pattern to skip -- repeatable")
	var ignoreIDs stringSliceFlag
	fs.Var(&ignoreIDs, "ignore", "dismiss a specific CVE/GHSA/etc. id for this run -- repeatable")

	// Go note: fs.Parse mutates the flag variables above in place and
	// returns an error only for things like an unknown flag -- with
	// flag.ExitOnError (set above), it actually calls os.Exit itself on a
	// parse error rather than returning one, so the err check here is
	// mostly a formality, but it's still good practice not to silently
	// ignore a returned error.
	//
	// Go note, the important one: Go's flag package stops looking for flags
	// at the *first* non-flag argument. Without reorderFlagsFirst below,
	// "cvetrace scan test/my-project --json" would silently treat "--json"
	// as a second positional argument instead of a flag, since the path
	// came first -- only "cvetrace scan --json test/my-project" would work.
	// That's a real surprise coming from commander.js (the Node version of
	// this tool's CLI library), which parses flags in any position. See
	// GO_PRIMER.md for more on this.
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "cvetrace scan: missing <path> argument")
		return 1
	}
	targetPath := fs.Arg(0)

	deps, err := discover.Walk(targetPath, excludes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
		return 1
	}

	vulns, err := trace.Resolve(deps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
		return 1
	}

	vulns, err = trace.DetectCodeReferences(targetPath, vulns, excludes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
		return 1
	}

	vulns = trace.ApplyOverrideSnippets(vulns)
	vulns = trace.ApplyPriority(vulns)

	fileRules, err := trace.LoadIgnoreFile(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
		return 1
	}
	kept, ignored := trace.ApplyIgnoreRules(vulns, fileRules, ignoreIDs)

	if *jsonOutput {
		out, err := report.BuildJSON(kept, ignored)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
	} else {
		report.PrintTerminal(kept, ignored)
	}

	if *failOn != "" {
		meets, err := meetsThreshold(kept, *failOn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
			return 1
		}
		if meets {
			return 1
		}
	}

	return 0
}

// meetsThreshold reports whether any of vulns is at or above failOn's
// severity (case-insensitive) -- the --fail-on gate used for CI.
func meetsThreshold(vulns []trace.Vulnerability, failOn string) (bool, error) {
	threshold, ok := trace.SeverityRank[strings.ToUpper(failOn)]
	if !ok {
		return false, fmt.Errorf("unknown --fail-on severity: %s", failOn)
	}
	for _, v := range vulns {
		if trace.SeverityRank[v.Severity] >= threshold {
			return true, nil
		}
	}
	return false, nil
}

// flagsWithValue lists every flag this project has that consumes a second,
// separate token as its value (as opposed to a plain on/off switch like
// --json) -- reorderFlagsFirst needs to know this set so it moves both
// tokens together, rather than accidentally splitting a flag from its value
// across the flags/positionals boundary.
var flagsWithValue = map[string]bool{
	"--fail-on": true,
	"--exclude": true,
	"--ignore":  true,
}

// reorderFlagsFirst rearranges args so every flag-looking argument (anything
// starting with "-") -- plus, for flagsWithValue, the very next token, its
// value -- comes before any positional argument, preserving the relative
// order within each group. E.g. ["path", "--json"] becomes
// ["--json", "path"], and ["path", "--exclude", "test/**"] becomes
// ["--exclude", "test/**", "path"]. See the "Go note, the important one"
// comment on runScan for why this exists.
//
// A flag written as "--exclude=test/**" (value attached with "=") is left
// alone either way, since it's already a single self-contained token -- the
// two-token form is the one this function has to actively handle.
func reorderFlagsFirst(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}

		flags = append(flags, arg)
		if flagsWithValue[arg] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}
