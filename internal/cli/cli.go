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

const usage = `cvetrace scans a Node.js project directory for known CVEs in its
dependencies, using the free OSV.dev vulnerability database (no API key
required).

This is an early, Node-ecosystem-only slice of a larger port -- see the
project README for what's implemented so far and what's planned next.

Usage:
  cvetrace scan <path> [--json]

Options:
  --json    output a machine-readable JSON report instead of the terminal report
`

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
		fmt.Print(usage)
		return 0
	}

	switch args[1] {
	case "scan":
		return runScan(args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "cvetrace: unknown command %q\n\n%s", args[1], usage)
		return 1
	}
}

func runScan(args []string) int {
	// Go note: flag.NewFlagSet (rather than the package-level flag.String,
	// flag.Bool, etc.) creates a flag set scoped to just this subcommand, so
	// "cvetrace scan --json" doesn't have to share a single global flag
	// namespace with any other subcommand this program might grow later.
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "output a machine-readable JSON report")

	// Go note: fs.Parse mutates jsonOutput in place and returns an error only
	// for things like an unknown flag -- with flag.ExitOnError (set above),
	// it actually calls os.Exit itself on a parse error rather than
	// returning one, so the err check here is mostly a formality, but it's
	// still good practice not to silently ignore a returned error.
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

	deps, err := discover.Walk(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
		return 1
	}

	vulns, err := trace.Resolve(deps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
		return 1
	}

	if *jsonOutput {
		out, err := report.BuildJSON(vulns)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cvetrace: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
	} else {
		report.PrintTerminal(vulns)
	}

	return 0
}

// reorderFlagsFirst rearranges args so every flag-looking argument (anything
// starting with "-") comes before any positional argument, preserving the
// relative order within each group -- e.g. ["path", "--json"] becomes
// ["--json", "path"]. See the "Go note, the important one" comment above for
// why this exists.
//
// This only works correctly for flags that don't take a separate value token
// (like --json, a plain on/off switch). A flag written as two tokens, e.g.
// "--fail-on critical", would have its value token wrongly left behind in
// the positional group by this simple version -- not a problem yet, since
// --json is the only flag this project has so far, but worth knowing before
// copying this pattern for a future flag that takes a value.
func reorderFlagsFirst(args []string) []string {
	var flags, positionals []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}
