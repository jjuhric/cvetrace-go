# cvetrace-go

A Go port of [jjuhric/cvetrace](https://github.com/jjuhric/cvetrace) — a CVE
**discovery, trace, and solutions** CLI. Same idea, different goal: this version
compiles to a single, fully static binary with no runtime bundled inside it and
nothing to install to run it, unlike the Node.js original (which needs Node
installed) or a compiled-JS approach like Bun (which bundles a whole JS runtime
into the binary, making it much larger).

> **Status: early slice, discovery-only.** This is the second of several planned
> increments — see [What's implemented so far](#whats-implemented-so-far). Node,
> Java/Maven, and Python are all detected now; Gradle's real dependency resolution
> (the Node version invokes the target project's own Gradle wrapper for full accuracy)
> and everything the Node version's "remediation intelligence" report fields provide are
> **not built yet**. There's also no release pipeline yet publishing downloadable
> binaries — for now this is run from source (see [Usage](#usage)); prebuilt,
> zero-install binaries are the whole point of doing this in Go, and are a planned
> near-term addition.

**New to Go?** See [GO_PRIMER.md](GO_PRIMER.md) — a concept map from what you already
know from the Node version of this project (JavaScript) to Go, plus pointers to where
each concept shows up in this actual codebase. The source code itself is also commented
more heavily than is typical, specifically to explain Go idioms as they appear.

## Why Go, specifically

Go compiles directly to a native, OS-specific binary with no separate runtime needed to
run it — the same category as C/C++/Rust, and a tier above compiling a JS codebase with
Bun/Deno/Node's SEA feature (which still bundle an entire language runtime into the
output, producing a much larger file). Go was chosen over C/C++/Rust for this specific
project because its standard library already covers everything a CVE scanner needs —
HTTP client (`net/http`), JSON (`encoding/json`), regex, directory walking — with no
third-party dependencies required, and because it cross-compiles for every OS from a
single machine with zero extra tooling (`GOOS=windows go build`, no toolchain juggling).

## Requirements

| Scenario | What you need |
|---|---|
| Building/running from source (current state) | [Go](https://go.dev) 1.26+ installed, and outbound internet access to `api.osv.dev` (the vulnerability lookup) |
| Running a prebuilt binary (planned, not yet published) | Nothing. That's the point. |

## Usage

```sh
git clone https://github.com/jjuhric/cvetrace-go
cd cvetrace-go
go run ./cmd/cvetrace scan <path-to-project> [--json]
```

Or build a binary once and reuse it:

```sh
go build -o cvetrace ./cmd/cvetrace
./cvetrace scan <path-to-project> [--json]
```

- `<path-to-project>` — directory to scan. Detects Node (`package.json`/
  `package-lock.json`), Java/Maven (`pom.xml`), and Python (`Pipfile.lock`/
  `requirements.txt`/`pyproject.toml`) — see
  [What's implemented so far](#whats-implemented-so-far) for exactly what's covered.
- `--json` — emit a machine-readable JSON report instead of the terminal report.

**Go note:** unlike the Node version's CLI (built on commander.js, which accepts flags
anywhere), Go's standard `flag` package normally requires flags to come *before* any
positional argument. This project works around that (see `internal/cli/cli.go`'s
`reorderFlagsFirst`), so `cvetrace scan <path> --json` works the same way the Node
version's does — but it's exactly the kind of gotcha worth knowing about if you look at
the code. More detail in [GO_PRIMER.md](GO_PRIMER.md).

## How it works

1. **Discover** (`internal/discover`) — walk the target directory, skip
   `node_modules`/`.git`/`target`/etc., and parse each ecosystem's manifests into
   resolved `{ecosystem, name, version}` dependencies: Node's `package.json`/
   `package-lock.json` (`node.go`), Maven's `pom.xml` via Go's built-in XML parser
   (`java.go`), and Python's `Pipfile.lock`/`requirements.txt`/`pyproject.toml`
   (`python.go`).
2. **Trace** (`internal/trace`) — batch-query [OSV.dev](https://osv.dev) (free, no API
   key) for each dependency, compute the correct fixed version for the *specific*
   affected-version range the current version actually falls in (a real bug from the
   Node version's development, ported over as a fix and a regression test here too --
   see `minimumFixedVersion`'s doc comment in `internal/trace/resolve.go`), and collapse
   duplicate records OSV.dev sometimes indexes the same CVE under (another real bug,
   found this time while building *this* port -- see `dedupeByCVE`'s doc comment).
3. **Report** (`internal/report`) — a colorized terminal report, or `--json`.

## What's implemented so far

| Ecosystem | Manifests read | Status |
|---|---|---|
| Node.js | `package.json`, `package-lock.json` | Implemented |
| Java (Maven) | `pom.xml`, incl. `${property}` resolution | Implemented |
| Java (Gradle) | `build.gradle`/`.kts` | Not yet — planned. The Node version gets full accuracy here by actually invoking the target project's own Gradle wrapper, which is a meaningfully bigger effort than static parsing (subprocess management, a generated init script) -- deliberately its own future increment rather than bundled in with Java/Python. |
| Python | `Pipfile.lock`, `requirements.txt`, `pyproject.toml` (best-effort, not a full TOML parser -- see `python.go`) | Implemented |

None of the Node version's later "remediation intelligence" fields
(`dependencyScope`/`usageContext`/`dependencyPath`/`codeReference`/`updateImpact`/
`recommendedVersion`/`overrideSnippet`/`advisoryDetails`/`priorityScore`/
`remediationTier`), nor `--fail-on`/`--exclude`/`--ignore`, exist in this port yet
either. The Node version (`jjuhric/cvetrace`) is the reference for what to build next;
this project is about porting it to Go incrementally, not reinventing it.

## Development

```sh
go build ./...     # compile everything
go vet ./...        # catch common mistakes static analysis can find
gofmt -l .           # list any files that aren't formatted correctly (gofmt -w . to fix)
go test ./...         # run all tests
```

Cross-compiling for another OS is one flag, no extra toolchain:

```sh
GOOS=windows GOARCH=amd64 go build -o cvetrace.exe ./cmd/cvetrace
GOOS=darwin  GOARCH=arm64 go build -o cvetrace-mac  ./cmd/cvetrace
GOOS=linux   GOARCH=amd64 go build -o cvetrace-linux ./cmd/cvetrace
```

Test fixtures live under `test/fixtures/*-fixture-project` — copies of the Node repo's
fixtures of the same names (`minimist@0.0.8`, `log4j-core@2.14.1` a.k.a. Log4Shell, and
`PyYAML==5.3`, each a real, known CVE), kept in sync so both projects prove correctness
against the exact same known vulnerabilities.

## Project layout

```
cvetrace-go/
  go.mod                    # module definition (like package.json, but much smaller)
  cmd/cvetrace/main.go      # thin executable entrypoint
  internal/
    cli/        # argument parsing, subcommand dispatch
    discover/    # finds dependencies in a project directory
    trace/        # queries OSV.dev, resolves the correct fix version
    report/        # terminal + JSON output
  test/fixtures/    # known-vulnerable sample projects used by tests
```

See [GO_PRIMER.md](GO_PRIMER.md) for why it's organized this way.

## License

MIT
