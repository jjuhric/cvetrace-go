# cvetrace-go

A Go port of [jjuhric/cvetrace](https://github.com/jjuhric/cvetrace) — a CVE
**discovery, trace, and solutions** CLI. Same idea, different goal: this version
compiles to a single, fully static binary with no runtime bundled inside it and
nothing to install to run it, unlike the Node.js original (which needs Node
installed) or a compiled-JS approach like Bun (which bundles a whole JS runtime
into the binary, making it much larger).

> **Status: feature-complete.** Node, Java/Maven, Java/Gradle, and Python are all
> detected now (Gradle by actually invoking the target project's own Gradle wrapper,
> same as the Node version), every finding is tagged with the Node version's full
> "remediation intelligence" field set (`dependencyScope`/`usageContext`/
> `dependencyPath`/`codeReference`/`updateImpact`/`recommendedVersion`/
> `advisoryDetails`/`remediationTier`/`overrideSnippet`/`priorityScore`/`priorityLabel`),
> `--fail-on`/`--exclude`/`--ignore` plus a `.cvetraceignore` file all work, and
> [tagged releases](#installing-a-prebuilt-binary) publish zero-install binaries for
> Windows, macOS (Intel + Apple Silicon), and Linux automatically -- see
> [What's implemented so far](#whats-implemented-so-far) for the full picture.

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
| Running a prebuilt binary | Nothing. That's the point -- see [Installing a prebuilt binary](#installing-a-prebuilt-binary). |
| Building/running from source | [Go](https://go.dev) 1.26+ installed |
| Either way | Outbound internet access to `api.osv.dev` (the vulnerability lookup), always. Also needs Java installed (for Gradle itself), but only when the target project actually has a `build.gradle`/`.kts` -- irrelevant otherwise. |

## Installing a prebuilt binary

Every tag matching `v*.*.*` triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which cross-compiles this project for every supported OS/architecture and publishes the
binaries to that tag's [GitHub Release](https://github.com/jjuhric/cvetrace-go/releases) --
no `go` toolchain, no Node, nothing installed on the machine that ends up running it.

1. Download the binary matching your OS/architecture from the
   [latest release](https://github.com/jjuhric/cvetrace-go/releases/latest):
   `cvetrace-windows-amd64.exe`, `cvetrace-darwin-amd64`, `cvetrace-darwin-arm64`,
   `cvetrace-linux-amd64`, or `cvetrace-linux-arm64`.
2. On macOS/Linux, mark it executable: `chmod +x cvetrace-*`
3. Run it directly: `./cvetrace-darwin-arm64 scan <path-to-project>` (or just
   `cvetrace-windows-amd64.exe scan <path-to-project>` on Windows).

Each release also publishes a `checksums.txt` (SHA-256) alongside the binaries, so you
can verify a download before running it: `sha256sum -c checksums.txt` (or compare
manually against the file you downloaded).

`cvetrace --version` reports the exact release a downloaded binary came from -- see
`Version` in [`internal/cli/cli.go`](internal/cli/cli.go) for how the release workflow
bakes that in at build time.

## Usage

```sh
git clone https://github.com/jjuhric/cvetrace-go
cd cvetrace-go
go run ./cmd/cvetrace scan <path-to-project> [options]
```

Or build a binary once and reuse it:

```sh
go build -o cvetrace ./cmd/cvetrace
./cvetrace scan <path-to-project> [options]
```

- `<path-to-project>` — directory to scan. Detects Node (`package.json`/
  `package-lock.json`), Java/Maven (`pom.xml`), Java/Gradle (`build.gradle`/`.kts`, via
  a real invocation of the target project's own Gradle wrapper), and Python
  (`Pipfile.lock`/`requirements.txt`/`pyproject.toml`) — see
  [What's implemented so far](#whats-implemented-so-far) for exactly what's covered.
- `--json` — emit a machine-readable JSON report instead of the terminal report.
- `--fail-on <severity>` — exit non-zero if a vulnerability at or above this severity is
  found (`low`, `moderate`/`medium`, `high`, `critical`) — the flag a CI pipeline gates
  on. Ignored findings never count toward this.
- `--exclude <glob>` — glob pattern (relative to `<path-to-project>`), e.g. `'test/**'`,
  to skip during both dependency discovery and code-usage scanning — repeatable.
- `--ignore <id>` — dismiss a specific CVE/GHSA/etc. id for this run — repeatable. For a
  permanent dismissal, add a `.cvetraceignore` file to the scanned directory instead
  (see [Ignoring findings](#ignoring-findings)).

Run `cvetrace scan -h` for the full option reference (examples, exit status, and a
description of every report field).

**Go note:** unlike the Node version's CLI (built on commander.js, which accepts flags
anywhere), Go's standard `flag` package normally requires flags to come *before* any
positional argument. This project works around that (see `internal/cli/cli.go`'s
`reorderFlagsFirst`), so `cvetrace scan <path> --json` and
`cvetrace scan <path> --exclude test/**` both work the same way the Node version's does
— but it's exactly the kind of gotcha worth knowing about if you look at the code. More
detail in [GO_PRIMER.md](GO_PRIMER.md).

## Ignoring findings

Two ways to dismiss a reviewed-and-accepted finding so it stops showing up (mirrors
Nexus IQ/Dependabot's "dismiss"):

- `--ignore <id>` — one-off, this run only.
- A `.cvetraceignore` file in the directory being scanned — permanent: one CVE/GHSA/etc.
  id per line, blank lines and full-line `#` comments ignored, an optional trailing
  `# reason` captured for the record.

```
# .cvetraceignore
CVE-2021-1234                      # no reason given
CVE-2021-5678 # reviewed, false positive in our usage
```

Ignored findings are dropped from the main report and don't count toward `--fail-on`,
but are never silently discarded — run with `--json` to see the full `ignored` array
(id, reason, and which mechanism -- `.cvetraceignore` or `--ignore` -- matched). See
`internal/trace/ignore.go`.

## How it works

1. **Discover** (`internal/discover`) — walk the target directory, skip
   `node_modules`/`.git`/`target`/etc., and parse each ecosystem's manifests into
   resolved `{ecosystem, name, version}` dependencies: Node's `package.json`/
   `package-lock.json` (`node.go`), Maven's `pom.xml` via Go's built-in XML parser
   (`java.go`), Gradle's `build.gradle`/`.kts` by actually invoking the target project's
   own Gradle wrapper with a generated init script (`gradle.go` — the same
   "fully-resolved, not statically parsed" approach the Node version uses, with a
   regex-based static-parsing fallback if Gradle can't be invoked), and Python's
   `Pipfile.lock`/`requirements.txt`/`pyproject.toml` (`python.go`).
2. **Trace** (`internal/trace`) — batch-query [OSV.dev](https://osv.dev) (free, no API
   key) for each dependency, compute the correct fixed version for the *specific*
   affected-version range the current version actually falls in (a real bug from the
   Node version's development, ported over as a fix and a regression test here too --
   see `minimumFixedVersion`'s doc comment in `internal/trace/resolve.go`), collapse
   duplicate records OSV.dev sometimes indexes the same CVE under (another real bug,
   found this time while building *this* port -- see `dedupeByCVE`'s doc comment),
   classify each fix's semver distance (`updateImpact`) and the single actionable
   decision that follows from it (`remediationTier`), and aggregate every CVE known for
   the same package instance into one `recommendedVersion`.
3. **Usage detection** (`internal/trace/usage.go`) — a second, separate walk of the
   target directory's own source files (not manifests), tagging each finding's
   `codeReference` by regex-scanning for an import/require statement for that package.
4. **Override snippets** (`internal/trace/override.go`) — for confidently transitive
   findings with a known target version, generates the exact npm/Gradle/(future-ready
   Maven) snippet to force that version without waiting on the parent to update.
5. **Priority** (`internal/trace/priority.go`) — combines severity, `usageContext`, and
   `codeReference` (plus a small `updateImpact` tiebreak favoring easy wins) into one
   sortable `priorityScore` and a P1-P4 `priorityLabel`, and re-sorts every finding by it
   -- this is the pipeline's final ordering, deliberately worded differently from
   `severity` so e.g. "severity: CRITICAL, priority: P4" (a critical CVE in dev-only code
   never referenced in your own source) reads as a sensible triage call, not a
   contradiction.
6. **Ignore filtering** (`internal/trace/ignore.go`) — merges `.cvetraceignore` with
   `--ignore` values and splits findings into kept/ignored, right before reporting.
7. **Report** (`internal/report`) — a colorized terminal report, or `--json`.

## Fields on each finding

| Field | Values | Meaning |
|---|---|---|
| `dependencyScope` | `direct` / `transitive` / `unknown` | Whether the vulnerable package is declared directly in your manifest, or pulled in by something else you depend on. |
| `dependencyPath` | array or omitted | For transitive findings **in Node or Gradle** (the only ecosystems this port resolves a real dependency graph for): the chain from a direct dependency down to this package, e.g. `["webpack", "loader-utils", "vulnerable-pkg"]`. Omitted for direct dependencies, and always omitted for Maven/Python since those aren't resolved transitively at all. |
| `usageContext` | `production` / `development` / `unknown` | Whether the package is reachable from your production dependencies, or only from dev/test/build tooling (`devDependencies`, Maven `test` scope, Gradle `testImplementation`, etc.) that never ships. |
| `codeReference` | `found` / `not-found` / `unknown` | Whether the package is actually imported/required anywhere in your own source files, not just declared in a manifest. **This is a usage signal, not reachability analysis** -- `found` doesn't mean the specific vulnerable function is called, and `not-found` doesn't prove the code is unused (dynamic requires, reflection, etc. are missed). Java/Kotlin detection assumes the library's import matches its Maven/Gradle groupId (usually true, not guaranteed); Python detection uses the PyPI package name directly, which misses packages whose import name differs from what's published (e.g. PyYAML is `import yaml`) -- a known gap, not silently handled. See `DetectCodeReferences` in `internal/trace/usage.go`. |
| `updateImpact` | `patch` / `minor` / `major` / `unknown` | How big a semver jump the fix requires -- a heuristic for how likely it is to be backwards-compatible, not a guarantee. Log4Shell's own fix (2.14.1 → 2.15.0) is itself a "minor" bump by this measure. |
| `recommendedVersion` | version or omitted | The single highest fix version across every CVE known for this exact package instance -- "upgrade to X, clears everything" instead of reconciling N separate per-CVE targets. Omitted if no fix is known for any of them yet. |
| `advisoryDetails` | text or omitted | OSV.dev's full advisory text, which frequently has a mitigation/workaround section beyond "upgrade" (e.g. Log4Shell's config-flag workaround for anyone who can't upgrade immediately). |
| `remediationTier` | `safe-to-update` / `needs-approval` / `no-fix-available` / `unknown-impact` | Collapses `fixedVersion` + `updateImpact` into one decision to branch on directly -- see `classifyRemediationTier`'s doc comment in `internal/trace/resolve.go` for exactly what each value does and doesn't guarantee. Shown as the terminal report's `->` action line. |
| `overrideSnippet` | object or omitted (JSON output only) | For transitive findings with a known target version: the exact `{file, instructions, snippet}` to force the patched version without waiting on the parent dependency to update -- npm `overrides`, Gradle `resolutionStrategy.force`, or (ready for when Maven support grows that far) Maven `dependencyManagement`. Often the fastest real fix for a transitive CVE. Omitted for direct dependencies and for ecosystems that don't resolve transitively at all. See `generateOverrideSnippet` in `internal/trace/override.go`. |
| `priorityScore` / `priorityLabel` | number / `P1`-`P4` | A single sortable triage ranking combining severity, `usageContext`, `codeReference`, and a small `updateImpact` bonus -- see `ComputePriority`'s doc comment in `internal/trace/priority.go` for the exact formula and, importantly, what it isn't (an authoritative risk score). This is the terminal report's actual sort order and the `[P#]` prefix on each line. |

Every field from the Node version's "remediation intelligence" set now exists in this
port -- see [What's implemented so far](#whats-implemented-so-far) for the full
ecosystem-by-ecosystem picture. The Node version (`jjuhric/cvetrace`) remains the
reference for exact behavior; this project is about porting it to Go faithfully, not
reinventing it.

## What's implemented so far

| Ecosystem | Manifests read | Status |
|---|---|---|
| Node.js | `package.json`, `package-lock.json` | Fully resolved, including transitive dependencies -- `dependencyScope`/`usageContext`/`dependencyPath` come from a breadth-first walk of the lockfile's own per-package `dependencies` graph, seeded from the root manifest's `dependencies`/`devDependencies` (see `buildNodeScopeMap` in `node.go`). |
| Java (Maven) | `pom.xml`, incl. `${property}` resolution | Only directly declared dependencies are traced -- no transitive resolution (that would require invoking `mvn`, not currently done), so `dependencyScope` is always `direct` and `dependencyPath` is always omitted. `usageContext` comes from `<scope>test</scope>` mapping to `development`, everything else to `production`. |
| Java (Gradle) | `build.gradle`/`.kts` | **Fully resolved** by actually invoking the target project's own `gradlew`/`gradlew.bat` wrapper (falling back to a system-wide `gradle` if no wrapper is present) with a generated init script, including transitive dependencies and the full dependency path to each one -- same accuracy as Node/npm. Falls back to regex-based static parsing of `build.gradle` (direct-only, no path) if Gradle itself can't be invoked (e.g. no Java installed). |
| Python | `Pipfile.lock`, `requirements.txt`, `pyproject.toml` (best-effort, not a full TOML parser -- see `python.go`) | No transitive resolution -- `dependencyPath` is always omitted. `dependencyScope` is `direct` for requirements.txt/pyproject.toml, or `unknown` for Pipfile.lock (whose lock format doesn't retain which entries were originally declared vs. pulled in transitively). `usageContext` comes from Pipfile.lock's default/develop split, a `requirements-dev.txt`-style sibling filename, or a pyproject.toml/Poetry group name matching a dev-ish convention (`dev`, `test`, `docs`, `lint`, `typing`). |

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
fixtures of the same names (`minimist@0.0.8`, `log4j-core@2.14.1` a.k.a. Log4Shell (both
in `java-fixture-project`'s `pom.xml` and, separately, in `gradle-fixture-project`'s
`build.gradle`), and `PyYAML==5.3`, each a real, known CVE), kept in sync so both
projects prove correctness against the exact same known vulnerabilities. The Gradle
fixture includes a real, committed Gradle wrapper so its test exercises actual Gradle
invocation, not just the static-parsing fallback — expect that particular test to be the
slowest in the suite (Gradle daemon/dependency-cache startup).

### Cutting a release

Push a tag matching `v*.*.*` and [`.github/workflows/release.yml`](.github/workflows/release.yml)
takes it from there -- runs the full test suite as a gate, cross-compiles for every
supported OS/architecture with the tag baked in as `cvetrace --version`'s output, and
publishes the binaries plus a `checksums.txt` to that tag's GitHub Release:

```sh
git tag v1.2.3
git push origin v1.2.3
```

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
