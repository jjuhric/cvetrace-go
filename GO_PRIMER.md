# Go for JS developers

A concept map from what you already know — this project's own Node.js version — to Go,
written against this specific codebase. Every section points at real files so you can
go read the actual code, not just the explanation.

## The shape of a project

**JS:** `package.json` declares the project + dependencies; `node_modules/` holds
installed packages; any file can `require`/`import` any other file relative to itself
or by package name.

**Go:** `go.mod` declares the module (this project's own import path) and its
dependencies — much shorter, since this project currently has *zero* third-party
dependencies (everything it needs — HTTP, JSON, file walking — is in Go's standard
library). See [`go.mod`](go.mod).

Code is organized into **packages** — every `.go` file starts with a `package foo`
line, and every file in the same directory must declare the same package name. A
package is the unit of visibility: only names starting with a capital letter
(`Dependency`, `Walk`) are visible outside their own package; lowercase names
(`skipDirs`, `discoverNode`) are private to it. There's no `export` keyword — the
capital letter *is* the export.

`internal/` is not just a naming convention, it's enforced by the compiler: packages
under a directory named `internal/` can only be imported by code inside the same
module. Try importing `github.com/jjuhric/cvetrace-go/internal/discover` from some
other, unrelated Go module and it simply won't compile. That's why this project's real
logic lives under `internal/` and `cmd/cvetrace/main.go` (see below) stays tiny — the
logic packages are explicitly *not* a public library for other projects to depend on.

## Errors instead of exceptions

**JS:** functions throw; callers wrap risky calls in `try { } catch (err) { }`, and it's
easy to forget to catch something.

**Go:** a function that can fail returns an `error` as its *last* return value —
`func Walk(root string) ([]Dependency, error)` in
[`internal/discover/discover.go`](internal/discover/discover.go). There's no
`try`/`catch`. Instead:

```go
deps, err := discover.Walk(targetPath)
if err != nil {
    // handle it
}
```

This is everywhere in Go code, to the point of feeling repetitive at first. The upside:
there's no way to *silently* ignore an error the way a missing `catch` block in JS
would — you have to explicitly write `if err != nil` and decide what to do, or
explicitly throw the error away (`_, _ = discover.Walk(...)`), which is a visible,
deliberate choice rather than an accident.

`fmt.Errorf("OSV.dev querybatch failed: %s", resp.Status)` in
[`internal/trace/osv.go`](internal/trace/osv.go) is how you construct a new error —
Go's equivalent of `throw new Error(...)`, except it's *returned*, never thrown.

## Structs instead of objects

**JS:** an object's shape is whatever properties you happened to set on it.

**Go:** a `struct` declares its exact shape up front — see `Dependency` in
[`internal/discover/types.go`](internal/discover/types.go). Every `Dependency` value
always has exactly the fields `Ecosystem`, `Name`, `Version`, `ManifestPath` — no more,
no fewer, and the compiler checks this at every use.

JSON struct tags (the `` `json:"ecosystem"` `` part) tell `encoding/json` how to map
between Go's `UpperCamelCase` field names (required to be capitalized, so they're
visible outside the package) and the `lowerCamelCase` JSON keys this project's reports
use — see `Vulnerability` in [`internal/trace/resolve.go`](internal/trace/resolve.go).
There's no separate schema file; the struct *is* the schema, for both directions
(parsing OSV.dev's responses, and producing this tool's own `--json` output).

## No `null`/`undefined` — zero values instead

**JS:** an unset variable is `undefined`; you can explicitly set something to `null`.

**Go:** every type has a **zero value** it starts at if you don't set it explicitly —
`""` for strings, `0` for numbers, `false` for booleans, `nil` for pointers/slices/maps.
There's no third "not set" state distinct from the zero value itself. This shows up
directly in [`internal/trace/osv.go`](internal/trace/osv.go)'s `event` struct: OSV.dev's
JSON only ever sends *one* of `introduced`/`fixed`/`last_affected` per event, and
whichever ones are absent from the JSON simply decode to `""` — so `if e.Fixed != ""` is
how the code asks "was this a fixed event," relying on the zero value directly instead
of needing a separate "is this present" flag.

The `(value, ok bool)` return pattern — see `parseVersionParts` in
[`internal/trace/resolve.go`](internal/trace/resolve.go) — is how Go expresses "this
might not have worked" for non-error cases: instead of returning `null`/`NaN` the way JS
might, it returns a second boolean the caller has to explicitly check.

Sometimes, though, you genuinely want three states -- "unset," "set to the zero value,"
and "set to something else" -- and a plain value can't tell the first two apart. A
pointer can: a `nil` pointer means "unset," and a non-nil pointer (even one pointing at
`""`) means "set." [`internal/discover/node.go`](internal/discover/node.go)'s
`bfsPredecessors` needs exactly this: it records, for every package name reached while
walking the dependency graph, which other package name pulled it in -- except for a
*seed* package (one of the manifest's own direct dependencies), which has no predecessor
at all. A plain `map[string]string` can't distinguish "reached, no predecessor" (a seed)
from "never reached" (not in the map), since both would need to map to `""` and Go
map lookups already have their own `(value, ok)` form for "was this key present" --
using that same trick *inside* the stored value would be confusing. Instead
`bfsPredecessors` returns `map[string]*string`: `nil` for a seed's predecessor, a
pointer to the actual predecessor name otherwise, and simple key-presence in the map
(checked the normal `map[string]ok` way) for "was this name reached by the search at
all." This is the JS equivalent of the difference between `undefined` (key never set)
and an object holding `{ predecessor: null }` (key set, value deliberately empty) --
Go just makes you reach for a pointer to get that second state, since a bare `string`
zero value can't represent it.

## `defer` instead of `finally`

**Go:** `defer resp.Body.Close()` (see [`internal/trace/osv.go`](internal/trace/osv.go))
schedules that call to run when the *surrounding function* returns, no matter which
`return` statement triggers it. It's Go's answer to "I need to guarantee cleanup" — the
same job `finally` does in JS, but attached right next to the resource being acquired,
rather than in a separate block potentially far away.

## Testing: built-in, convention over configuration

**JS (this project's Node version):** `node --test`, `describe`/`test` blocks.

**Go:** any function named `TestXxx(t *testing.T)` in a file named `*_test.go` is a
test — `go test ./...` finds and runs all of them automatically. No test framework to
install, no config file. See
[`internal/trace/resolve_test.go`](internal/trace/resolve_test.go) — including a direct
port of the real Log4Shell interval-matching bug the Node version's tests caught, as a
regression test here too.

`t.Fatalf` stops the current test immediately (use when there's no point checking
anything else); `t.Errorf` records a failure but lets the test keep running (use to
report several independent problems from one test instead of stopping at the first).

## Parsing formats beyond JSON

**JS (this project's Node version):** JSON parsing is built into the language
(`JSON.parse`), but there's no built-in XML support and no built-in TOML support --
`src/discover/java.js` in the Node repo has to fall back to regular expressions to
scrape `pom.xml`, since JavaScript simply has nothing better for XML.

**Go:** the standard library ships a real XML parser, `encoding/xml` -- see
[`internal/discover/java.go`](internal/discover/java.go). `xml.Unmarshal` decodes
`pom.xml` directly into Go structs the same way `encoding/json` decodes JSON, matching
struct tags (`` `xml:"groupId"` ``) to element names, so this Go port doesn't need the
regex workaround the Node version does for the same file. One subtlety worth knowing:
by default, a struct tag with no namespace prefix matches an element by its *local*
name regardless of what XML namespace it's actually in -- which is why this still
decodes correctly even though the real `pom.xml` fixture declares a default namespace
(`xmlns="http://maven.apache.org/POM/4.0.0"`) on its root element.

`<properties>` needed a different technique, though: its child elements have
*arbitrary*, project-defined tag names (`<log4j.version>2.14.1</log4j.version>` -- the
tag name itself *is* the property name), which can't be declared as fixed struct fields
the way `<dependency>`'s always-the-same-shape children can. `` `xml:",any"` `` is
Go's catch-all for exactly this: "match any child element I haven't already claimed,"
capturing the tag name and text content generically. Look at the `mavenProperty`
struct and its usage in `java.go` for the full pattern.

Go's standard library has *no* TOML support at all, unlike JSON and XML -- so
[`internal/discover/python.go`](internal/discover/python.go)'s `pyproject.toml`
handling stays regex-based and best-effort, same as the Node version's, rather than
reaching for this project's first third-party dependency over partial TOML coverage.
That file also uses Go's `regexp` package (`internal/discover/python.go`), which is
worth one note of its own: it implements RE2 syntax, a different (and less expressive)
engine than JS's regex -- no backreferences, no lookahead/lookbehind -- in exchange for
a hard guarantee that matching always runs in time linear to the input's length, so a
malicious or just weird input can never cause catastrophic backtracking the way it
occasionally can in JS. None of the patterns in this project needed the unsupported
features, so this only ever helps.

## Running another program and giving up on it if it hangs

**JS (this project's Node version):** `src/discover/gradle.js` shells out to the target
project's own `gradlew` using `child_process.spawn`, with a manually-managed timer that
calls `.kill()` on the child process if it doesn't finish in time.

**Go:** [`internal/discover/gradle.go`](internal/discover/gradle.go) does the equivalent
with two standard-library pieces that compose together:

```go
ctx, cancel := context.WithTimeout(context.Background(), gradleTimeout)
defer cancel()

cmd := exec.CommandContext(ctx, command, args...)
stdout, err := cmd.Output()
```

A `context.Context` is Go's general-purpose way to carry a deadline/cancellation signal
*through* a call chain — `context.WithTimeout` creates one that automatically fires after
`gradleTimeout` (5 minutes here) elapses. `exec.CommandContext` (as opposed to plain
`exec.Command`) ties a subprocess's lifetime to that context: if the timeout fires while
Gradle is still running, Go kills the process for you — no manual timer or `.kill()` call
to remember, and no risk of a leaked Gradle process lingering after this program moves on.
`defer cancel()` releases the context's internal timer resources as soon as
`resolveGradleProject` returns, whether it returned normally or via the timeout.

This pattern — a context carrying "how long am I willing to wait," handed to whatever
might block — is idiomatic Go for *any* operation with a deadline, not just subprocesses;
you'll see the same `context.Context` type show up if this project ever adds
cancellable/timeout-bound HTTP requests in `internal/trace/osv.go` too.

Two more pieces worth knowing about from the same file:

- `os.CreateTemp("", "cvetrace-init-*.gradle")` creates a temporary file with a unique
  name (Go substitutes `*` with random digits) — used here to write out a generated
  Gradle init script without colliding with a concurrent run of the same tool. Paired
  with `defer os.Remove(initScript.Name())` for cleanup, the same "acquire, defer the
  release right next to it" idiom as `defer resp.Body.Close()` above.
- `cmd.Output()` returns the subprocess's captured stdout directly, while a separate
  `bytes.Buffer` assigned to `cmd.Stderr` captures error output for a more useful error
  message if the command fails — Go's `exec.Cmd` treats stdout/stderr as plain
  `io.Writer` targets you wire up explicitly, rather than always inheriting the parent
  process's streams the way a naive `child_process.exec` callback bundles both together.

## Running and building

**JS:** `node bin/cvetrace.js scan .` runs the source directly, every time, needing
Node installed.

**Go:**
- `go run ./cmd/cvetrace scan .` compiles to a temporary binary and runs it in one step
  — closest to `node`, good for development.
- `go build -o cvetrace ./cmd/cvetrace` produces an actual standalone binary file you
  keep and run directly (`./cvetrace scan .`) — no `go` involved at all once built. This
  is the whole reason this port exists: that binary needs nothing else installed to run.
- `GOOS=windows GOARCH=amd64 go build ...` cross-compiles for a *different* OS/CPU than
  the one you're building on — no extra toolchain, no Docker, no building on each target
  OS separately, which is a big part of why Go was picked for this over C/C++.

## A real gotcha this project hit: flag ordering

Go's standard `flag` package stops looking for flags at the *first* non-flag
(positional) argument. `cvetrace scan --json test/my-project` works, but
`cvetrace scan test/my-project --json` would silently treat `--json` as a second,
unused positional argument instead of a flag — a real surprise coming from
commander.js (the Node version's CLI library), which accepts flags in any position.

`reorderFlagsFirst` in [`internal/cli/cli.go`](internal/cli/cli.go) works around this by
rearranging arguments (flags first, positionals after) before handing them to
`flag.Parse`. `internal/cli/cli_test.go` and `cmd/cvetrace/main_test.go` both test this
directly — it's exactly the kind of thing worth a regression test, since it's easy to
silently break again.

## Where to look next

Read the packages in this order — it mirrors the actual pipeline (discover → trace →
report) and each one builds on the last:

1. [`internal/discover/types.go`](internal/discover/types.go) — the simplest file in
   the project, just a struct definition. Start here.
2. [`internal/discover/node.go`](internal/discover/node.go) — JSON parsing, error
   handling, the zero-value pattern, and (its most involved part)
   `buildNodeScopeMap`/`bfsPredecessors`'s breadth-first graph walk over the lockfile's
   own dependency declarations -- see
   [No `null`/`undefined` — zero values instead](#no-nullundefined--zero-values-instead)
   above for why its predecessor map uses `*string` rather than plain `string`.
3. [`internal/discover/java.go`](internal/discover/java.go) — XML parsing, including
   the `,any` catch-all technique for `<properties>`'s arbitrarily-named children.
4. [`internal/discover/python.go`](internal/discover/python.go) — regexp-based
   best-effort parsing, and the `readIfExists` helper's `(value, ok, error)` pattern.
5. [`internal/discover/gradle.go`](internal/discover/gradle.go) — the most involved
   discoverer: actually running a subprocess (the target project's own Gradle wrapper)
   with a timeout, rather than just parsing a file. See
   [Running another program and giving up on it if it hangs](#running-another-program-and-giving-up-on-it-if-it-hangs)
   above before this one.
6. [`internal/discover/discover.go`](internal/discover/discover.go) — how all four
   discoverers above get dispatched during a single directory walk.
7. [`internal/trace/osv.go`](internal/trace/osv.go) — an HTTP client using only the
   standard library, more JSON structs.
8. [`internal/trace/resolve.go`](internal/trace/resolve.go) — the most involved file;
   read its doc comments carefully, especially `minimumFixedVersion` and `dedupeByCVE`
   (both fix real bugs found while building this project, documented right where the
   fix lives).
9. [`internal/cli/cli.go`](internal/cli/cli.go) — how it all gets wired into a runnable
   command.
