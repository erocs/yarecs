# yarecs

A scope-aware regex scanner for C-like languages. Rules are matched against source code with awareness of the enclosing scope hierarchy (namespace → class → method), so you can write rules that only fire inside specific contexts — or that require a related pattern to appear (or be absent) elsewhere in the same method, class, or namespace.

## Build

```sh
cargo build --release
# binary at target/release/yarecs
```

## Quick start

```sh
yarecs --config rules/c_cpp_security.toml src/
yarecs --config rules/unreal_engine5.toml --extensions h,cpp Source/
yarecs --config rules/java_security.toml --config rules/generic_secrets.toml --extensions java src/
```

## CLI reference

```
yarecs [OPTIONS] <PATHS>...
```

| Flag | Default | Description |
|---|---|---|
| `-c, --config <FILE>` | `rules.toml` | Rule file (TOML). Repeatable — rules from all files are merged in order. |
| `-e, --extensions <LIST>` | `c,cpp,cc,cxx,h,hpp,hh,cs,java,go,rs,kt,kts,swift` | Comma-separated file extensions to scan. |
| `-f, --format <FORMAT>` | `text` | Output format: `text`, `json`, `csv`, `sarif`. |
| `-o, --output <FILE>` | *(stdout)* | Write results to a file instead of stdout. Progress and summary always go to stderr. |
| `--dump-scopes` | — | Print the parsed scope tree for each file (useful when writing rules). |

**Exit code:** `0` if no errors, `1` if any `severity = "error"` matches are found.

## Rule syntax

Rules are defined in TOML files as an array of `[[rules]]` tables.

```toml
[[rules]]
name     = "no_raw_new"           # unique identifier
pattern  = "\\bnew\\s+\\w+"       # ripgrep-compatible regex
scope    = "**::*::*"             # optional scope filter (default: all scopes)
search   = "code"                 # optional: "code" | "comments" | "all"
severity = "warning"              # "error" | "warning" | "info"
message  = "Prefer smart pointers over raw 'new'"
```

### Scope filters

Scopes are named by the identifier in their declaration header and chained with `::`.

| Filter | Matches |
|---|---|
| `**` | Everywhere (all scopes including file root) |
| `**::*` | Any single named scope at any depth (e.g. any function) |
| `**::*::*` | Any scope two levels deep (e.g. method inside class) |
| `**::MyClass::*` | Any method inside a class named `MyClass` |
| `Foo::Bar::baz` | Exactly `namespace Foo { class Bar { void baz() } }` |

### Search target

| Value | Behaviour |
|---|---|
| `code` *(default)* | Searches only code — skips comment and string literal ranges. |
| `comments` | Searches only `//` and `/* */` comment ranges. |
| `all` | Searches the entire scope body; annotates each match as code, `{in comment}`, or `{in string}`. |

### Chain conditions

A `chain` entry adds a secondary pattern that must satisfy a relationship to the primary match for the rule to fire. All entries in the chain must be satisfied (AND semantics). Add `negate = true` to invert a condition (fires when the pattern is *absent*).

```toml
[[rules]]
name    = "server_rpc_no_validation"
pattern = 'UFUNCTION\s*\([^)]*\bServer\b'
scope   = "**"
severity = "error"
message  = "Server RPC missing WithValidation"
chain   = [
    { pattern = "WithValidation", relationship = "anywhere_in_statement", negate = true },
]
```

| Relationship | Search range |
|---|---|
| `after` | From the trigger match to the end of the current scope body |
| `before` | From the start of the current scope body to the trigger match |
| `anywhere_in_method` | The entire body of the nearest enclosing function/method |
| `anywhere_in_class` | The entire body of the nearest enclosing class/struct |
| `anywhere_in_namespace` | The entire body of the nearest enclosing namespace |
| `anywhere_in_statement` | The single statement containing the trigger (bounded by `;`, `{`, `}`, skipping those inside comments or strings) |

### Example rule file

```toml
# Forbid raw new inside methods
[[rules]]
name     = "no_raw_new"
pattern  = "\\bnew\\s+\\w+"
scope    = "**::*::*"
severity = "warning"
message  = "Prefer smart pointers over raw 'new'"

# Flag lock() only when unlock() follows it in the same method
[[rules]]
name     = "lock_without_unlock"
pattern  = "\\block\\s*\\("
scope    = "**"
severity = "warning"
message  = "lock() with no subsequent unlock() in this method"
chain    = [
    { pattern = "\\bunlock\\s*\\(", relationship = "after", negate = true },
]

# Flag dangerous calls that have been commented out
[[rules]]
name     = "commented_out_delete"
pattern  = "\\bdelete\\b|\\bfree\\s*\\("
search   = "comments"
severity = "info"
message  = "Dangerous call is commented out — verify it stays that way"
```

## Bundled rulesets

| File | Languages | Rules | Description |
|---|---|---|---|
| `rules/c_cpp_security.toml` | C, C++ | 38 | Memory safety, dangerous functions, TOCTOU, crypto, privesc |
| `rules/unreal_engine5.toml` | C++ (UE5) | 13 | RPC validation, path traversal, sockets, asset loading |
| `rules/csharp_security.toml` | C# | 30 | Crypto, deserialization, XXE, JWT, XSS, ReDoS, SSRF |
| `rules/java_security.toml` | Java | 31 | Crypto, deserialization, SSL/TLS, XXE, command injection |
| `rules/go_security.toml` | Go | 30 | Crypto, TLS, unsafe, JWT, cookies, CGI, process execution |
| `rules/kotlin_security.toml` | Kotlin | 12 | Crypto, network, cookies, command injection |
| `rules/rust_security.toml` | Rust | 10 | TLS, unsafe, process, temp files |
| `rules/generic_secrets.toml` | Any | 40 | Hardcoded credentials, API keys, private keys, Trojan Source |

`generic_secrets.toml` is designed to be layered alongside any language ruleset:

```sh
yarecs --config rules/c_cpp_security.toml \
       --config rules/generic_secrets.toml \
       src/
```

## Output formats

**Text** (default) — human-readable, one match per line:
```
src/auth.cpp:42  [error]   c_gets  gets() — no bounds checking; use fgets() or gets_s()
  gets(buf);
```

**JSON** — array of match objects, suitable for tooling integration.

**CSV** — spreadsheet-friendly; one row per match with file, line, rule, severity, message, snippet columns.

**SARIF** — Static Analysis Results Interchange Format v2.1.0; compatible with GitHub Code Scanning, VS Code SARIF Viewer, and Azure DevOps.

```sh
yarecs --config rules/c_cpp_security.toml --format sarif --output results.sarif src/
```

## Supported languages

| Language | Extensions | Notes |
|---|---|---|
| C / C++ | `c cpp cc cxx h hpp hh` | Default profile |
| C# | `cs` | |
| Java | `java` | |
| Go | `go` | `type Name struct {}` name-before-keyword; backtick raw strings |
| Rust | `rs` | `mod`, `impl`, `trait`, `fn` |
| Kotlin | `kt kts` | Semicolon-free; control-flow misclassification guard active |
| Swift | `swift` | Semicolon-free |

## Scope tree debugging

When writing new rules, use `--dump-scopes` to inspect how yarecs parses a file:

```sh
yarecs --dump-scopes src/MyActor.cpp
```

```
File []
  Namespace [MyApp]
    Class [Widget]
      Function [render]
      Function [safe_render]
    Class [Engine]
      Function [run]
```

The scope path used in filters is the chain of bracket labels joined by `::`, e.g. `MyApp::Widget::render`.
