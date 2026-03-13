//! Pushdown-automaton scope parser.
//!
//! Consumes the flat [`Token`] stream from the lexer and builds a [`ScopeNode`] tree
//! that mirrors the brace nesting of the source file.  Each `{…}` pair becomes a node;
//! the node's kind and name are determined by examining the token sequence that
//! precedes the `{` (the *header*) via [`classify_header`].
//!
//! ## Language profiles
//!
//! Each supported language family gets a [`LanguageProfile`] that describes which
//! keywords introduce named scopes and which are control-flow.  [`profile_for_ext`]
//! selects the right profile from a file extension.  C/C++ is the default.
//! Adding a new language requires only a new `static` profile — the PDA itself
//! is language-agnostic.
//!
//! Design constraints:
//! - No full grammar — only enough to distinguish namespaces, classes/structs/unions,
//!   enums, functions, and anonymous/control-flow blocks.
//! - Comments, strings, and preprocessor directives are invisible to the PDA because
//!   the lexer already consumed their internal braces and parentheses.
//! - Malformed input (unbalanced braces) is silently recovered: unclosed frames are
//!   closed at EOF, and stray `}` at the root level are absorbed.

use crate::lexer::{Token, TokenKind};

// ---------------------------------------------------------------------------
// Scope types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ScopeKind {
    /// Root of the file – virtual, not a real brace pair
    File,
    Namespace,
    Class,
    Struct,
    Enum,
    Union,
    Interface,
    Function,
    /// Anonymous / control-flow block (if/for/while/try/…)
    Block,
}

impl ScopeKind {
    /// Returns `true` for scope kinds that carry a meaningful name and should
    /// appear in scope paths.  `File` and anonymous `Block` scopes are excluded
    /// because they have no identifier to contribute to the path.
    pub fn is_named(&self) -> bool {
        !matches!(self, ScopeKind::File | ScopeKind::Block)
    }
}

impl std::fmt::Display for ScopeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeKind::File      => write!(f, "file"),
            ScopeKind::Namespace => write!(f, "namespace"),
            ScopeKind::Class     => write!(f, "class"),
            ScopeKind::Struct    => write!(f, "struct"),
            ScopeKind::Enum      => write!(f, "enum"),
            ScopeKind::Union     => write!(f, "union"),
            ScopeKind::Interface => write!(f, "interface"),
            ScopeKind::Function  => write!(f, "fn"),
            ScopeKind::Block     => write!(f, "block"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeNode {
    pub kind: ScopeKind,
    /// Empty for anonymous / file-root scopes
    pub name: String,
    /// Byte offset of the opening `{`
    pub body_start: usize,
    /// Byte offset of the closing `}`
    pub body_end: usize,
    /// 1-based line of `{`
    pub start_line: u32,
    /// 1-based line of `}`
    pub end_line: u32,
    pub children: Vec<ScopeNode>,
}

impl ScopeNode {
    /// Byte range of the contents between `{` and `}` (exclusive of the braces).
    ///
    /// For the virtual `File` root there is no `{`, so the range starts at 0.
    pub fn body_range(&self) -> std::ops::Range<usize> {
        if self.kind == ScopeKind::File {
            self.body_start..self.body_end
        } else {
            self.body_start + 1..self.body_end
        }
    }
}

// ---------------------------------------------------------------------------
// Language profiles
// ---------------------------------------------------------------------------

/// Control-flow keywords that open anonymous blocks in most C-family languages.
///
/// `case` and `default` are intentionally omitted: switch labels don't use `(` so
/// the function heuristic already returns Block for them naturally, and including
/// them would misclassify Java/C# `default void method()` interface implementations.
const CONTROL_FLOW_COMMON: &[&str] = &[
    "if", "else", "for", "while", "do", "switch",
    "try", "catch",
];

/// Extended control-flow list for C and C++ (adds MSVC/GCC compiler extensions).
const CONTROL_FLOW_C: &[&str] = &[
    "if", "else", "for", "while", "do", "switch",
    "try", "catch", "case", "default",
    "__try", "__except", "__finally",
    "__attribute__", "__declspec",
];

/// Control-flow keywords for Go (no parentheses around conditions; `select` is Go-specific).
const CONTROL_FLOW_GO: &[&str] = &[
    "if", "else", "for", "switch", "select",
];

/// Control-flow keywords for Swift (`guard`/`defer`/`repeat` are Swift-specific).
const CONTROL_FLOW_SWIFT: &[&str] = &[
    "if", "else", "for", "while", "repeat", "switch", "guard", "defer", "do", "catch",
];

/// Control-flow keywords for Kotlin (`when` is the Kotlin pattern-match keyword).
const CONTROL_FLOW_KOTLIN: &[&str] = &[
    "if", "else", "for", "while", "do", "when", "try", "catch",
];

/// Per-language description of which keywords introduce named scopes and functions.
///
/// All profiles share the same PDA logic; only the keyword tables differ.
/// `enum` is handled universally (see [`classify_header`]) because `enum class`/
/// `enum struct` require consuming an extra word, which needs special-case logic.
pub struct LanguageProfile {
    /// Keywords that introduce named, brace-delimited scopes other than functions.
    /// Each entry maps a keyword to a [`ScopeKind`].
    ///
    /// **Name resolution**: the word immediately *after* the keyword is taken as the
    /// scope name.  If no word follows (Go-style `type Name struct { }`), the word
    /// immediately *before* the keyword is used instead.
    pub scope_keywords: &'static [(&'static str, ScopeKind)],

    /// Keywords that introduce a function or method scope (e.g. `func`, `fn`, `fun`).
    ///
    /// When matched, [`find_fn_name_after`] scans the remaining header tokens for the
    /// name, automatically skipping a Go-style receiver `(…)` if present.
    /// Languages that use the C-style heuristic (last word before the first `(`)
    /// leave this slice empty.
    pub fn_keywords: &'static [&'static str],

    /// Keywords that open anonymous control-flow blocks.  If the first word of a
    /// header matches one of these the scope is classified as [`ScopeKind::Block`].
    pub control_flow: &'static [&'static str],
}

// C and C++ (also used as the fallback for unknown extensions)
pub static PROFILE_C: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("namespace", ScopeKind::Namespace),
        ("class",     ScopeKind::Class),
        ("struct",    ScopeKind::Struct),
        ("union",     ScopeKind::Union),
        ("interface", ScopeKind::Interface),
    ],
    fn_keywords:  &[],
    control_flow: CONTROL_FLOW_C,
};

// C# — same as C/C++ but adds `record` (C# 9+) and drops `union`
pub static PROFILE_CSHARP: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("namespace", ScopeKind::Namespace),
        ("class",     ScopeKind::Class),
        ("struct",    ScopeKind::Struct),
        ("interface", ScopeKind::Interface),
        ("enum",      ScopeKind::Enum),
        ("record",    ScopeKind::Class),
    ],
    fn_keywords:  &[],
    control_flow: CONTROL_FLOW_COMMON,
};

// Java — no namespaces (package is a directive, not a brace scope)
pub static PROFILE_JAVA: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("class",     ScopeKind::Class),
        ("interface", ScopeKind::Interface),
        ("enum",      ScopeKind::Enum),
    ],
    fn_keywords:  &[],
    control_flow: CONTROL_FLOW_COMMON,
};

// Go — structs/interfaces use `type Name keyword { }` order (name before keyword)
pub static PROFILE_GO: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("struct",    ScopeKind::Struct),
        ("interface", ScopeKind::Interface),
    ],
    fn_keywords:  &["func"],
    control_flow: CONTROL_FLOW_GO,
};

// Rust — `mod` ≈ namespace, `impl`/`trait` ≈ class-like, `fn` introduces functions
pub static PROFILE_RUST: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("mod",   ScopeKind::Namespace),
        ("impl",  ScopeKind::Class),
        ("trait", ScopeKind::Interface),
        ("struct", ScopeKind::Struct),
        ("enum",  ScopeKind::Enum),
        ("union", ScopeKind::Union),
    ],
    fn_keywords:  &["fn"],
    control_flow: CONTROL_FLOW_COMMON,
};

// Kotlin — `object` declarations behave like singleton classes
pub static PROFILE_KOTLIN: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("class",     ScopeKind::Class),
        ("interface", ScopeKind::Interface),
        ("object",    ScopeKind::Class),
        ("enum",      ScopeKind::Enum),
    ],
    fn_keywords:  &["fun"],
    control_flow: CONTROL_FLOW_KOTLIN,
};

// Swift — `extension` lets you add methods to existing types outside their definition
pub static PROFILE_SWIFT: LanguageProfile = LanguageProfile {
    scope_keywords: &[
        ("class",     ScopeKind::Class),
        ("struct",    ScopeKind::Struct),
        ("enum",      ScopeKind::Enum),
        ("protocol",  ScopeKind::Interface),
        ("extension", ScopeKind::Class),
    ],
    fn_keywords:  &["func"],
    control_flow: CONTROL_FLOW_SWIFT,
};

/// Select the language profile for a given file extension.
/// Falls back to [`PROFILE_C`] for any unrecognised extension.
pub fn profile_for_ext(ext: &str) -> &'static LanguageProfile {
    match ext {
        "cs"           => &PROFILE_CSHARP,
        "java"         => &PROFILE_JAVA,
        "go"           => &PROFILE_GO,
        "rs"           => &PROFILE_RUST,
        "kt" | "kts"   => &PROFILE_KOTLIN,
        "swift"        => &PROFILE_SWIFT,
        _              => &PROFILE_C,
    }
}

// ---------------------------------------------------------------------------
// Header classification
// ---------------------------------------------------------------------------

/// Examine the token sequence collected since the last block delimiter and
/// decide what kind of scope is being opened, plus its name.
///
/// Classification priority (first match wins):
/// 1. `enum` — universal special case to handle C++ `enum class`/`enum struct`
/// 2. Profile scope keyword (`namespace`, `class`, `struct`, `mod`, `impl`, …)
/// 3. Profile fn keyword (`func`, `fn`, `fun`) — name resolved via [`find_fn_name_after`]
/// 4. Control-flow keyword as first word → anonymous [`ScopeKind::Block`]
/// 5. C-style heuristic: last word before the first top-level `(` → [`ScopeKind::Function`]
/// 6. Fallback → anonymous [`ScopeKind::Block`]
fn classify_header(header: &[Token], profile: &LanguageProfile) -> (ScopeKind, String) {
    if header.is_empty() {
        return (ScopeKind::Block, String::new());
    }

    // Collect just the Word tokens for keyword scanning
    let words: Vec<&str> = header
        .iter()
        .filter_map(|t| {
            if let TokenKind::Word(w) = &t.kind { Some(w.as_str()) } else { None }
        })
        .collect();

    if words.is_empty() {
        return (ScopeKind::Block, String::new());
    }

    // Scan for scope keywords (first match wins).
    for (i, &w) in words.iter().enumerate() {
        match w {
            // `enum` is handled universally because C++ `enum class`/`enum struct`
            // need to consume one extra word to find the real name.
            "enum" => {
                let next = words.get(i + 1).copied().unwrap_or("");
                if next == "class" || next == "struct" {
                    let name = words.get(i + 2).copied().unwrap_or("").to_string();
                    return (ScopeKind::Enum, name);
                }
                return (ScopeKind::Enum, next.to_string());
            }
            kw => {
                if let Some((_, kind)) = profile.scope_keywords.iter().find(|(k, _)| *k == kw) {
                    // Normal case: name follows the keyword  (`class Foo`, `mod bar`)
                    let name_after = words.get(i + 1).copied().unwrap_or("");
                    // Go-style fallback: `type Name struct { }` — name *precedes* keyword
                    let name = if name_after.is_empty() && i > 0 {
                        words[i - 1].to_string()
                    } else {
                        name_after.to_string()
                    };
                    return (kind.clone(), name);
                }
            }
        }
    }

    // Check for fn keywords (func / fn / fun / …).  These are scanned against the
    // full token list (not just words) so that find_fn_name_after can skip receivers.
    for (i, token) in header.iter().enumerate() {
        if let TokenKind::Word(w) = &token.kind {
            if profile.fn_keywords.contains(&w.as_str()) {
                return (ScopeKind::Function, find_fn_name_after(&header[i + 1..]));
            }
        }
    }

    // Control-flow check: any word in the header is a control keyword → anonymous block.
    //
    // Checking only `words[0]` was insufficient for languages without mandatory
    // semicolons (Kotlin, Swift, Go).  In those languages the header accumulates
    // all tokens since the previous `{` or `}`, which may include several complete
    // statements.  The C/C++ heuristic below would then fire on an incidental
    // call like `MessageDigest.getInstance(…)` before ever seeing the `for`/`if`
    // keyword at the end of the header.  Checking any word fixes that:
    //   `val md: MessageDigest = … getInstance("SHA-1")  for (b in xs)`
    //   → `for` found anywhere → Block  ✓
    //
    // Steps 1 (scope keywords) and 2 (fn keywords) already returned early for
    // valid class/function declarations, so no real declaration header reaches here
    // with a control keyword embedded in it.
    if words.iter().any(|&w| profile.control_flow.contains(&w)) {
        return (ScopeKind::Block, String::new());
    }

    // C/C++ function signature heuristic: the last Word before the first `(` at
    // paren depth 0 is the function name.  Languages that use explicit fn_keywords
    // never reach this branch for normal function declarations.
    let mut paren_depth: i32 = 0;
    let mut func_name = String::new();

    for token in header {
        match &token.kind {
            TokenKind::OpenParen => {
                if paren_depth == 0 {
                    if func_name.is_empty() || profile.control_flow.contains(&func_name.as_str()) {
                        return (ScopeKind::Block, String::new());
                    }
                    return (ScopeKind::Function, func_name);
                }
                paren_depth += 1;
            }
            TokenKind::CloseParen => {
                if paren_depth > 0 { paren_depth -= 1; }
            }
            TokenKind::Word(w) if paren_depth == 0 => {
                func_name = w.clone();
            }
            _ => {}
        }
    }

    (ScopeKind::Block, String::new())
}

/// Scan tokens that follow a fn keyword and return the function name.
///
/// Handles Go-style receiver parameters: if the first significant token is `(`,
/// the entire `(…)` group is consumed and the name is the next `Word` after it.
/// For `fn name(…)` and `fun name(…)` the first `Word` is the name directly.
fn find_fn_name_after(tokens: &[Token]) -> String {
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i].kind {
            TokenKind::OpenParen => {
                // Receiver group — skip to the matching close paren, then continue
                let mut depth = 1usize;
                i += 1;
                while i < tokens.len() && depth > 0 {
                    match tokens[i].kind {
                        TokenKind::OpenParen  => depth += 1,
                        TokenKind::CloseParen => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                // Name word (if any) comes after the closing paren; loop continues
            }
            TokenKind::Word(w) => return w.clone(),
            _ => { i += 1; }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// PDA-based scope parser
// ---------------------------------------------------------------------------

struct ScopeFrame {
    kind: ScopeKind,
    name: String,
    body_start: usize,
    start_line: u32,
    children: Vec<ScopeNode>,
}

/// Parses a flat token stream into a `ScopeNode` tree using a pushdown automaton.
pub struct ScopeParser {
    /// Language-specific keyword tables; selected once per file from the extension.
    profile: &'static LanguageProfile,
    stack: Vec<ScopeFrame>,
    /// Tokens accumulated since the last block delimiter (`{`, `}`) or `;`
    header: Vec<Token>,
    header_start: usize,
}

impl ScopeParser {
    pub fn new(profile: &'static LanguageProfile) -> Self {
        ScopeParser {
            profile,
            stack: Vec::new(),
            header: Vec::new(),
            header_start: 0,
        }
    }

    /// Parse a flat token stream into a [`ScopeNode`] tree.
    ///
    /// `source_len` is the byte length of the original source string; it is used to
    /// set `body_end` on any frames that remain open when the token stream is exhausted
    /// (i.e., syntactically unclosed braces are closed at EOF).
    pub fn parse(mut self, tokens: &[Token], source_len: usize) -> ScopeNode {
        // Seed the stack with a virtual file-root frame
        self.stack.push(ScopeFrame {
            kind: ScopeKind::File,
            name: String::new(),
            body_start: 0,
            start_line: 1,
            children: Vec::new(),
        });

        for token in tokens {
            match &token.kind {
                // These tokens are invisible to the scope structure
                TokenKind::Comment | TokenKind::Preprocessor | TokenKind::StringLiteral => {}

                TokenKind::Semicolon => {
                    self.header.clear();
                    self.header_start = token.end;
                }

                TokenKind::OpenBrace => {
                    let (kind, name) = classify_header(&self.header, self.profile);

                    self.stack.push(ScopeFrame {
                        kind,
                        name,
                        body_start: token.start,
                        start_line: token.line,
                        children: Vec::new(),
                    });

                    self.header.clear();
                    self.header_start = token.end;
                }

                TokenKind::CloseBrace => {
                    if self.stack.len() > 1 {
                        let frame = self.stack.pop().unwrap();
                        let node = ScopeNode {
                            kind: frame.kind,
                            name: frame.name,
                            body_start: frame.body_start,
                            body_end: token.start,
                            start_line: frame.start_line,
                            end_line: token.line,
                            children: frame.children,
                        };
                        self.stack.last_mut().unwrap().children.push(node);
                    }
                    // Unbalanced `}` at stack depth 1 is silently absorbed

                    self.header.clear();
                    self.header_start = token.end;
                }

                _ => {
                    if self.header.is_empty() {
                        self.header_start = token.start;
                    }
                    self.header.push(token.clone());
                }
            }
        }

        // Recover from unclosed braces (malformed input)
        while self.stack.len() > 1 {
            let frame = self.stack.pop().unwrap();
            let node = ScopeNode {
                kind: frame.kind,
                name: frame.name,
                body_start: frame.body_start,
                body_end: source_len,
                start_line: frame.start_line,
                end_line: 0,
                children: frame.children,
            };
            self.stack.last_mut().unwrap().children.push(node);
        }

        let root = self.stack.pop().unwrap();
        ScopeNode {
            kind: ScopeKind::File,
            name: String::new(),
            body_start: 0,
            body_end: source_len,
            start_line: 1,
            end_line: 0,
            children: root.children,
        }
    }
}

// ---------------------------------------------------------------------------
// Debug display
// ---------------------------------------------------------------------------

/// Recursively print the scope tree to stderr, indented by depth.
/// Used by `--dump-scopes` to let rule authors inspect how a file was parsed.
pub fn print_scope_tree(node: &ScopeNode, depth: usize) {
    let indent = "  ".repeat(depth);
    let name = if node.name.is_empty() { "<anon>".to_string() } else { node.name.clone() };
    eprintln!(
        "{}[{}] {:?} (bytes {}..{}, lines {}..{})",
        indent, node.kind, name,
        node.body_start, node.body_end,
        node.start_line, node.end_line,
    );
    for child in &node.children {
        print_scope_tree(child, depth + 1);
    }
}
