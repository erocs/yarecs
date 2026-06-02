//! Single-pass byte-level tokenizer for C-like source files and Python.
//!
//! The lexer is intentionally minimal: it only distinguishes tokens that the
//! downstream scope parser or engine need to interpret.  All other source text
//! collapses into [`TokenKind::Other`] so that no grammar knowledge is required.
//!
//! A single call to [`Lexer::tokenize`] produces a [`LexOutput`] that carries
//! three parallel views of the same byte stream:
//!  - `tokens`         – structural tokens for the scope PDA
//!  - `comment_ranges` – byte spans of every comment (for context annotation and comment-search)
//!  - `string_ranges`  – byte spans of every string/char literal (for code-gap computation)
//!
//! ## Python mode
//!
//! When `python_mode = true` (selected via [`Lexer::new`] from the language profile),
//! the lexer performs Python-style logical-line tracking and emits two extra token kinds:
//! [`TokenKind::Indent`] when indentation increases and [`TokenKind::Dedent`] when it
//! decreases.  It also emits a synthetic [`TokenKind::Semicolon`] at the end of each
//! logical line so that the scope parser can clear its header buffer between statements.
//! Indentation inside `( ) [ ] { }` is suppressed (implicit line continuation).

/// Tokens produced by the lexer.
/// We only track the distinctions the scope parser needs; everything else is `Other`.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// Identifier or keyword
    Word(String),
    /// `{`
    OpenBrace,
    /// `}`
    CloseBrace,
    /// `(`
    OpenParen,
    /// `)`
    CloseParen,
    /// `;`  – clears the header buffer in the scope parser
    Semicolon,
    /// `:` – kept for potential future use (inheritance, labels); used as scope
    /// delimiter in Python mode when it appears at bracket depth 0.
    Colon,
    /// Any quoted literal (single, double, raw, wide, Unicode prefixed)
    StringLiteral,
    /// `// …` or `/* … */`
    Comment,
    /// `# …` to end of logical line
    Preprocessor,
    /// Python only: indentation level increased (logical line start with deeper indent)
    Indent,
    /// Python only: indentation level decreased (zero-width token; one per popped level)
    Dedent,
    /// Anything else
    Other,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    /// Byte offset of the first byte of this token
    pub start: usize,
    /// Byte offset one past the last byte of this token
    pub end: usize,
    /// 1-based line number of the first byte
    pub line: u32,
}

/// Everything the rest of the pipeline needs from a single tokenization pass.
pub struct LexOutput {
    pub tokens: Vec<Token>,
    /// Byte ranges of `// …` and `/* … */` comments, sorted and non-overlapping.
    pub comment_ranges: Vec<std::ops::Range<usize>>,
    /// Byte ranges of string/char literals, sorted and non-overlapping.
    pub string_ranges: Vec<std::ops::Range<usize>>,
}

/// Stateful tokenizer.  Create with [`Lexer::new`] and consume with [`Lexer::tokenize`].
/// The tokenizer is destructive — it advances through the source byte-by-byte, so it
/// cannot be rewound; create a new instance to re-tokenize the same source.
pub struct Lexer<'src> {
    src: &'src [u8],
    pos: usize,
    line: u32,
    /// Python indentation tracking
    python_mode:  bool,
    indent_stack: Vec<usize>,  // column widths; 0 is always at the bottom
    paren_depth:  i32,         // ( ) [ ] { } depth — suppresses INDENT/DEDENT inside groupings
    at_line_start: bool,
}

impl<'src> Lexer<'src> {
    /// Create a new lexer.  Pass `python_mode = true` for `.py`/`.pyw`/`.pyi` files so
    /// that the lexer emits [`TokenKind::Indent`] / [`TokenKind::Dedent`] tokens and
    /// synthetic `Semicolon` tokens at logical-line boundaries.
    pub fn new(src: &'src str, python_mode: bool) -> Self {
        Lexer {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
            python_mode,
            indent_stack: if python_mode { vec![0] } else { Vec::new() },
            paren_depth: 0,
            at_line_start: python_mode, // first line treated as line-start
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = *self.src.get(self.pos)?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    // ── Python indentation helpers ────────────────────────────────────────────

    /// Count leading space/tab bytes from `self.pos` without consuming them.
    /// Tabs count as 1 column each (consistent indent comparison, not visual width).
    fn count_leading_whitespace(&self) -> usize {
        let mut count = 0;
        let mut p = self.pos;
        while p < self.src.len() {
            match self.src[p] {
                b' ' | b'\t' => { count += 1; p += 1; }
                _ => break,
            }
        }
        count
    }

    /// Return the first non-space/tab byte at or after `self.pos`.
    fn peek_after_whitespace(&self) -> Option<u8> {
        let mut p = self.pos;
        while p < self.src.len() {
            match self.src[p] {
                b' ' | b'\t' => p += 1,
                b => return Some(b),
            }
        }
        None
    }

    // ── Comment / string consumers ────────────────────────────────────────────

    /// Consume bytes to end of line after `//` has been consumed.
    fn skip_line_comment(&mut self) {
        while let Some(b) = self.advance() {
            if b == b'\n' {
                break;
            }
        }
    }

    /// Consume bytes up to and including `*/` after `/*` has been consumed.
    fn skip_block_comment(&mut self) {
        loop {
            match self.advance() {
                None => break,
                Some(b'*') if self.peek() == Some(b'/') => {
                    self.advance();
                    break;
                }
                _ => {}
            }
        }
    }

    /// Consume a Go backtick raw string up to the closing `` ` ``.
    /// Called after the opening backtick has been consumed.
    /// Unlike C-style strings there are no escape sequences — content is literal.
    fn skip_backtick_string(&mut self) {
        while let Some(b) = self.advance() {
            if b == b'`' { break; }
        }
    }

    /// Consume a quoted literal up to the matching unescaped `delim` byte (`"` or `'`).
    /// Called after the opening delimiter has already been consumed.
    fn skip_string(&mut self, delim: u8) {
        while let Some(b) = self.advance() {
            if b == b'\\' {
                self.advance(); // skip escaped char (handles \n, \", \\, etc.)
            } else if b == delim {
                break;
            }
        }
    }

    /// Consume a Python triple-quoted string up to the matching closing triple `delim`.
    /// Called after the three opening delimiters have already been consumed.
    /// Handles embedded escape sequences so `\"""` does not terminate a `"""`-string.
    fn skip_triple_string(&mut self, delim: u8) {
        loop {
            match self.advance() {
                None => break,
                Some(b'\\') => { self.advance(); }
                Some(b) if b == delim => {
                    if self.peek() == Some(delim) {
                        self.advance();
                        if self.peek() == Some(delim) { self.advance(); break; }
                    }
                }
                _ => {}
            }
        }
    }

    /// Consume a quoted literal after the opening delimiter byte has been consumed.
    /// Detects Python/JS triple-quote sequences (`"""` / `'''`) automatically.
    fn consume_quoted(&mut self, delim: u8) {
        if self.peek() == Some(delim) {
            self.advance();
            if self.peek() == Some(delim) {
                self.advance();
                self.skip_triple_string(delim);
            }
            // else: empty string literal (two delimiters back-to-back); done.
        } else {
            self.skip_string(delim);
        }
    }

    /// Skip a C++11 raw string `(rest-of-delim(...content...)delim")`.
    /// Call after consuming the opening `"`.
    fn skip_raw_string(&mut self) {
        // Collect the custom delimiter (bytes up to the `(`)
        let delim_start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'(' {
                break;
            }
            self.advance();
        }
        let raw_delim: Vec<u8> = self.src[delim_start..self.pos].to_vec();
        self.advance(); // consume `(`

        // Build the closing marker: `)` + delim + `"`
        let mut close: Vec<u8> = vec![b')'];
        close.extend_from_slice(&raw_delim);
        close.push(b'"');

        loop {
            match self.advance() {
                None => break,
                Some(b')') => {
                    if self.src[self.pos..].starts_with(&close[1..]) {
                        for _ in 0..close.len() - 1 {
                            self.advance();
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    /// Consume a preprocessor directive to end of its logical line, respecting
    /// `\`-continuations so multi-line `#define` macros are consumed in full.
    fn skip_preprocessor(&mut self) {
        loop {
            match self.advance() {
                None => break,
                Some(b'\\') => {
                    // Line continuation
                    if self.peek() == Some(b'\r') { self.advance(); }
                    if self.peek() == Some(b'\n') { self.advance(); }
                }
                Some(b'\n') => break,
                _ => {}
            }
        }
    }

    /// Read an identifier/keyword starting with `first` (already consumed).
    fn read_word(&mut self, first: u8) -> String {
        let mut word = String::with_capacity(16);
        word.push(first as char);
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                word.push(b as char);
                self.advance();
            } else {
                break;
            }
        }
        word
    }

    /// Consume the source and produce a [`LexOutput`].
    ///
    /// Comment and string byte ranges are collected in this same pass so that the
    /// engine can later classify match positions and compute code-only gaps without
    /// re-scanning the file.
    pub fn tokenize(mut self) -> LexOutput {
        let mut tokens = Vec::new();
        let mut comment_ranges: Vec<std::ops::Range<usize>> = Vec::new();
        let mut string_ranges: Vec<std::ops::Range<usize>> = Vec::new();

        while let Some(b) = self.peek() {
            // ── Python: emit INDENT / DEDENT at the start of each logical line ────
            if self.python_mode && self.at_line_start && self.paren_depth == 0 {
                self.at_line_start = false;
                let col = self.count_leading_whitespace();
                let sig = self.peek_after_whitespace();
                // Blank lines and comment-only lines do not affect the indent stack.
                if !matches!(sig, None | Some(b'\n') | Some(b'\r') | Some(b'#')) {
                    let top = *self.indent_stack.last().unwrap_or(&0);
                    let pos = self.pos;
                    let ln  = self.line;
                    if col > top {
                        self.indent_stack.push(col);
                        tokens.push(Token { kind: TokenKind::Indent, start: pos, end: pos, line: ln });
                    } else if col < top {
                        while self.indent_stack.len() > 1
                            && *self.indent_stack.last().unwrap() > col
                        {
                            self.indent_stack.pop();
                            tokens.push(Token { kind: TokenKind::Dedent, start: pos, end: pos, line: ln });
                        }
                    }
                    // col == top: same level, no token — header was already cleared by
                    // the Semicolon emitted on the previous newline.
                }
                // fall through: leading whitespace consumed by the normal skip below
            }
            // ─────────────────────────────────────────────────────────────────────

            // Whitespace handling (with Python newline → Semicolon)
            if b.is_ascii_whitespace() {
                if b == b'\n' && self.python_mode && self.paren_depth == 0 {
                    // Logical line end: emit a Semicolon so the parser clears its header.
                    let pos = self.pos;
                    let ln  = self.line;
                    self.advance(); // consume '\n'; increments self.line
                    tokens.push(Token { kind: TokenKind::Semicolon, start: pos, end: pos + 1, line: ln });
                    self.at_line_start = true;
                    continue;
                }
                self.advance();
                continue;
            }

            let start = self.pos;
            let line  = self.line;

            let kind = match b {
                b'{' => {
                    self.advance();
                    if self.python_mode { self.paren_depth += 1; }
                    TokenKind::OpenBrace
                }
                b'}' => {
                    self.advance();
                    if self.python_mode && self.paren_depth > 0 { self.paren_depth -= 1; }
                    TokenKind::CloseBrace
                }
                b'(' => {
                    self.advance();
                    if self.python_mode { self.paren_depth += 1; }
                    TokenKind::OpenParen
                }
                b')' => {
                    self.advance();
                    if self.python_mode && self.paren_depth > 0 { self.paren_depth -= 1; }
                    TokenKind::CloseParen
                }
                b';' => { self.advance(); TokenKind::Semicolon }
                b':' => { self.advance(); TokenKind::Colon }

                // Python: track [ ] for implicit line-continuation suppression.
                // They remain Other tokens for the scope parser.
                b'[' if self.python_mode => {
                    self.advance();
                    self.paren_depth += 1;
                    TokenKind::Other
                }
                b']' if self.python_mode => {
                    self.advance();
                    if self.paren_depth > 0 { self.paren_depth -= 1; }
                    TokenKind::Other
                }

                b'/' => {
                    self.advance();
                    match self.peek() {
                        Some(b'/') => { self.advance(); self.skip_line_comment(); TokenKind::Comment }
                        Some(b'*') => { self.advance(); self.skip_block_comment(); TokenKind::Comment }
                        _ => TokenKind::Other
                    }
                }

                b'"'  => { self.advance(); self.consume_quoted(b'"');  TokenKind::StringLiteral }
                b'\'' => { self.advance(); self.consume_quoted(b'\''); TokenKind::StringLiteral }
                b'`'  => { self.advance(); self.skip_backtick_string(); TokenKind::StringLiteral }

                b'#' => { self.advance(); self.skip_preprocessor(); TokenKind::Preprocessor }

                b if b.is_ascii_alphabetic() || b == b'_' => {
                    self.advance();
                    let word = self.read_word(b);
                    self.classify_word(word)
                }

                _ => { self.advance(); TokenKind::Other }
            };

            let end = self.pos;
            match &kind {
                TokenKind::Comment       => comment_ranges.push(start..end),
                TokenKind::StringLiteral => string_ranges.push(start..end),
                _ => {}
            }
            tokens.push(Token { kind, start, end, line });
        }

        // Python: drain remaining open indentation levels at EOF
        if self.python_mode && self.indent_stack.len() > 1 {
            let (pos, ln) = (self.pos, self.line);
            while self.indent_stack.len() > 1 {
                self.indent_stack.pop();
                tokens.push(Token { kind: TokenKind::Dedent, start: pos, end: pos, line: ln });
            }
        }

        LexOutput { tokens, comment_ranges, string_ranges }
    }

    /// After reading a word, check whether it's a string literal prefix
    /// (`R`, `L`, `u`, `U`, `u8`, `LR`, `uR`, `UR`, `u8R`).
    fn classify_word(&mut self, word: String) -> TokenKind {
        // Raw string prefixes (C++11)
        let is_raw = matches!(word.as_str(), "R" | "LR" | "uR" | "UR" | "u8R");
        if is_raw && self.peek() == Some(b'"') {
            self.advance(); // consume the `"`
            self.skip_raw_string();
            return TokenKind::StringLiteral;
        }

        // Ordinary C/C++ string/char prefixes (`L"..."`, `u"..."`, `U"..."`, `u8"..."`)
        let is_str_prefix = matches!(word.as_str(), "L" | "u" | "U" | "u8");
        if is_str_prefix {
            match self.peek() {
                Some(b'"') => { self.advance(); self.consume_quoted(b'"'); return TokenKind::StringLiteral; }
                Some(b'\'') => { self.advance(); self.consume_quoted(b'\''); return TokenKind::StringLiteral; }
                _ => {}
            }
        }

        // Python string prefixes: b/B (bytes), f/F (f-string), r (raw), and combinations.
        // Uppercase R is already handled above as a C++ raw-string prefix; only lowercase r
        // is added here so the two don't collide.
        let is_py_prefix = matches!(
            word.as_str(),
            "b"  | "B"  | "f"  | "F"  | "r"
            | "rb" | "rB" | "Rb" | "RB"
            | "br" | "bR" | "Br" | "BR"
            | "rf" | "rF" | "Rf" | "RF"
            | "fr" | "fR" | "Fr" | "FR"
        );
        if is_py_prefix {
            match self.peek() {
                Some(b'"')  => { self.advance(); self.consume_quoted(b'"');  return TokenKind::StringLiteral; }
                Some(b'\'') => { self.advance(); self.consume_quoted(b'\''); return TokenKind::StringLiteral; }
                _ => {}
            }
        }

        TokenKind::Word(word)
    }
}
