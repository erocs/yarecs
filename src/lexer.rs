//! Single-pass byte-level tokenizer for C-like source files.
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
    /// `:` – kept for potential future use (inheritance, labels)
    Colon,
    /// Any quoted literal (single, double, raw, wide, Unicode prefixed)
    StringLiteral,
    /// `// …` or `/* … */`
    Comment,
    /// `# …` to end of logical line
    Preprocessor,
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
}

impl<'src> Lexer<'src> {
    pub fn new(src: &'src str) -> Self {
        Lexer { src: src.as_bytes(), pos: 0, line: 1 }
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
            // Skip whitespace without producing tokens
            if b.is_ascii_whitespace() {
                self.advance();
                continue;
            }

            let start = self.pos;
            let line = self.line;

            let kind = match b {
                b'{' => { self.advance(); TokenKind::OpenBrace }
                b'}' => { self.advance(); TokenKind::CloseBrace }
                b'(' => { self.advance(); TokenKind::OpenParen }
                b')' => { self.advance(); TokenKind::CloseParen }
                b';' => { self.advance(); TokenKind::Semicolon }
                b':' => { self.advance(); TokenKind::Colon }

                b'/' => {
                    self.advance();
                    match self.peek() {
                        Some(b'/') => { self.advance(); self.skip_line_comment(); TokenKind::Comment }
                        Some(b'*') => { self.advance(); self.skip_block_comment(); TokenKind::Comment }
                        _ => TokenKind::Other
                    }
                }

                b'"'  => { self.advance(); self.skip_string(b'"');   TokenKind::StringLiteral }
                b'\'' => { self.advance(); self.skip_string(b'\''); TokenKind::StringLiteral }
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

        LexOutput { tokens, comment_ranges, string_ranges }
    }

    /// After reading a word, check whether it's a string literal prefix
    /// (`R`, `L`, `u`, `U`, `u8`, `LR`, `uR`, `UR`, `u8R`).
    fn classify_word(&mut self, word: String) -> TokenKind {
        // Raw string prefixes
        let is_raw = matches!(word.as_str(), "R" | "LR" | "uR" | "UR" | "u8R");
        if is_raw && self.peek() == Some(b'"') {
            self.advance(); // consume the `"`
            self.skip_raw_string();
            return TokenKind::StringLiteral;
        }

        // Ordinary string/char prefixes
        let is_str_prefix = matches!(word.as_str(), "L" | "u" | "U" | "u8");
        if is_str_prefix {
            match self.peek() {
                Some(b'"') => { self.advance(); self.skip_string(b'"'); return TokenKind::StringLiteral; }
                Some(b'\'') => { self.advance(); self.skip_string(b'\''); return TokenKind::StringLiteral; }
                _ => {}
            }
        }

        TokenKind::Word(word)
    }
}
