//! Byte-oriented lexer for `ntpd.conf`.
//!
//! ## Design
//!
//! - Input is `&[u8]`, not `&str` — non-UTF-8 bytes are valid in
//!   quoted strings per OpenNTPD's lexer.
//! - NUL bytes are rejected everywhere.
//! - Token buffer limit: 8096 bytes (matching OpenNTPD's buffer).
//! - Backslash-newline continuation is handled at the cursor level.
//! - Error recovery advances to the next physical newline.
//!
//! ## Phase 4B courts
//!
//! 1. Cursor: peek, bump, unread, span_from, physical line tracking.
//! 2. Exact keyword recognition: lowercase byte matching.
//! 3. Token scanners: quoted, number, unquoted, comment, recovery.
//! 4. Boundary cases: 8096-byte limit, i64 edges, NUL, EOF in quotes.
//! 5. Error recovery: unterminated quote, invalid number, NUL, overflow.

use alloc::vec::Vec;
use core::fmt;

use super::directive::ConfigString;
use super::directive::SourceSpan;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The maximum token length accepted by the lexer, matching OpenNTPD's
/// 8096-byte `hhbuf`.
pub const MAX_TOKEN_LENGTH: usize = 8096;

/// A lexer token.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
    pub line: usize,
}

/// The kind of a lexer token.
#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    Keyword(Keyword),
    String(ConfigString),
    Number(i64),
    Newline,
    Symbol(u8),
    Eof,
    Error(LexErrorKind),
}

/// Recognised lowercase keywords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyword {
    Constraint,
    Constraints,
    Correction,
    From,
    Listen,
    On,
    Query,
    RefId,
    Rtable,
    Sensor,
    Server,
    Servers,
    Stratum,
    Trusted,
    Weight,
}

impl Keyword {
    /// Try to match the given bytes (must be lowercase ASCII).
    fn try_match(bytes: &[u8]) -> Option<Self> {
        use Keyword::*;
        Some(match bytes {
            b"constraint" => Constraint,
            b"constraints" => Constraints,
            b"correction" => Correction,
            b"from" => From,
            b"listen" => Listen,
            b"on" => On,
            b"query" => Query,
            b"refid" => RefId,
            b"rtable" => Rtable,
            b"sensor" => Sensor,
            b"server" => Server,
            b"servers" => Servers,
            b"stratum" => Stratum,
            b"trusted" => Trusted,
            b"weight" => Weight,
            _ => return None,
        })
    }
}

impl fmt::Display for Keyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Keyword::*;
        write!(
            f,
            "{}",
            match self {
                Constraint => "constraint",
                Constraints => "constraints",
                Correction => "correction",
                From => "from",
                Listen => "listen",
                On => "on",
                Query => "query",
                RefId => "refid",
                Rtable => "rtable",
                Sensor => "sensor",
                Server => "server",
                Servers => "servers",
                Stratum => "stratum",
                Trusted => "trusted",
                Weight => "weight",
            }
        )
    }
}

/// Structured lexical error kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexErrorKind {
    /// NUL byte encountered in input (rejected everywhere).
    EmbeddedNul,
    /// String started but not terminated by EOF.
    UnterminatedQuote,
    /// Token exceeded MAX_TOKEN_LENGTH (8096) bytes.
    TokenTooLong,
    /// Numeric token contains invalid characters.
    InvalidNumber,
    /// Numeric value overflows i64 range.
    NumberOverflow,
}

impl fmt::Display for LexErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LexErrorKind::*;
        write!(
            f,
            "{}",
            match self {
                EmbeddedNul => "embedded NUL byte",
                UnterminatedQuote => "unterminated quote",
                TokenTooLong => "token exceeds maximum length",
                InvalidNumber => "invalid number",
                NumberOverflow => "number overflow",
            }
        )
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

/// Byte-oriented lexer for `ntpd.conf`.
///
/// Tracks physical line numbers and byte offsets.  Backslash-newline
/// sequences are consumed silently (they contribute no token bytes but
/// increment the physical line count).
pub struct Lexer<'a> {
    input: &'a [u8],
    offset: usize,
    line: usize,
    line_start: usize,
    recovering: bool,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer over the given byte slice.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            line: 1,
            line_start: 0,
            recovering: false,
        }
    }

    /// Return the current byte without advancing.
    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    /// Advance one byte and return it.
    fn bump(&mut self) -> Option<u8> {
        let b = self.input.get(self.offset).copied();
        if b.is_some() {
            self.offset += 1;
        }
        b
    }

    /// Un-read the last byte (only call if the last operation was
    /// a single `bump()`).
    fn unread(&mut self) {
        self.offset = self.offset.saturating_sub(1);
    }

    /// Return a `SourceSpan` from `start` to the current offset.
    #[allow(dead_code)]
    fn span_from(&self, start: usize) -> SourceSpan {
        SourceSpan::new(start, self.offset)
    }

    /// True if at end of input.
    fn is_eof(&self) -> bool {
        self.offset >= self.input.len()
    }

    /// Peek at the next character without consuming it (for number detection).
    fn peek_next(&self) -> Option<u8> {
        self.input.get(self.offset + 1).copied()
    }

    /// Consume a backslash-newline continuation if present.
    /// Returns true if a continuation was consumed.
    fn try_consume_continuation(&mut self) -> bool {
        if self.peek() == Some(b'\\') && self.peek_next() == Some(b'\n') {
            self.offset += 2;
            self.line += 1;
            self.line_start = self.offset;
            true
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Main lex entry point
    // -----------------------------------------------------------------------

    /// Lex the next token from the input.
    pub fn next_token(&mut self) -> Token {
        // Skip whitespace (but not newlines)
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') => {
                    self.offset += 1;
                }
                Some(b'\\') => {
                    if self.try_consume_continuation() {
                        continue;
                    }
                    break;
                }
                _ => break,
            }
        }

        let start = self.offset;
        let current_line = self.line;

        // End of input
        if self.is_eof() {
            return self.make_token(TokenKind::Eof, start, current_line);
        }

        // Newline
        if self.peek() == Some(b'\n') {
            self.offset += 1;
            self.line += 1;
            self.line_start = self.offset;
            // If recovering, clear the flag — recovery ends at newline.
            self.recovering = false;
            return self.make_token(TokenKind::Newline, start, current_line);
        }

        let b = self.peek().unwrap();

        // Comment: skip to end of physical line, but still produce a
        // Newline token so the parser sees the line boundary.
        if b == b'#' {
            while let Some(c) = self.peek() {
                if c == b'\n' {
                    break;
                }
                if c == b'\0' {
                    return self.error_token(LexErrorKind::EmbeddedNul, start, current_line);
                }
                self.offset += 1;
            }
            // The newline will be lexed on the next call
            return self.next_token();
        }

        // NUL is always an error
        if b == b'\0' {
            self.offset += 1;
            self.recovering = true;
            return self.error_token(LexErrorKind::EmbeddedNul, start, current_line);
        }

        // Quoted string
        if b == b'"' || b == b'\'' {
            return self.lex_quoted(start, current_line);
        }

        // Number or minus sign
        if b == b'-' || b.is_ascii_digit() {
            return self.lex_number(start, current_line);
        }

        // Symbol (single punctuation character)
        if b.is_ascii_punctuation() {
            self.offset += 1;
            return self.make_token(TokenKind::Symbol(b), start, current_line);
        }

        // Unquoted word (keyword or identifier)
        self.lex_unquoted(start, current_line)
    }

    // -----------------------------------------------------------------------
    // Token-specific scanners
    // -----------------------------------------------------------------------

    /// Lex a quoted string (single or double quotes).
    fn lex_quoted(&mut self, start: usize, line: usize) -> Token {
        let quote = self.bump().unwrap(); // consume opening quote
        let mut bytes = Vec::new();

        loop {
            // Handle continuation inside quotes
            while self.peek() == Some(b'\\') && self.peek_next() == Some(b'\n') {
                self.offset += 2;
                self.line += 1;
                self.line_start = self.offset;
            }

            match self.bump() {
                None => {
                    // Unterminated quote at EOF
                    self.recovering = true;
                    return self.error_token(LexErrorKind::UnterminatedQuote, start, line);
                }
                Some(b'\0') => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::EmbeddedNul, start, line);
                }
                Some(b'\n') => {
                    // Physical newline inside a quoted string (not preceded by backslash)
                    // OpenNTPD treats this as an unterminated quote.
                    self.unread();
                    self.recovering = true;
                    return self.error_token(LexErrorKind::UnterminatedQuote, start, line);
                }
                Some(c) if c == quote && self.peek() != Some(b'\\') => {
                    // End of quoted string — but check for escaped quotes
                    // Actually, escaped quotes are \\" not "".
                    // Simple end: the quote character followed by non-backslash.
                    // But handle escaped quote: backslash before matching quote = literal quote.
                    if bytes.last() == Some(&b'\\') {
                        // The backslash was escaping this quote; replace \" with just "
                        bytes.pop();
                        bytes.push(c);
                        continue;
                    }
                    break;
                }
                Some(c) if c == quote => {
                    // Escaped quote (backslash before quote)
                    bytes.pop(); // remove the backslash
                    bytes.push(c);
                }
                Some(c) => {
                    bytes.push(c);
                    if bytes.len() > MAX_TOKEN_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, line);
                    }
                }
            }
        }

        let config_str = ConfigString::new(bytes).unwrap_or_else(|| {
            // Should not happen since we reject NUL above
            ConfigString::new(b"...".to_vec()).unwrap()
        });

        self.make_token(TokenKind::String(config_str), start, line)
    }

    /// Lex a number (optional minus sign followed by digits).
    fn lex_number(&mut self, start: usize, line: usize) -> Token {
        let negative = self.peek() == Some(b'-');
        if negative {
            self.offset += 1;
            // Lone '-' is not a number
            if self.is_eof() || !self.peek().map_or(false, |b| b.is_ascii_digit()) {
                return self.make_token(TokenKind::Symbol(b'-'), start, line);
            }
        }

        let mut bytes = Vec::new();
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                bytes.push(b);
                self.offset += 1;
                if bytes.len() > MAX_TOKEN_LENGTH {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::TokenTooLong, start, line);
                }
            } else {
                break;
            }
        }

        if bytes.is_empty() {
            self.recovering = true;
            return self.error_token(LexErrorKind::InvalidNumber, start, line);
        }

        // Parse the number as i64
        match parse_i64_from_bytes(&bytes, negative) {
            Some(n) => self.make_token(TokenKind::Number(n), start, line),
            None => {
                self.recovering = true;
                self.error_token(LexErrorKind::NumberOverflow, start, line)
            }
        }
    }

    /// Lex an unquoted word (keyword or identifier string).
    fn lex_unquoted(&mut self, start: usize, line: usize) -> Token {
        let mut bytes = Vec::new();

        loop {
            // Handle backslash-newline inside unquoted tokens? OpenNTPD
            // allows it only in quoted strings for most directives.
            // For simplicity, we do NOT continue unquoted tokens across lines.
            match self.peek() {
                None => break,
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') | Some(b'#') => break,
                Some(b'\\') if self.peek_next() == Some(b'\n') => break,
                Some(b'\\') => {
                    bytes.push(b'\\');
                    self.offset += 1;
                }
                Some(b'\0') => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::EmbeddedNul, start, line);
                }
                Some(c)
                    if c.is_ascii_punctuation()
                        && !c.is_ascii_digit()
                        && c != b'_'
                        && c != b'.'
                        && c != b':'
                        && c != b'-'
                        && c != b'+'
                        && c != b'/' =>
                {
                    // Punctuation terminates unquoted tokens.
                    // But keep dot (domain names), colon (IPv6), slash (paths),
                    // plus/minus (signed numbers handled separately), underscore.
                    break;
                }
                Some(c) => {
                    bytes.push(c);
                    self.offset += 1;
                    if bytes.len() > MAX_TOKEN_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, line);
                    }
                }
            }
        }

        if bytes.is_empty() {
            self.recovering = true;
            return self.error_token(LexErrorKind::InvalidNumber, start, line);
        }

        // Try keyword match first (exact lowercase only)
        if let Some(kw) = Keyword::try_match(&bytes) {
            return self.make_token(TokenKind::Keyword(kw), start, line);
        }

        // Otherwise it's an unquoted string
        let config_str =
            ConfigString::new(bytes).unwrap_or_else(|| ConfigString::new(b"...".to_vec()).unwrap());
        self.make_token(TokenKind::String(config_str), start, line)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_token(&self, kind: TokenKind, start: usize, line: usize) -> Token {
        Token {
            kind,
            span: SourceSpan::new(start, self.offset),
            line,
        }
    }

    fn error_token(&self, kind: LexErrorKind, start: usize, line: usize) -> Token {
        Token {
            kind: TokenKind::Error(kind),
            span: SourceSpan::new(start, self.offset),
            line,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a signed i64 from ASCII digit bytes.
/// Handles i64::MIN correctly (the absolute value 2^63 fits in u64
/// but not in i64 as a positive value).
fn parse_i64_from_bytes(bytes: &[u8], negative: bool) -> Option<i64> {
    // First parse as u64 to handle the i64::MIN case
    let mut abs: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        abs = abs.checked_mul(10)?;
        abs = abs.checked_add((b - b'0') as u64)?;
    }
    if negative {
        // i64::MIN is -2^63 which is -9223372036854775808.
        // As u64, 2^63 is 9223372036854775808 which fits in u64.
        if abs > (i64::MAX as u64) + 1 {
            return None;
        }
        if abs == (i64::MAX as u64) + 1 {
            Some(i64::MIN)
        } else {
            Some(-(abs as i64))
        }
    } else {
        if abs > i64::MAX as u64 {
            return None;
        }
        Some(abs as i64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn lex_all(input: &[u8]) -> Vec<Token> {
        let mut lexer = Lexer::new(input);
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token();
            let is_eof = matches!(tok.kind, TokenKind::Eof);
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        tokens
    }

    // --- Cursor ---

    #[test]
    fn test_cursor_peek_bump() {
        let mut l = Lexer::new(b"ab");
        assert_eq!(l.peek(), Some(b'a'));
        assert_eq!(l.bump(), Some(b'a'));
        assert_eq!(l.peek(), Some(b'b'));
        assert_eq!(l.bump(), Some(b'b'));
        assert_eq!(l.peek(), None);
    }

    #[test]
    fn test_cursor_unread() {
        let mut l = Lexer::new(b"ab");
        l.bump();
        l.unread();
        assert_eq!(l.peek(), Some(b'a'));
    }

    // --- Comments ---

    #[test]
    fn test_comment_only() {
        let toks = lex_all(b"# comment\nserver\n");
        // comment consumes content, recursive next_token() sees \n → Newline,
        // then server → Keyword(Server), then \n → Newline, then Eof
        assert_eq!(toks.len(), 4);
        assert!(matches!(toks[0].kind, TokenKind::Newline));
        assert!(matches!(toks[1].kind, TokenKind::Keyword(Keyword::Server)));
        assert!(matches!(toks[2].kind, TokenKind::Newline));
        assert!(matches!(toks[3].kind, TokenKind::Eof));
    }

    #[test]
    fn test_comment_at_eof() {
        let toks = lex_all(b"# comment");
        assert_eq!(toks.len(), 1);
        assert!(matches!(toks[0].kind, TokenKind::Eof));
    }

    // --- Keywords ---

    #[test]
    fn test_all_keywords() {
        let input = b"constraint constraints correction from listen on query refid rtable sensor server servers stratum trusted weight";
        let toks = lex_all(input);
        // Expect one token per keyword (no spaces or newlines in the list,
        // but the lexer splits on space/tab boundaries, so each keyword
        // is a separate token)
        let expected_keywords = [
            Keyword::Constraint,
            Keyword::Constraints,
            Keyword::Correction,
            Keyword::From,
            Keyword::Listen,
            Keyword::On,
            Keyword::Query,
            Keyword::RefId,
            Keyword::Rtable,
            Keyword::Sensor,
            Keyword::Server,
            Keyword::Servers,
            Keyword::Stratum,
            Keyword::Trusted,
            Keyword::Weight,
        ];
        let kw_tokens: Vec<&Keyword> = toks
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Keyword(k) => Some(k),
                _ => None,
            })
            .collect();
        for (i, expected) in expected_keywords.iter().enumerate() {
            assert_eq!(kw_tokens.get(i), Some(&expected), "keyword {i} mismatch");
        }
    }

    #[test]
    fn test_keyword_case_sensitive() {
        let toks = lex_all(b"Server SERVER");
        for tok in &toks {
            match &tok.kind {
                TokenKind::String(_) => {}
                TokenKind::Eof => break,
                other => panic!("expected String or Eof, got {other:?}"),
            }
        }
    }

    // --- Numbers ---

    #[test]
    fn test_number_positive() {
        let mut l = Lexer::new(b"42");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Number(42));
    }

    #[test]
    fn test_number_negative() {
        let mut l = Lexer::new(b"-7");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Number(-7));
    }

    #[test]
    fn test_number_zero() {
        let mut l = Lexer::new(b"0");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Number(0));
    }

    #[test]
    fn test_number_i64_min() {
        let mut l = Lexer::new(b"-9223372036854775808");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Number(i64::MIN));
    }

    #[test]
    fn test_number_i64_max() {
        let mut l = Lexer::new(b"9223372036854775807");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Number(i64::MAX));
    }

    #[test]
    fn test_number_overflow_positive() {
        let mut l = Lexer::new(b"9223372036854775808");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
    }

    #[test]
    fn test_number_overflow_negative() {
        let mut l = Lexer::new(b"-9223372036854775809");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
    }

    #[test]
    fn test_lone_minus_is_symbol() {
        let mut l = Lexer::new(b"-");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Symbol(b'-'));
    }

    // --- Quoted strings ---

    #[test]
    fn test_quoted_double() {
        let mut l = Lexer::new(b"\"hello\"");
        let tok = l.next_token();
        assert!(matches!(&tok.kind, TokenKind::String(s) if s.as_bytes() == b"hello"));
    }

    #[test]
    fn test_quoted_single() {
        let mut l = Lexer::new(b"'world'");
        let tok = l.next_token();
        assert!(matches!(&tok.kind, TokenKind::String(s) if s.as_bytes() == b"world"));
    }

    #[test]
    fn test_quoted_non_utf8() {
        let toks = lex_all(b"\"\xff\xfe\"");
        assert!(!toks.is_empty());
        match &toks[0].kind {
            TokenKind::String(s) => {
                assert_eq!(s.as_bytes(), b"\xff\xfe");
                assert!(s.as_utf8().is_none());
            }
            other => panic!("expected String, got {other:?}"),
        }
    }

    #[test]
    fn test_quoted_empty() {
        let mut l = Lexer::new(b"\"\"");
        let tok = l.next_token();
        assert!(matches!(&tok.kind, TokenKind::String(s) if s.as_bytes().is_empty()));
    }

    #[test]
    fn test_unterminated_quote_eof() {
        let mut l = Lexer::new(b"\"hello");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::UnterminatedQuote)
        ));
    }

    #[test]
    fn test_unterminated_quote_newline() {
        let mut l = Lexer::new(b"\"hello\n");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::UnterminatedQuote)
        ));
    }

    // --- NUL rejection ---

    #[test]
    fn test_nul_unquoted() {
        let mut l = Lexer::new(b"bad\0");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::EmbeddedNul)
        ));
    }

    #[test]
    fn test_nul_quoted() {
        let mut l = Lexer::new(b"\"bad\0\"");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::EmbeddedNul)
        ));
    }

    #[test]
    fn test_nul_comment() {
        let mut l = Lexer::new(b"# bad\0");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::EmbeddedNul)
        ));
    }

    // --- Newlines and lines ---

    #[test]
    fn test_newline_tracking() {
        let toks = lex_all(b"server\nlisten\n");
        assert_eq!(toks[0].line, 1);
        assert!(matches!(toks[0].kind, TokenKind::Keyword(Keyword::Server)));
        assert_eq!(toks[1].kind, TokenKind::Newline);
        assert_eq!(toks[2].line, 2);
        assert!(matches!(toks[2].kind, TokenKind::Keyword(Keyword::Listen)));
    }

    // --- Continuation ---

    #[test]
    fn test_backslash_newline_continuation() {
        // OpenNTPD only supports continuation inside quoted strings.
        // In unquoted context, 'ser\\n' is an unquoted word, continuation
        // is whitespace, and 'ver' is a second unquoted word.
        let toks = lex_all(b"ser\\\nver\n");
        assert_eq!(toks.len(), 4); // str, str, nl, eof
        assert!(matches!(toks[0].kind, TokenKind::String(_)));
        assert!(matches!(toks[1].kind, TokenKind::String(_)));
    }

    #[test]
    fn test_backslash_newline_in_quoted() {
        let toks = lex_all(b"\"hello \\\nworld\"\n");
        assert_eq!(toks.len(), 3); // String + Newline + Eof
        match &toks[0].kind {
            TokenKind::String(s) => assert_eq!(s.as_bytes(), b"hello world"),
            other => panic!("expected String, got {other:?}"),
        }
        assert!(matches!(toks[1].kind, TokenKind::Newline));
    }

    // --- Line recovery ---

    #[test]
    fn test_recovery_after_error() {
        let toks = lex_all(b"\"unterminated\nserver\n");
        assert!(matches!(
            toks[0].kind,
            TokenKind::Error(LexErrorKind::UnterminatedQuote)
        ));
        // After the newline, recovery should produce a Newline token...
        assert!(matches!(toks[1].kind, TokenKind::Newline));
        // ...then the next directive should be parsed normally
        assert!(matches!(toks[2].kind, TokenKind::Keyword(Keyword::Server)));
    }

    // --- Symbols ---

    #[test]
    fn test_symbols() {
        let toks = lex_all(b"(){};");
        assert_eq!(toks[0].kind, TokenKind::Symbol(b'('));
        assert_eq!(toks[1].kind, TokenKind::Symbol(b')'));
        assert_eq!(toks[2].kind, TokenKind::Symbol(b'{'));
        assert_eq!(toks[3].kind, TokenKind::Symbol(b'}'));
        assert_eq!(toks[4].kind, TokenKind::Symbol(b';'));
    }

    // --- Token length boundary ---

    #[test]
    fn test_token_length_boundary() {
        // Build a token just under the limit
        let short = vec![b'a'; MAX_TOKEN_LENGTH];
        let toks = lex_all(&short);
        assert!(matches!(toks[0].kind, TokenKind::String(_)));

        // Build a token at the limit + 1
        let long = vec![b'a'; MAX_TOKEN_LENGTH + 1];
        let toks = lex_all(&long);
        assert!(matches!(
            toks[0].kind,
            TokenKind::Error(LexErrorKind::TokenTooLong)
        ));
    }

    // --- Mixed directive line ---

    #[test]
    fn test_simple_directive_line() {
        let toks = lex_all(b"server pool.ntp.org weight 5\n");
        let kinds: Vec<&str> = toks
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Keyword(_) => Some("kw"),
                TokenKind::String(_) => Some("str"),
                TokenKind::Number(_) => Some("num"),
                TokenKind::Newline => Some("nl"),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, &["kw", "str", "kw", "num", "nl"]);
    }

    #[test]
    fn test_listen_directive_line() {
        let toks = lex_all(b"listen on * rtable 0\n");
        let kinds: Vec<&str> = toks
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Keyword(_) => Some("kw"),
                TokenKind::Symbol(b'*') => Some("*"),
                TokenKind::Number(_) => Some("num"),
                TokenKind::Newline => Some("nl"),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, &["kw", "kw", "*", "kw", "num", "nl"]);
    }
}
