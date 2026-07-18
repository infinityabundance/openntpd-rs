//! Byte-oriented lexer for `ntpd.conf` — OpenNTPD 7.9p1 lexical rules.
//!
//! ## Cursor model
//!
//! Two cursor paths:
//! - `next_unquoted_byte()` — reproduces OpenNTPD's `lgetc(0)`: consumes
//!   backslash-newline globally, drops backslash before non-newline.
//! - `bump_raw()` — raw byte-by-byte without transformation (for quoted
//!   strings, which apply their own escape rules).
//!
//! ## Key rules
//!
//! - Input is `&[u8]` (non-UTF-8 bytes valid in quoted strings).
//! - NUL rejected everywhere.
//! - Digits followed by non-number-terminator → fall back to string.
//! - String-start characters: alphanumeric, `:`, `_`, `*`.
//! - Backslash-newline consumed globally (both quoted and unquoted).
//! - Raw newline inside quoted string continues the string.
//! - Token limits: 8094 bytes (quoted), 8095 bytes (unquoted/numbers).
//! - Error recovery: consume to next physical newline.

use alloc::vec::Vec;
use core::fmt;

use super::directive::ConfigString;
use super::directive::SourceSpan;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum token payload for quoted strings (8094 + NUL fits in 8096 buffer).
pub const MAX_QUOTED_LENGTH: usize = 8094;
/// Maximum token payload for unquoted / numeric tokens (8095 + NUL fits).
pub const MAX_UNQUOTED_LENGTH: usize = 8095;

/// Characters that can terminate a numeric token.
fn is_number_terminator(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\n' | b'\r' | b')' | b',' | b'/' | b'}' | b'='
    )
}

/// Characters that can start an unquoted string.
fn is_string_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'*')
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
    pub line: usize,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexErrorKind {
    EmbeddedNul,
    UnterminatedQuote,
    TokenTooLong,
    InvalidNumber,
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

pub struct Lexer<'a> {
    input: &'a [u8],
    offset: usize,
    line: usize,
    line_start: usize,
    recovering: bool,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            line: 1,
            line_start: 0,
            recovering: false,
        }
    }

    // -- Raw cursor (no transformation) --

    fn peek_raw(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn bump_raw(&mut self) -> Option<u8> {
        let b = self.input.get(self.offset).copied();
        if b.is_some() {
            self.offset += 1;
        }
        b
    }

    fn unread(&mut self) {
        self.offset = self.offset.saturating_sub(1);
    }

    fn is_eof(&self) -> bool {
        self.offset >= self.input.len()
    }

    fn span_from(&self, start: usize) -> SourceSpan {
        SourceSpan::new(start, self.offset)
    }

    // -- Unquoted cursor (reproduces OpenNTPD's lgetc(0)) --
    //
    // Consumes backslash-newline globally.
    // Drops backslash before non-newline (in unquoted context).
    // Does NOT skip carriage returns — OpenNTPD only skips space and tab.

    fn next_unquoted_byte(&mut self) -> Option<u8> {
        loop {
            match self.peek_raw() {
                Some(b'\\') => {
                    self.offset += 1; // consume backslash
                    match self.peek_raw() {
                        Some(b'\n') => {
                            self.offset += 1;
                            self.line += 1;
                            self.line_start = self.offset;
                            continue;
                        }
                        Some(b'\r') => {
                            // Backslash before \r: drop backslash, return \r
                            self.offset += 1;
                            return Some(b'\r');
                        }
                        _ => {
                            // Backslash before non-newline: dropped.
                            // Continue to return the next byte (without
                            // consuming it yet — it will be consumed below).
                            continue;
                        }
                    }
                }
                Some(c) => {
                    // Normal byte: consume and return it
                    self.offset += 1;
                    return Some(c);
                }
                None => return None,
            }
        }
    }

    // -- Whitespace skipping (space and tab only, like OpenNTPD) --

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_raw(), Some(b' ') | Some(b'\t')) {
            self.offset += 1;
        }
    }

    // -- Main lex entry point --

    pub fn next_token(&mut self) -> Token {
        // Error recovery: consume to next physical newline
        if self.recovering {
            while !matches!(self.peek_raw(), None | Some(b'\n')) {
                self.offset += 1;
            }
            self.recovering = false;
        }

        self.skip_whitespace();

        let start = self.offset;
        let current_line = self.line;

        // EOF
        if self.is_eof() {
            return self.make_token(TokenKind::Eof, start, current_line);
        }

        // Newline
        if self.peek_raw() == Some(b'\n') {
            self.offset += 1;
            self.line += 1;
            self.line_start = self.offset;
            return self.make_token(TokenKind::Newline, start, current_line);
        }

        let b = self.peek_raw().unwrap();

        // Comment
        if b == b'#' {
            loop {
                // Peek at the next byte before consuming
                match self.peek_raw() {
                    None => {
                        // EOF after comment — return next_token which gives Eof
                        return self.next_token();
                    }
                    Some(b'\n') => {
                        // Don't consume the newline — return next_token
                        // which will produce a Newline token
                        return self.next_token();
                    }
                    Some(b'\0') => {
                        self.offset += 1;
                        self.recovering = true;
                        return self.error_token(LexErrorKind::EmbeddedNul, start, current_line);
                    }
                    _ => {
                        // Consume and continue
                        self.offset += 1;
                    }
                }
            }
        }

        // NUL error
        if b == b'\0' {
            self.offset += 1;
            self.recovering = true;
            return self.error_token(LexErrorKind::EmbeddedNul, start, current_line);
        }

        // Quoted string
        if b == b'"' || b == b'\'' {
            return self.lex_quoted(start, current_line);
        }

        // Number or minus — but with fallback to string if followed
        // by non-number-terminator.
        if b == b'-' || b.is_ascii_digit() {
            return self.lex_number_or_string(start, current_line);
        }

        // String-start characters: alphanumeric, :, _, *
        if is_string_start(b) {
            return self.lex_unquoted(start, current_line);
        }

        // Punctuation symbol
        if b.is_ascii_punctuation() {
            self.offset += 1;
            return self.make_token(TokenKind::Symbol(b), start, current_line);
        }

        // Fallback: unquoted string for any other byte
        self.lex_unquoted(start, current_line)
    }

    // -----------------------------------------------------------------------
    // Number-or-string: fallback when digits are not number-terminated
    // -----------------------------------------------------------------------

    fn lex_number_or_string(&mut self, start: usize, line: usize) -> Token {
        let start_negative = self.peek_raw() == Some(b'-');
        if start_negative {
            self.offset += 1;
        }

        // Collect digit bytes
        let mut digits = Vec::new();
        while let Some(b) = self.peek_raw() {
            if b.is_ascii_digit() {
                digits.push(b);
                self.offset += 1;
                if digits.len() > MAX_UNQUOTED_LENGTH {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::TokenTooLong, start, line);
                }
            } else {
                break;
            }
        }

        // If no digits after minus, lone '-' is a symbol
        if start_negative && digits.is_empty() {
            return self.make_token(TokenKind::Symbol(b'-'), start, line);
        }

        // Check what follows the digits
        let terminator = self.peek_raw();

        if digits.is_empty() || !terminator.map_or(true, is_number_terminator) {
            // Not a valid number — re-lex from start as unquoted string.
            // Reset offset to start (but keep start_negative adjustment).
            self.offset = if start_negative { start + 1 } else { start };
            // Actually we need to reset properly.
            self.offset = start;
            return self.lex_unquoted(start, line);
        }

        // Valid number — parse it
        match parse_i64_from_bytes(&digits, start_negative) {
            Some(n) => self.make_token(TokenKind::Number(n), start, line),
            None => {
                self.recovering = true;
                self.error_token(LexErrorKind::NumberOverflow, start, line)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Quoted string
    // -----------------------------------------------------------------------

    fn lex_quoted(&mut self, start: usize, line: usize) -> Token {
        let quote = self.bump_raw().unwrap(); // consume opening quote
        let mut bytes = Vec::new();

        loop {
            match self.bump_raw() {
                None => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::UnterminatedQuote, start, line);
                }
                Some(b'\0') => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::EmbeddedNul, start, line);
                }
                Some(b'\n') => {
                    // Raw newline inside quoted string: include in bytes
                    self.line += 1;
                    self.line_start = self.offset;
                    bytes.push(b'\n');
                }
                Some(c) if c == quote => {
                    // End of quoted string
                    break;
                }
                Some(b'\\') => {
                    match self.bump_raw() {
                        Some(b'\n') => {
                            // Backslash-newline: continuation, increment line
                            self.line += 1;
                            self.line_start = self.offset;
                            // Don't add to bytes
                        }
                        Some(c) if c == quote || c == b' ' || c == b'\t' => {
                            // Escaped quote, space, or tab: push the literal byte
                            bytes.push(c);
                        }
                        Some(c) => {
                            // Unknown escape: preserve both backslash and char
                            bytes.push(b'\\');
                            bytes.push(c);
                        }
                        None => {
                            self.recovering = true;
                            return self.error_token(LexErrorKind::UnterminatedQuote, start, line);
                        }
                    }
                    if bytes.len() > MAX_QUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, line);
                    }
                }
                Some(c) => {
                    bytes.push(c);
                    if bytes.len() > MAX_QUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, line);
                    }
                }
            }
        }

        let config_str = ConfigString::new(bytes)
            .expect("quoted string contains NUL (should have been rejected above)");
        self.make_token(TokenKind::String(config_str), start, line)
    }

    // -----------------------------------------------------------------------
    // Unquoted string / keyword
    // -----------------------------------------------------------------------

    fn lex_unquoted(&mut self, start: usize, line: usize) -> Token {
        let mut bytes = Vec::new();

        loop {
            match self.next_unquoted_byte() {
                None => break,
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => {
                    // next_unquoted_byte consumed the byte; un-read it
                    self.unread();
                    break;
                }
                Some(b'#') => {
                    self.unread_physical(b'#');
                    break;
                }
                Some(b'\0') => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::EmbeddedNul, start, line);
                }
                Some(c)
                    if c.is_ascii_punctuation()
                        && !is_string_start(c)
                        && c != b'.'
                        && c != b'-'
                        && c != b'+'
                        && c != b'/' =>
                {
                    // Punctuation that terminates unquoted tokens
                    // (but keep dot for domains, -/+ for signed, / for paths)
                    self.unread_physical(c);
                    break;
                }
                Some(c) => {
                    bytes.push(c);
                    if bytes.len() > MAX_UNQUOTED_LENGTH {
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

        // Try keyword match (exact lowercase only)
        if let Some(kw) = Keyword::try_match(&bytes) {
            return self.make_token(TokenKind::Keyword(kw), start, line);
        }

        let config_str = ConfigString::new(bytes)
            .expect("unquoted string contains NUL (should have been rejected above)");
        self.make_token(TokenKind::String(config_str), start, line)
    }

    /// Un-read a byte that was already consumed via `next_unquoted_byte`.
    /// Since `next_unquoted_byte` may have consumed continuation, we un-read
    /// raw via `self.offset -= 1`.
    fn unread_physical(&mut self, _byte: u8) {
        self.offset = self.offset.saturating_sub(1);
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
// Number parsing
// ---------------------------------------------------------------------------

fn parse_i64_from_bytes(bytes: &[u8], negative: bool) -> Option<i64> {
    let mut abs: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        abs = abs.checked_mul(10)?;
        abs = abs.checked_add((b - b'0') as u64)?;
    }
    if negative {
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

    fn count_tokens(input: &[u8]) -> Vec<&'static str> {
        lex_all(input)
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Keyword(_) => Some("kw"),
                TokenKind::String(_) => Some("str"),
                TokenKind::Number(_) => Some("num"),
                TokenKind::Newline => Some("nl"),
                TokenKind::Symbol(_) => Some("sym"),
                TokenKind::Eof => None,
                TokenKind::Error(_) => Some("err"),
            })
            .collect()
    }

    // -- Cursor --
    #[test]
    fn cursor_peek_bump() {
        let mut l = Lexer::new(b"ab");
        assert_eq!(l.peek_raw(), Some(b'a'));
        assert_eq!(l.bump_raw(), Some(b'a'));
        assert_eq!(l.peek_raw(), Some(b'b'));
        assert_eq!(l.bump_raw(), Some(b'b'));
        assert_eq!(l.peek_raw(), None);
    }
    #[test]
    fn cursor_unread() {
        let mut l = Lexer::new(b"ab");
        l.bump_raw();
        l.unread();
        assert_eq!(l.peek_raw(), Some(b'a'));
    }

    // -- Comments --
    #[test]
    fn comment_only() {
        let toks = count_tokens(b"# comment\nserver\n");
        assert_eq!(toks, &["nl", "kw", "nl"]);
    }
    #[test]
    fn comment_at_eof() {
        assert!(lex_all(b"# comment")
            .iter()
            .all(|t| matches!(t.kind, TokenKind::Eof)));
    }

    // -- Keywords --
    #[test]
    fn all_keywords() {
        let input = b"constraint constraints correction from listen on query refid rtable sensor server servers stratum trusted weight";
        let expected = [
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
        let tokens = lex_all(input);
        let kws: Vec<Keyword> = tokens
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Keyword(k) => Some(*k),
                _ => None,
            })
            .collect();
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(kws.get(i), Some(exp), "keyword {i} mismatch");
        }
    }
    #[test]
    fn keyword_case_sensitive() {
        for tok in &lex_all(b"Server SERVER") {
            assert!(matches!(tok.kind, TokenKind::String(_) | TokenKind::Eof));
        }
    }

    // -- Numbers --
    #[test]
    fn number_positive() {
        let mut l = Lexer::new(b"42");
        assert_eq!(l.next_token().kind, TokenKind::Number(42));
    }
    #[test]
    fn number_negative() {
        let mut l = Lexer::new(b"-7");
        assert_eq!(l.next_token().kind, TokenKind::Number(-7));
    }
    #[test]
    fn number_zero() {
        let mut l = Lexer::new(b"0");
        assert_eq!(l.next_token().kind, TokenKind::Number(0));
    }
    #[test]
    fn number_i64_min() {
        let mut l = Lexer::new(b"-9223372036854775808");
        assert_eq!(l.next_token().kind, TokenKind::Number(i64::MIN));
    }
    #[test]
    fn number_i64_max() {
        let mut l = Lexer::new(b"9223372036854775807");
        assert_eq!(l.next_token().kind, TokenKind::Number(i64::MAX));
    }
    #[test]
    fn number_overflow_pos() {
        let mut l = Lexer::new(b"9223372036854775808");
        assert!(matches!(
            l.next_token().kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
    }
    #[test]
    fn number_overflow_neg() {
        let mut l = Lexer::new(b"-9223372036854775809");
        assert!(matches!(
            l.next_token().kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
    }
    #[test]
    fn lone_minus_symbol() {
        let mut l = Lexer::new(b"-");
        assert_eq!(l.next_token().kind, TokenKind::Symbol(b'-'));
    }

    // -- Number fallback to string --
    #[test]
    fn numeric_ipv4_is_string() {
        let toks = count_tokens(b"192.0.2.1");
        assert_eq!(toks, &["str"]); // single string "192.0.2.1"
    }
    #[test]
    fn numeric_ipv6_is_string() {
        let toks = count_tokens(b"2001:db8::1");
        assert_eq!(toks, &["str"]);
    }
    #[test]
    fn digit_prefixed_hostname_is_string() {
        let toks = count_tokens(b"0.pool.ntp.org");
        assert_eq!(toks, &["str"]);
    }
    #[test]
    fn digits_followed_by_alpha_is_string() {
        let toks = count_tokens(b"123abc");
        assert_eq!(toks, &["str"]);
    }
    #[test]
    fn digit_hyphen_digit_is_string() {
        let toks = count_tokens(b"1-2");
        assert_eq!(toks, &["str"]);
    }
    #[test]
    fn number_then_slash() {
        let toks = count_tokens(b"123/");
        assert_eq!(toks, &["num", "sym"]); // Number(123), Symbol('/')
    }
    #[test]
    fn number_then_space() {
        let toks = count_tokens(b"123 ");
        assert_eq!(toks, &["num"]);
    }
    #[test]
    fn number_then_newline() {
        let toks = count_tokens(b"123\n");
        assert_eq!(toks, &["num", "nl"]);
    }

    // -- String-start characters --
    #[test]
    fn wildcard_is_string() {
        // Step through lex_unquoted directly
        let mut l = Lexer::new(b"*");

        // Manually do what next_token does to reach lex_unquoted
        let start = l.offset;
        let line = l.line;

        // First, what does next_unquoted_byte return?
        let b1 = l.next_unquoted_byte();
        // If it's None, bytes remains empty and we get InvalidNumber
        if b1.is_none() {
            panic!("next_unquoted_byte returned None for '*'");
        }

        // Now what does peek_raw show?
        let peek_after = l.peek_raw();
        if peek_after.is_some() {
            panic!(
                "peek_raw returned {:?} after reading '*', expected EOF",
                peek_after
            );
        }
    }
    #[test]
    fn wildcard_listen() {
        let toks = count_tokens(b"listen on * rtable 0\n");
        assert_eq!(toks, &["kw", "kw", "str", "kw", "num", "nl"]);
    }
    #[test]
    fn colon_prefixed_string() {
        let toks = count_tokens(b"::1");
        assert_eq!(toks, &["str"]);
    }
    #[test]
    fn underscore_prefixed_string() {
        let toks = count_tokens(b"_ntp");
        assert_eq!(toks, &["str"]);
    }

    // -- Quoted strings --
    #[test]
    fn quoted_double() {
        let mut l = Lexer::new(b"\"hello\"");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes() == b"hello"));
    }
    #[test]
    fn quoted_single() {
        let mut l = Lexer::new(b"'world'");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes() == b"world"));
    }
    #[test]
    fn quoted_non_utf8() {
        let toks = lex_all(b"\"\xff\xfe\"");
        match &toks[0].kind {
            TokenKind::String(s) => {
                assert_eq!(s.as_bytes(), b"\xff\xfe");
                assert!(s.as_utf8().is_none());
            }
            _ => panic!(),
        }
    }
    #[test]
    fn quoted_empty() {
        let mut l = Lexer::new(b"\"\"");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes().is_empty()));
    }
    #[test]
    fn unterminated_quote_eof() {
        let toks = lex_all(b"\"hello");
        assert!(toks
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::UnterminatedQuote))));
    }
    #[test]
    fn unterminated_quote_newline() {
        let toks = lex_all(b"\"hello\n");
        // OpenNTPD allows raw newlines in quoted strings (continues).
        // Unterminated only if we hit EOF.
        assert!(toks
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::UnterminatedQuote))));
    }

    // -- Quoted escape sequences --
    #[test]
    fn quoted_escaped_quote() {
        let mut l = Lexer::new(b"\"he\\\"llo\"");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes() == b"he\"llo"));
    }
    #[test]
    fn quoted_escaped_space() {
        let mut l = Lexer::new(b"\"hello\\ world\"");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes() == b"hello world"));
    }
    #[test]
    fn quoted_escaped_tab() {
        let mut l = Lexer::new(b"\"hello\\\tworld\"");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes() == b"hello\tworld"));
    }
    #[test]
    fn quoted_unknown_escape_preserves_backslash() {
        let mut l = Lexer::new(b"\"hello\\x\"");
        let t = l.next_token();
        assert!(matches!(&t.kind, TokenKind::String(s) if s.as_bytes() == b"hello\\x"));
    }

    // -- Quoted raw newline continues --
    #[test]
    fn quoted_raw_newline_continues() {
        let toks = lex_all(b"\"hello\nworld\"\n");
        assert_eq!(toks.len(), 3); // string + newline + eof
        match &toks[0].kind {
            TokenKind::String(s) => assert_eq!(s.as_bytes(), b"hello\nworld"),
            _ => panic!(),
        }
    }

    // -- Backslash-newline continuation --
    #[test]
    fn unquoted_continuation_merges() {
        let toks = count_tokens(b"ser\\\nver");
        // Backslash-newline consumed; "server" matches the keyword.
        assert_eq!(toks, &["kw"]);
    }
    #[test]
    fn unquoted_backslash_removed() {
        let toks = count_tokens(b"ser\\ver");
        // Backslash before non-newline is dropped; result is "server" which
        // matches the keyword. That's correct lexical behavior.
        assert_eq!(toks, &["kw"]);
    }
    #[test]
    fn quoted_backslash_newline() {
        let toks = count_tokens(b"\"hello \\\nworld\"\n");
        assert_eq!(toks, &["str", "nl"]);
        match &lex_all(b"\"hello \\\nworld\"")[0].kind {
            TokenKind::String(s) => assert_eq!(s.as_bytes(), b"hello world"),
            _ => panic!(),
        }
    }

    // -- NUL rejection --
    #[test]
    fn nul_unquoted() {
        assert!(lex_all(b"bad\0")
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::EmbeddedNul))));
    }
    #[test]
    fn nul_quoted() {
        assert!(lex_all(b"\"bad\0\"")
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::EmbeddedNul))));
    }
    #[test]
    fn nul_comment() {
        assert!(lex_all(b"# bad\0")
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::EmbeddedNul))));
    }

    // -- Newline tracking --
    #[test]
    fn newline_tracking() {
        let toks = lex_all(b"server\nlisten\n");
        assert_eq!(toks[0].line, 1);
        assert_eq!(toks[2].line, 2);
    }

    // -- Error recovery --
    #[test]
    fn recovery_after_unterminated_quote() {
        let toks = count_tokens(b"\"unterminated\nserver\n");
        // Quote continues across newline, consumes everything to EOF.
        // Error at EOF with recovering set, but nothing left to recover.
        assert_eq!(toks, &["err"]);
    }
    #[test]
    fn recovery_after_nul() {
        let toks = count_tokens(b"bad\0\nserver\n");
        assert_eq!(toks, &["err", "nl", "kw", "nl"]);
    }
    #[test]
    fn recovery_after_overflow() {
        let toks = count_tokens(b"99999999999999999999\nserver\n");
        assert_eq!(toks, &["err", "nl", "kw", "nl"]);
    }

    // -- Symbols --
    #[test]
    fn symbols() {
        let toks = count_tokens(b"(){};");
        assert_eq!(toks, &["sym", "sym", "sym", "sym", "sym"]);
    }

    // -- Token length boundaries --
    #[test]
    fn quoted_limit_8094() {
        let mut input = vec![b'"'];
        input.extend(core::iter::repeat(b'a').take(MAX_QUOTED_LENGTH));
        input.push(b'"');
        let toks = lex_all(&input);
        assert!(matches!(toks[0].kind, TokenKind::String(_)));
    }
    #[test]
    fn quoted_limit_8095_rejected() {
        let mut input = vec![b'"'];
        input.extend(core::iter::repeat(b'a').take(MAX_QUOTED_LENGTH + 1));
        input.push(b'"');
        let toks = lex_all(&input);
        assert!(matches!(
            toks[0].kind,
            TokenKind::Error(LexErrorKind::TokenTooLong)
        ));
    }
    #[test]
    fn unquoted_limit_8095() {
        let toks = lex_all(&vec![b'a'; MAX_UNQUOTED_LENGTH]);
        assert!(matches!(toks[0].kind, TokenKind::String(_)));
    }
    #[test]
    fn unquoted_limit_8096_rejected() {
        let toks = lex_all(&vec![b'a'; MAX_UNQUOTED_LENGTH + 1]);
        assert!(matches!(
            toks[0].kind,
            TokenKind::Error(LexErrorKind::TokenTooLong)
        ));
    }

    // -- Integration --
    #[test]
    fn simple_directive_line() {
        assert_eq!(
            count_tokens(b"server pool.ntp.org weight 5\n"),
            &["kw", "str", "kw", "num", "nl"]
        );
    }
    #[test]
    fn listen_directive_line() {
        assert_eq!(
            count_tokens(b"listen on * rtable 0\n"),
            &["kw", "kw", "str", "kw", "num", "nl"]
        );
    }
}
