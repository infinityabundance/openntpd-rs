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
//! The logical unquoted cursor is used by: initial token dispatch, leading
//! whitespace scan, comment scan, number scan, error recovery, unquoted
//! string scan, recovery findeol.
//!
//! ## Key rules
//!
//! - Input is `&[u8]` (non-UTF-8 bytes valid in quoted strings).
//! - NUL rejected everywhere.
//! - Digits followed by non-number-terminator → fall back to string.
//! - String-start characters: alphanumeric, `:`, `_`, `*`.
//! - Backslash-newline consumed globally before token classification.
//! - Raw newline inside quoted string: line incremented, byte NOT added to result.
//! - Token limits: 8094 (quoted), 8095 (unquoted/numbers).
//! - Error recovery uses logical cursor (skips escaped newlines).

use alloc::vec::Vec;
use core::fmt;

use super::directive::ConfigString;
use super::directive::SourceSpan;

pub const MAX_QUOTED_LENGTH: usize = 8094;
pub const MAX_UNQUOTED_LENGTH: usize = 8095;

fn is_number_terminator(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\n' | b'\r' | b')' | b',' | b'/' | b'}' | b'='
    )
}

fn is_string_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'*')
}

/// Characters allowed inside an unquoted token (OpenNTPD's upstream class).
fn is_allowed_in_unquoted(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || (b.is_ascii_punctuation()
            && !matches!(
                b,
                b'(' | b')'
                    | b'{'
                    | b'}'
                    | b'<'
                    | b'>'
                    | b'!'
                    | b'='
                    | b'/'
                    | b'#'
                    | b','
                    | b';'
                    | b'['
                    | b']'
            ))
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

/// Snapshot of cursor state for speculative scanning.
#[derive(Clone, Copy)]
struct CursorState {
    offset: usize,
    line: usize,
    line_start: usize,
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

    fn save_cursor(&self) -> CursorState {
        CursorState {
            offset: self.offset,
            line: self.line,
            line_start: self.line_start,
        }
    }

    fn restore_cursor(&mut self, cs: CursorState) {
        self.offset = cs.offset;
        self.line = cs.line;
        self.line_start = cs.line_start;
    }

    // -- Raw cursor --

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

    // -- Logical unquoted cursor (reproduces OpenNTPD's lgetc(0)) --
    //
    // Backslash-newline consumed globally.  Backslash before non-newline
    // is dropped (in unquoted context).

    fn next_unquoted_byte(&mut self) -> Option<u8> {
        loop {
            match self.peek_raw() {
                Some(b'\\') => {
                    self.offset += 1;
                    match self.peek_raw() {
                        Some(b'\n') => {
                            self.offset += 1;
                            self.line += 1;
                            self.line_start = self.offset;
                            continue;
                        }
                        Some(b'\r') => {
                            self.offset += 1;
                            return Some(b'\r');
                        }
                        _ => continue,
                    }
                }
                Some(c) => {
                    self.offset += 1;
                    return Some(c);
                }
                None => return None,
            }
        }
    }

    // Consume leading continuations before dispatch.
    fn consume_leading_continuations(&mut self) {
        loop {
            match self.peek_raw() {
                Some(b'\\') => {
                    let saved = self.save_cursor();
                    self.offset += 1;
                    match self.peek_raw() {
                        Some(b'\n') => {
                            self.offset += 1;
                            self.line += 1;
                            self.line_start = self.offset;
                            // Continue to check for more continuations
                        }
                        _ => {
                            // Not a continuation, restore cursor
                            self.restore_cursor(saved);
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    // -- Whitespace skipping (uses logical cursor for continuation) --

    fn skip_whitespace(&mut self) {
        // Use peek_raw for whitespace (no continuation needed for spaces)
        while matches!(self.peek_raw(), Some(b' ') | Some(b'\t')) {
            self.offset += 1;
        }
        // Check for continuation after whitespace
        self.consume_leading_continuations();
    }

    // -- Error recovery (uses logical cursor so escaped newlines are skipped) --

    fn recover_to_newline(&mut self) {
        loop {
            match self.next_unquoted_byte() {
                None => break,
                Some(b'\n') => {
                    self.unread();
                    break;
                }
                _ => continue,
            }
        }
    }

    // -- Main lex entry point --

    pub fn next_token(&mut self) -> Token {
        // Error recovery
        if self.recovering {
            self.recover_to_newline();
            self.recovering = false;
        }

        // Consume leading continuations
        self.consume_leading_continuations();

        // Skip whitespace
        self.skip_whitespace();

        let start = self.offset;
        let current_line = self.line;

        if self.is_eof() {
            return self.make_token(TokenKind::Eof, start, current_line);
        }

        if self.peek_raw() == Some(b'\n') {
            self.offset += 1;
            self.line += 1;
            self.line_start = self.offset;
            return self.make_token(TokenKind::Newline, start, current_line);
        }

        let b = self.peek_raw().unwrap();

        // Comment — don't consume \n, handle continuation for line extension
        if b == b'#' {
            loop {
                match self.peek_raw() {
                    None => return self.next_token(),
                    Some(b'\n') => return self.next_token(),
                    Some(b'\\') => {
                        let saved = self.save_cursor();
                        self.offset += 1;
                        if self.peek_raw() == Some(b'\n') {
                            // Continuation — comment continues on next line
                            self.offset += 1;
                            self.line += 1;
                            self.line_start = self.offset;
                        } else {
                            // Not a continuation — restore and consume
                            self.restore_cursor(saved);
                            self.offset += 1;
                        }
                    }
                    Some(b'\0') => {
                        self.offset += 1;
                        self.recovering = true;
                        return self.error_token(LexErrorKind::EmbeddedNul, start, current_line);
                    }
                    _ => {
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

        // Number or minus
        if b == b'-' || b.is_ascii_digit() {
            return self.lex_number_or_string(start, current_line);
        }

        // String-start characters
        if is_string_start(b) {
            return self.lex_unquoted(start, current_line);
        }

        // Punctuation symbol
        if b.is_ascii_punctuation() {
            self.offset += 1;
            return self.make_token(TokenKind::Symbol(b), start, current_line);
        }

        self.lex_unquoted(start, current_line)
    }

    // -----------------------------------------------------------------------
    // Number-or-string
    // -----------------------------------------------------------------------

    fn lex_number_or_string(&mut self, start: usize, line: usize) -> Token {
        let saved = self.save_cursor();
        let first = self.next_unquoted_byte();

        let start_negative = first == Some(b'-');

        // If the first byte wasn't '-' or a digit, restore and lex as unquoted.
        if !start_negative && !first.map_or(false, |b| b.is_ascii_digit()) {
            self.restore_cursor(saved);
            return self.lex_unquoted(start, line);
        }

        // Scan digits using the logical unquoted cursor so that
        // backslash-newline continuation is consumed (matching lgetc(0)).
        let mut digits = Vec::new();
        if let Some(b) = first {
            if b.is_ascii_digit() {
                digits.push(b);
            }
        }

        loop {
            match self.next_unquoted_byte() {
                Some(b) if b.is_ascii_digit() => {
                    digits.push(b);
                    if digits.len() > MAX_UNQUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, line);
                    }
                }
                Some(_) => {
                    // Non-digit — unread so terminator survives for terminator check.
                    self.unread();
                    break;
                }
                None => break,
            }
        }

        // Lone '-' with no following digits → symbol.
        if digits.is_empty() && start_negative {
            return self.make_token(TokenKind::Symbol(b'-'), start, line);
        }

        let terminator = self.peek_raw();

        if digits.is_empty() || !terminator.map_or(true, is_number_terminator) {
            // Not a valid number context — restore cursor and re-lex as unquoted.
            self.restore_cursor(saved);
            return self.lex_unquoted(start, line);
        }

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
        let quote = self.bump_raw().unwrap();
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
                    // Raw newline inside quoted string: increment line, do NOT
                    // add newline to bytes (matching OpenNTPD's behavior).
                    self.line += 1;
                    self.line_start = self.offset;
                }
                Some(c) if c == quote => break,
                Some(b'\\') => {
                    match self.bump_raw() {
                        Some(b'\n') => {
                            self.line += 1;
                            self.line_start = self.offset;
                        }
                        Some(b'\0') => {
                            self.recovering = true;
                            return self.error_token(LexErrorKind::EmbeddedNul, start, line);
                        }
                        Some(c) if c == quote || c == b' ' || c == b'\t' => {
                            bytes.push(c);
                        }
                        Some(c) => {
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
                    self.unread();
                    break;
                }
                Some(b'#') => {
                    self.unread();
                    break;
                }
                Some(b'\0') => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::EmbeddedNul, start, line);
                }
                Some(c) if !is_allowed_in_unquoted(c) => {
                    self.unread();
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

        if let Some(kw) = Keyword::try_match(&bytes) {
            return self.make_token(TokenKind::Keyword(kw), start, line);
        }

        let config_str = ConfigString::new(bytes)
            .expect("unquoted string contains NUL (should have been rejected above)");
        self.make_token(TokenKind::String(config_str), start, line)
    }

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

    fn kinds(input: &[u8]) -> Vec<&'static str> {
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
    }

    // -- Comments --
    #[test]
    fn comment_only() {
        assert_eq!(kinds(b"# comment\nserver\n"), &["nl", "kw", "nl"]);
    }
    #[test]
    fn comment_at_eof() {
        assert!(lex_all(b"# comment")
            .iter()
            .all(|t| matches!(t.kind, TokenKind::Eof)));
    }
    #[test]
    fn continuation_extends_comment() {
        assert_eq!(kinds(b"# cont\\\ninued\nserver\n"), &["nl", "kw", "nl"]);
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
        assert!(matches!(
            Lexer::new(b"9223372036854775808").next_token().kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
    }
    #[test]
    fn number_overflow_neg() {
        assert!(matches!(
            Lexer::new(b"-9223372036854775809").next_token().kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
    }
    #[test]
    fn lone_minus_symbol() {
        assert_eq!(Lexer::new(b"-").next_token().kind, TokenKind::Symbol(b'-'));
    }
    #[test]
    fn number_then_slash() {
        assert_eq!(kinds(b"123/"), &["num", "sym"]);
    }
    #[test]
    fn number_then_space() {
        assert_eq!(kinds(b"123 "), &["num"]);
    }
    #[test]
    fn number_then_newline() {
        assert_eq!(kinds(b"123\n"), &["num", "nl"]);
    }
    #[test]
    fn number_continuation() {
        // 12\ + newline + 3 -> number 123
        assert_eq!(kinds(b"12\\\n3\n"), &["num", "nl"]);
        let mut l = Lexer::new(b"12\\\n3");
        assert_eq!(l.next_token().kind, TokenKind::Number(123));
    }

    // -- Number fallback to string --
    #[test]
    fn numeric_ipv4_is_string() {
        assert_eq!(kinds(b"192.0.2.1"), &["str"]);
    }
    #[test]
    fn numeric_ipv6_is_string() {
        assert_eq!(kinds(b"2001:db8::1"), &["str"]);
    }
    #[test]
    fn digit_prefixed_hostname() {
        assert_eq!(kinds(b"0.pool.ntp.org"), &["str"]);
    }
    #[test]
    fn digits_followed_by_alpha() {
        assert_eq!(kinds(b"123abc"), &["str"]);
    }
    #[test]
    fn digit_hyphen_digit() {
        assert_eq!(kinds(b"1-2"), &["str"]);
    }

    // -- Global continuation --
    #[test]
    fn continuation_between_tokens() {
        assert_eq!(kinds(b"server\\\n pool.ntp.org\n"), &["kw", "str", "nl"]);
    }
    #[test]
    fn continuation_at_start_of_line() {
        assert_eq!(kinds(b"\\\nserver\n"), &["kw", "nl"]);
    }
    #[test]
    fn recovery_skips_escaped_newline() {
        // Line with unterminated content followed by continuation on next line
        // 'bad' + continuation + 'rest' reads as one string via next_unquoted_byte
        assert_eq!(kinds(b"bad\\\nrest\n"), &["str", "nl"]);
    }

    // -- String-start characters --
    #[test]
    fn wildcard_is_string() {
        assert_eq!(kinds(b"*"), &["str"]);
    }
    #[test]
    fn wildcard_listen() {
        assert_eq!(
            kinds(b"listen on * rtable 0\n"),
            &["kw", "kw", "str", "kw", "num", "nl"]
        );
    }
    #[test]
    fn colon_prefixed_string() {
        assert_eq!(kinds(b"::1"), &["str"]);
    }
    #[test]
    fn underscore_prefixed_string() {
        assert_eq!(kinds(b"_ntp"), &["str"]);
    }

    // -- Quoted strings --
    #[test]
    fn quoted_double() {
        assert_eq!(
            Lexer::new(b"\"hello\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"hello".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_single() {
        assert_eq!(
            Lexer::new(b"'world'").next_token().kind,
            TokenKind::String(ConfigString::new(b"world".to_vec()).unwrap())
        );
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
        assert!(
            matches!(&Lexer::new(b"\"\"").next_token().kind, TokenKind::String(s) if s.as_bytes().is_empty())
        );
    }
    #[test]
    fn unterminated_quote_eof() {
        assert!(lex_all(b"\"hello")
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::UnterminatedQuote))));
    }
    #[test]
    fn unterminated_quote_newline() {
        let toks = lex_all(b"\"hello\n");
        // Raw newline continues the string (line inc, no byte added).
        // Unterminated only at EOF.
        assert!(toks
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Error(LexErrorKind::UnterminatedQuote))));
    }

    // -- Quoted escape sequences --
    #[test]
    fn quoted_escaped_quote() {
        assert_eq!(
            Lexer::new(b"\"he\\\"llo\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"he\"llo".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_escaped_space() {
        assert_eq!(
            Lexer::new(b"\"hello\\ world\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"hello world".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_escaped_tab() {
        assert_eq!(
            Lexer::new(b"\"hello\\\tworld\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"hello\tworld".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_unknown_escape() {
        assert_eq!(
            Lexer::new(b"\"hello\\x\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"hello\\x".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_escaped_nul_returns_error() {
        // \0 after backslash inside quote
        let mut l = Lexer::new(b"\"a\\\0b\"");
        let tok = l.next_token();
        assert!(matches!(
            tok.kind,
            TokenKind::Error(LexErrorKind::EmbeddedNul)
        ));
    }

    // -- Quoted raw newline --
    #[test]
    fn quoted_raw_newline_continues() {
        let toks = lex_all(b"\"hello\nworld\"\n");
        assert_eq!(toks.len(), 3); // string + newline + eof
        match &toks[0].kind {
            // Raw newline increments line but is NOT added to bytes
            TokenKind::String(s) => assert_eq!(s.as_bytes(), b"helloworld"),
            _ => panic!(),
        }
    }

    // -- Backslash-newline continuation --
    #[test]
    fn unquoted_continuation_merges() {
        assert_eq!(kinds(b"ser\\\nver"), &["kw"]); // "server" -> keyword
    }
    #[test]
    fn unquoted_backslash_removed() {
        assert_eq!(kinds(b"ser\\ver"), &["kw"]); // "server" -> keyword
    }
    #[test]
    fn quoted_backslash_newline() {
        assert_eq!(kinds(b"\"hello \\\nworld\"\n"), &["str", "nl"]);
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
    fn recovery_after_nul() {
        assert_eq!(kinds(b"bad\0\nserver\n"), &["err", "nl", "kw", "nl"]);
    }
    #[test]
    fn recovery_after_overflow() {
        assert_eq!(
            kinds(b"99999999999999999999\nserver\n"),
            &["err", "nl", "kw", "nl"]
        );
    }
    #[test]
    fn recovery_after_unterminated_quote() {
        // Quote continues across newline, consumes to EOF
        assert_eq!(kinds(b"\"unterminated\nserver\n"), &["err"]);
    }

    // -- Symbols --
    #[test]
    fn symbols() {
        assert_eq!(kinds(b"(){};"), &["sym", "sym", "sym", "sym", "sym"]);
    }

    // -- Unquoted character class --
    #[test]
    fn unquoted_slash_terminates() {
        assert_eq!(kinds(b"foo/bar"), &["str", "sym", "str"]);
    }
    #[test]
    fn unquoted_at_sign_permitted() {
        assert_eq!(kinds(b"foo@bar"), &["str"]);
    }
    #[test]
    fn unquoted_question_mark_permitted() {
        assert_eq!(kinds(b"foo?bar"), &["str"]);
    }
    #[test]
    fn unquoted_semicolon_terminates() {
        assert_eq!(kinds(b"foo;bar"), &["str", "sym", "str"]);
    }
    #[test]
    fn unquoted_bracket_terminates() {
        assert_eq!(kinds(b"foo[bar"), &["str", "sym", "str"]);
    }
    #[test]
    fn unquoted_paren_terminates() {
        assert_eq!(kinds(b"foo(bar"), &["str", "sym", "str"]);
    }
    #[test]
    fn unquoted_bang_terminates() {
        assert_eq!(kinds(b"foo!bar"), &["str", "sym", "str"]);
    }
    #[test]
    fn unquoted_comma_terminates() {
        assert_eq!(kinds(b"foo,bar"), &["str", "sym", "str"]);
    }

    // -- Token length boundaries --
    #[test]
    fn quoted_limit_8094() {
        let mut input = vec![b'"'];
        input.extend(core::iter::repeat(b'a').take(MAX_QUOTED_LENGTH));
        input.push(b'"');
        assert!(matches!(lex_all(&input)[0].kind, TokenKind::String(_)));
    }
    #[test]
    fn quoted_limit_8095_rejected() {
        let mut input = vec![b'"'];
        input.extend(core::iter::repeat(b'a').take(MAX_QUOTED_LENGTH + 1));
        input.push(b'"');
        assert!(matches!(
            lex_all(&input)[0].kind,
            TokenKind::Error(LexErrorKind::TokenTooLong)
        ));
    }
    #[test]
    fn unquoted_limit_8095() {
        assert!(matches!(
            lex_all(&vec![b'a'; MAX_UNQUOTED_LENGTH])[0].kind,
            TokenKind::String(_)
        ));
    }
    #[test]
    fn unquoted_limit_8096_rejected() {
        assert!(matches!(
            lex_all(&vec![b'a'; MAX_UNQUOTED_LENGTH + 1])[0].kind,
            TokenKind::Error(LexErrorKind::TokenTooLong)
        ));
    }

    // -- Integration --
    #[test]
    fn simple_directive_line() {
        assert_eq!(
            kinds(b"server pool.ntp.org weight 5\n"),
            &["kw", "str", "kw", "num", "nl"]
        );
    }
    #[test]
    fn listen_directive_line() {
        assert_eq!(
            kinds(b"listen on * rtable 0\n"),
            &["kw", "kw", "str", "kw", "num", "nl"]
        );
    }
}
