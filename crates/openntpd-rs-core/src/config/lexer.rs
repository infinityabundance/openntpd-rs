//! Byte-oriented lexer for `ntpd.conf` — OpenNTPD 7.9p1 lexical rules.
//!
//! ## Cursor model
//!
//! A single logical-cursor primitive reproduces OpenNTPD's `lgetc(0)`:
//!
//! - `logical_get()` — consumes backslash-newline as continuation globally,
//!   drops a backslash before any non-newline byte and returns that byte
//!   immediately (it is NOT re-processed).
//! - `logical_unget(b)` — one-byte pushback, so peek via get+unget is safe.
//!
//! All non-quoted consumption (dispatch, whitespace, comments, recovery,
//! numbers, unquoted strings) goes through `logical_get()`.
//!
//! Quoted strings use `bump_raw()` because they apply their own escape
//! rules independently.
//!
//! ## Key rules
//!
//! - Input is `&[u8]` (non-UTF-8 bytes valid in quoted strings).
//! - NUL rejected everywhere (in comments this is intentional hardening —
//!   upstream does not special-case NUL in comments).
//! - Digits followed by non-number-terminator → fall back to string.
//! - String-start characters: alphanumeric, `:`, `_`, `*`.
//! - Backslash-newline consumed globally before token classification.
//! - Raw newline inside quoted string: line incremented, byte NOT added
//!   to result.
//! - Token limits: 8094 (quoted), 8095 (unquoted/numeric, including sign).

use alloc::vec::Vec;
use core::fmt;

use super::directive::ConfigString;
use super::directive::SourceSpan;

pub const MAX_QUOTED_LENGTH: usize = 8094;
pub const MAX_UNQUOTED_LENGTH: usize = 8095;

/// Number terminators — upstream uses `isspace()` plus explicit punctuation.
/// Includes vertical tab (`\x0B`) and form feed (`\x0C`) which `isspace()`
/// matches in the C locale.
fn is_number_terminator(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C' | b')' | b',' | b'/' | b'}' | b'='
    )
}

fn is_string_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'*')
}

/// Characters allowed inside an unquoted token (OpenNTPD's upstream class).
///
/// Excludes only the punctuation that terminates unquoted strings upstream:
/// `( ) { } < > ! = / # ,`.
fn is_allowed_in_unquoted(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || (b.is_ascii_punctuation()
            && !matches!(
                b,
                b'(' | b')' | b'{' | b'}' | b'<' | b'>' | b'!' | b'=' | b'/' | b'#' | b','
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
    pushback: Option<u8>,
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
    /// One-byte pushback for the logical cursor.  Set by `logical_unget()`;
    /// consumed first by the next `logical_get()`.
    logical_pushback: Option<u8>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            line: 1,
            line_start: 0,
            recovering: false,
            logical_pushback: None,
        }
    }

    fn save_cursor(&self) -> CursorState {
        CursorState {
            offset: self.offset,
            line: self.line,
            line_start: self.line_start,
            pushback: self.logical_pushback,
        }
    }

    fn restore_cursor(&mut self, cs: CursorState) {
        self.offset = cs.offset;
        self.line = cs.line;
        self.line_start = cs.line_start;
        self.logical_pushback = cs.pushback;
    }

    // -- Raw cursor (quoted strings only) --

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

    // -- Logical cursor (reproduces OpenNTPD's lgetc(0)) --
    //
    // * Backslash-newline → consumed as continuation (line incremented).
    // * Backslash + non-newline → first backslash dropped, the following
    //   byte returned immediately (NOT re-processed).
    // * One-byte pushback via `logical_unget()` / `logical_pushback` field.
    // * All non-quoted paths go through this primitive.

    fn logical_get(&mut self) -> Option<u8> {
        if let Some(b) = self.logical_pushback.take() {
            return Some(b);
        }
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
                        Some(c) => {
                            self.offset += 1;
                            return Some(c);
                        }
                        None => return None,
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

    fn logical_unget(&mut self, b: u8) {
        self.logical_pushback = Some(b);
    }

    /// Truly side-effect-free peek.  Uses cursor save/restore so that the
    /// raw offset and pushback are both unchanged — important because the
    /// raw cursor (`bump_raw`) does not see `logical_pushback`.
    fn logical_peek(&mut self) -> Option<u8> {
        if let Some(b) = self.logical_pushback {
            return Some(b);
        }
        let saved = self.save_cursor();
        let b = self.logical_get();
        self.restore_cursor(saved);
        b
    }

    // -- Whitespace skipping --
    //
    // Spaces and tabs are consumed via `logical_peek()` + `logical_get()`
    // so that pushback bytes (left by earlier `logical_unget`) are seen.
    // Continuation (backslash-newline) is detected via the raw cursor with
    // save/restore — after whitespace consumption, pushback is always None
    // because whitespace bytes are consumed, not pushed back.

    fn skip_whitespace(&mut self) {
        loop {
            // Consume spaces and tabs using logical peek/get so that
            // bytes in pushback (e.g. a space put back by a number scanner)
            // are correctly consumed.
            loop {
                match self.logical_peek() {
                    Some(b' ') | Some(b'\t') => {
                        self.logical_get();
                    }
                    _ => break,
                }
            }
            // After whitespace, check for continuation.  Pushback is None
            // here because any whitespace bytes in pushback were consumed
            // by the inner loop.
            let saved = self.save_cursor();
            match self.peek_raw() {
                Some(b'\\') => {
                    self.offset += 1;
                    match self.peek_raw() {
                        Some(b'\n') => {
                            self.offset += 1;
                            self.line += 1;
                            self.line_start = self.offset;
                            // Continuation — loop back to skip spaces on
                            // the next physical line.
                            continue;
                        }
                        _ => {
                            self.restore_cursor(saved);
                            break;
                        }
                    }
                }
                _ => {
                    self.restore_cursor(saved);
                    break;
                }
            }
        }
    }

    // -- Error recovery (uses logical cursor so escaped newlines are skipped) --

    fn recover_to_newline(&mut self) {
        loop {
            match self.logical_get() {
                None => break,
                Some(b'\n') => {
                    // Consume the newline (do NOT put it back) — the next
                    // token starts on the next physical line.
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

        // Skip whitespace (handles leading continuations internally)
        self.skip_whitespace();

        let start = self.offset;
        let current_line = self.line;

        // Peek at the first logical byte.
        let b = match self.logical_peek() {
            None => return self.make_token(TokenKind::Eof, start, current_line),
            Some(b) => b,
        };

        // Newline
        if b == b'\n' {
            self.logical_get(); // consume
            self.line += 1;
            self.line_start = self.offset;
            return self.make_token(TokenKind::Newline, start, current_line);
        }

        // Comment — use logical_get() for continuation handling.
        if b == b'#' {
            loop {
                match self.logical_get() {
                    None => return self.next_token(),
                    Some(b'\n') => {
                        self.logical_unget(b'\n');
                        return self.next_token();
                    }
                    Some(b'\0') => {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::EmbeddedNul, start, current_line);
                    }
                    _ => continue,
                }
            }
        }

        // NUL error
        if b == b'\0' {
            self.logical_get(); // consume
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
            self.logical_get(); // consume
            return self.make_token(TokenKind::Symbol(b), start, current_line);
        }

        // Fallback: attempt unquoted
        self.lex_unquoted(start, current_line)
    }

    // -----------------------------------------------------------------------
    // Number-or-string
    // -----------------------------------------------------------------------

    fn lex_number_or_string(&mut self, start: usize, line: usize) -> Token {
        let saved = self.save_cursor();
        let first = self.logical_get();

        let start_negative = first == Some(b'-');

        // If the first byte wasn't '-' or a digit, restore and lex as unquoted.
        if !start_negative && !first.map_or(false, |b| b.is_ascii_digit()) {
            self.restore_cursor(saved);
            return self.lex_unquoted(start, line);
        }

        // Scan digits using the logical cursor so that backslash-newline
        // continuation is consumed (matching lgetc(0)).
        let mut digits = Vec::new();
        if let Some(b) = first {
            if b.is_ascii_digit() {
                digits.push(b);
            }
        }

        loop {
            match self.logical_get() {
                Some(b) if b.is_ascii_digit() => {
                    digits.push(b);
                    // Length check includes the sign byte (upstream writes
                    // the sign into the same 8096-byte buffer).
                    let token_len = digits.len() + usize::from(start_negative);
                    if token_len > MAX_UNQUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, line);
                    }
                }
                Some(c) => {
                    self.logical_unget(c);
                    break;
                }
                None => break,
            }
        }

        // Lone '-' with no following digits → symbol.
        if digits.is_empty() && start_negative {
            return self.make_token(TokenKind::Symbol(b'-'), start, line);
        }

        let terminator = self.logical_peek();

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
        // Consume the opening quote.  It may be in logical_pushback (left by
        // skip_whitespace or logical_peek) rather than at the raw offset.
        let quote = self
            .logical_pushback
            .take()
            .or_else(|| self.bump_raw())
            .expect("lex_quoted called without an opening quote");
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
                        Some(c) if c == quote || c == b'\\' || c == b' ' || c == b'\t' => {
                            bytes.push(c);
                        }
                        // Unknown escape: append the backslash and un-read the
                        // next byte so it is re-processed normally (matching
                        // OpenNTPD's lgetc-based approach where the second
                        // byte is pushed back).
                        Some(_) => {
                            bytes.push(b'\\');
                            self.offset = self.offset.saturating_sub(1);
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
            match self.logical_get() {
                None => break,
                Some(b @ (b' ' | b'\t' | b'\n' | b'\r')) => {
                    self.logical_unget(b);
                    break;
                }
                Some(b'#') => {
                    self.logical_unget(b'#');
                    break;
                }
                Some(b'\0') => {
                    // Push back NUL so the dispatcher emits the error as
                    // a separate token.  Bytes accumulated before NUL are
                    // returned as a string token.
                    self.logical_unget(b'\0');
                    break;
                }
                Some(c) if !is_allowed_in_unquoted(c) => {
                    self.logical_unget(c);
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
            None
        } else {
            Some(abs as i64)
        }
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
        assert_eq!(l.logical_get(), Some(b'a'));
        assert_eq!(l.logical_peek(), Some(b'b'));
        assert_eq!(l.logical_get(), Some(b'b'));
        assert_eq!(l.logical_get(), None);
    }
    #[test]
    fn cursor_unread() {
        let mut l = Lexer::new(b"ab");
        let a = l.logical_get();
        l.logical_unget(a.unwrap());
        assert_eq!(l.logical_get(), Some(b'a'));
        assert_eq!(l.logical_get(), Some(b'b'));
        assert_eq!(l.logical_get(), None);
    }

    // -- Comments --
    #[test]
    fn comment_only() {
        assert_eq!(kinds(b"# comment\n"), &["nl"]);
    }
    #[test]
    fn comment_at_eof() {
        let empty: Vec<&str> = vec![];
        assert_eq!(kinds(b"# comment"), empty);
    }
    #[test]
    fn continuation_extends_comment() {
        assert_eq!(kinds(b"# continued \\\n comment\n"), &["nl"]);
    }

    // -- Keywords --
    #[test]
    fn all_keywords() {
        let input = b"constraint constraints correction from listen on query refid rtable sensor server servers stratum trusted weight\n";
        let toks = lex_all(input);
        let keywords: Vec<Keyword> = toks
            .iter()
            .filter_map(|t| match &t.kind {
                TokenKind::Keyword(k) => Some(*k),
                _ => None,
            })
            .collect();
        assert_eq!(keywords.len(), 15);
        assert!(keywords.contains(&Keyword::Constraint));
        assert!(keywords.contains(&Keyword::Constraints));
        assert!(keywords.contains(&Keyword::Correction));
        assert!(keywords.contains(&Keyword::From));
        assert!(keywords.contains(&Keyword::Listen));
        assert!(keywords.contains(&Keyword::On));
        assert!(keywords.contains(&Keyword::Query));
        assert!(keywords.contains(&Keyword::RefId));
        assert!(keywords.contains(&Keyword::Rtable));
        assert!(keywords.contains(&Keyword::Sensor));
        assert!(keywords.contains(&Keyword::Server));
        assert!(keywords.contains(&Keyword::Servers));
        assert!(keywords.contains(&Keyword::Stratum));
        assert!(keywords.contains(&Keyword::Trusted));
        assert!(keywords.contains(&Keyword::Weight));
    }
    #[test]
    fn keyword_case_sensitive() {
        assert_eq!(kinds(b"Server"), &["str"]);
        assert_eq!(kinds(b"SERVER"), &["str"]);
    }

    // -- Numbers --
    #[test]
    fn number_positive() {
        assert_eq!(kinds(b"123 "), &["num"]);
    }
    #[test]
    fn number_negative() {
        assert_eq!(kinds(b"-123 "), &["num"]);
    }
    #[test]
    fn number_zero() {
        assert_eq!(kinds(b"0 "), &["num"]);
    }
    #[test]
    fn number_i64_min() {
        assert_eq!(kinds(b"-9223372036854775808 "), &["num"]);
    }
    #[test]
    fn number_i64_max() {
        assert_eq!(kinds(b"9223372036854775807 "), &["num"]);
    }
    #[test]
    fn number_overflow_pos() {
        assert_eq!(kinds(b"9223372036854775808 "), &["err"]);
    }
    #[test]
    fn number_overflow_neg() {
        assert_eq!(kinds(b"-9223372036854775809 "), &["err"]);
    }
    #[test]
    fn lone_minus_symbol() {
        assert_eq!(kinds(b"- "), &["sym"]);
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
        assert_eq!(kinds(b"bad\\\nrest\n"), &["str", "nl"]);
    }

    // -- Backslash handling --
    #[test]
    fn leading_backslash_before_keyword() {
        assert_eq!(kinds(b"\\server\n"), &["kw", "nl"]);
    }
    #[test]
    fn double_backslash_preserves_second() {
        // First \ dropped, second \ preserved in unquoted string.
        assert_eq!(kinds(b"server\\\\.example\n"), &["str", "nl"]);
    }
    #[test]
    fn whitespace_continuation_with_indentation() {
        assert_eq!(
            kinds(b"server \\\n    pool.ntp.org\n"),
            &["kw", "str", "nl"]
        );
    }

    // -- String-start characters --
    #[test]
    fn wildcard_is_string() {
        assert_eq!(kinds(b"* "), &["str"]);
    }
    #[test]
    fn wildcard_listen() {
        assert_eq!(kinds(b"* rtable"), &["str", "kw"]);
    }
    #[test]
    fn colon_prefixed_string() {
        assert_eq!(kinds(b"::1 "), &["str"]);
    }
    #[test]
    fn underscore_prefixed_string() {
        assert_eq!(kinds(b"_ntp "), &["str"]);
    }

    // -- Quoted strings --
    #[test]
    fn quoted_double() {
        assert_eq!(kinds(b"\"hello\" "), &["str"]);
    }
    #[test]
    fn quoted_single() {
        assert_eq!(kinds(b"'hello' "), &["str"]);
    }
    #[test]
    fn quoted_non_utf8() {
        assert_eq!(
            Lexer::new(b"\"hello\xffworld\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"hello\xffworld".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_empty() {
        let mut l = Lexer::new(b"\"\"");
        assert_eq!(
            l.next_token().kind,
            TokenKind::String(ConfigString::new(b"".to_vec()).unwrap())
        );
    }
    #[test]
    fn unterminated_quote_eof() {
        assert_eq!(kinds(b"\"hello"), &["err"]);
    }
    #[test]
    fn unterminated_quote_newline() {
        // Raw newline inside quote is consumed (line increments, no token).
        assert_eq!(kinds(b"\"hello\n"), &["err"]);
    }
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
    fn quoted_consecutive_backslashes() {
        // "\\" -> one backslash (\\ is a known escape -> single \\)
        let mut l = Lexer::new(b"\"\\\\\"");
        assert_eq!(
            l.next_token().kind,
            TokenKind::String(ConfigString::new(b"\\".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_backslash_before_closing_quote() {
        let mut l = Lexer::new(b"\"\\\"\"");
        assert_eq!(
            l.next_token().kind,
            TokenKind::String(ConfigString::new(b"\"".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_escaped_nul_returns_error() {
        assert_eq!(kinds(b"\"a\\\0b\""), &["err"]);
    }
    #[test]
    fn quoted_raw_newline_continues() {
        let toks = lex_all(b"\"hello\nworld\"\n");
        assert_eq!(toks.len(), 3);
        match &toks[0].kind {
            TokenKind::String(s) => assert_eq!(s.as_bytes(), b"helloworld"),
            _ => panic!(),
        }
    }

    // -- Backslash-newline continuation --
    #[test]
    fn unquoted_continuation_merges() {
        assert_eq!(kinds(b"ser\\\nver"), &["kw"]);
    }
    #[test]
    fn unquoted_backslash_removed() {
        assert_eq!(kinds(b"ser\\ver"), &["kw"]);
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
        // Bytes before NUL returned as string, then NUL error.
        assert_eq!(kinds(b"foo\0bar"), &["str", "err"]);
    }
    #[test]
    fn nul_quoted() {
        assert_eq!(kinds(b"\"foo\0bar\""), &["err"]);
    }
    #[test]
    fn nul_comment() {
        // NUL in comment triggers error; recovery consumes the newline.
        assert_eq!(kinds(b"# foo\0bar\n"), &["err"]);
    }

    // -- Line tracking --
    #[test]
    fn newline_tracking() {
        let toks = lex_all(b"a\nb\n");
        assert_eq!(toks[0].line, 1);
        assert_eq!(toks[1].line, 1);
        assert_eq!(toks[2].line, 2);
        assert_eq!(toks[3].line, 2);
    }

    // -- Error recovery --
    #[test]
    fn recovery_after_nul() {
        // NUL error, recovery skips to next newline, then baz.
        assert_eq!(kinds(b"foo\0bar\nbaz\n"), &["str", "err", "str", "nl"]);
    }
    #[test]
    fn recovery_after_overflow() {
        // Overflow error, recovery consumes the newline, then baz.
        assert_eq!(
            kinds(b"999999999999999999999999999999\nbaz\n"),
            &["err", "str", "nl"]
        );
    }
    #[test]
    fn recovery_after_unterminated_quote() {
        // Quote consumes everything including raw newlines -> error only.
        assert_eq!(kinds(b"\"foo\nbar\n"), &["err"]);
    }

    // -- Punctuation symbols (standalone) --
    #[test]
    fn symbols() {
        assert_eq!(
            kinds(b"(){};,[]"),
            &["sym", "sym", "sym", "sym", "sym", "sym", "sym", "sym"]
        );
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
    fn semicolon_inside_unquoted_string() {
        assert_eq!(kinds(b"foo;bar"), &["str"]);
    }
    #[test]
    fn brackets_inside_unquoted_string() {
        assert_eq!(kinds(b"foo[bar]"), &["str"]);
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
        let payload = vec![b'a'; 8094];
        let mut input = Vec::new();
        input.push(b'"');
        input.extend_from_slice(&payload);
        input.push(b'"');
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::String(_)));
    }
    #[test]
    fn quoted_limit_8095_rejected() {
        let payload = vec![b'a'; 8095];
        let mut input = Vec::new();
        input.push(b'"');
        input.extend_from_slice(&payload);
        input.push(b'"');
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::Error(_)));
    }
    #[test]
    fn unquoted_limit_8095() {
        let payload = vec![b'a'; 8095];
        let tok = Lexer::new(&payload).next_token();
        assert!(matches!(tok.kind, TokenKind::String(_)));
    }
    #[test]
    fn unquoted_limit_8096_rejected() {
        let payload = vec![b'a'; 8096];
        let tok = Lexer::new(&payload).next_token();
        assert!(matches!(tok.kind, TokenKind::Error(_)));
    }
    #[test]
    fn negative_number_8095_total_accepted() {
        let mut input = Vec::new();
        input.push(b'-');
        input.extend(core::iter::repeat(b'9').take(8094));
        input.push(b' ');
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::Error(_)));
    }
    #[test]
    fn negative_number_8096_total_rejected() {
        let mut input = Vec::new();
        input.push(b'-');
        input.extend(core::iter::repeat(b'9').take(8095));
        input.push(b' ');
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::Error(_)));
        if let TokenKind::Error(e) = &tok.kind {
            assert!(matches!(e, LexErrorKind::TokenTooLong));
        }
    }
    #[test]
    fn positive_number_8095_total_accepted() {
        let mut input = Vec::new();
        input.extend(core::iter::repeat(b'9').take(8095));
        input.push(b' ');
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::Error(_)));
    }

    // -- Number terminator variants --
    #[test]
    fn number_terminator_vertical_tab() {
        let input: Vec<u8> = b"123\x0B".to_vec();
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::Number(123)));
    }
    #[test]
    fn number_terminator_form_feed() {
        let input: Vec<u8> = b"123\x0C".to_vec();
        let tok = Lexer::new(&input).next_token();
        assert!(matches!(tok.kind, TokenKind::Number(123)));
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
