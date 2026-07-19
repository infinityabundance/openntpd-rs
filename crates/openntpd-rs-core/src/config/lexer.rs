//! Byte-oriented lexer for `ntpd.conf` — OpenNTPD 7.9p1 lexical rules.
//!
//! ## Cursor model
//!
//! A single logical-cursor primitive reproduces OpenNTPD's `lgetc(0)`:
//!
//! - `logical_get()` — consumes backslash-newline as continuation globally,
//!   drops a backslash before any non-newline byte and returns that byte
//!   immediately (it is NOT re-processed).
//! - `logical_unget(b)` — one-byte pushback storing the byte's raw end
//!   position, so spans remain delimiter-accurate after pushback.
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
//!   A leading `-` is split: the minus becomes a Symbol token and the
//!   digit sequence becomes the next (string) token, matching `parse.y`.
//! - String-start characters: alphanumeric, `:`, `_`, `*`.
//! - Backslash-newline consumed globally before token classification.
//! - Raw newline inside quoted string: line incremented, byte NOT added
//!   to result.
//! - Quoted escape rules: `\` before the active quote, space, or tab
//!   includes only the target; `\` before any other byte includes both
//!   the backslash and the target (no pushback, no re-processing).
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
    pushback: Option<(u8, usize)>,
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
    /// Pushback carries the byte and the raw end position at the time
    /// `logical_unget()` was called, so token spans remain accurate.
    logical_pushback: Option<(u8, usize)>,
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
    // * Pushback carries raw_end so spans are accurate after unget.

    fn logical_get(&mut self) -> Option<u8> {
        if let Some((b, _)) = self.logical_pushback.take() {
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
        // Store the raw offset at the time of pushback (the position past
        // the byte just consumed) so the caller can compute an accurate
        // token end: `self.offset` before unget is `end_of_byte`.
        self.logical_pushback = Some((b, self.offset));
    }

    /// Truly side-effect-free peek.  Uses cursor save/restore so that the
    /// raw offset and pushback are both unchanged — important because the
    /// raw cursor (`bump_raw`) does not see `logical_pushback`.
    fn logical_peek(&mut self) -> Option<u8> {
        if let Some((b, _)) = self.logical_pushback {
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
            loop {
                match self.logical_peek() {
                    Some(b' ') | Some(b'\t') => {
                        self.logical_get();
                    }
                    _ => break,
                }
            }
            // Do NOT consume raw continuation if a delimiter is pending
            // in logical pushback — the pushed byte must be emitted as
            // a token before any following input is consumed.
            if self.logical_pushback.is_some() {
                break;
            }
            let saved = self.save_cursor();
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

    // -- Error recovery --
    //
    // Uses the logical cursor so escaped newlines are skipped as
    // continuations.  The terminating newline is consumed and the
    // line counter is advanced.

    fn recover_to_newline(&mut self) {
        loop {
            match self.logical_get() {
                None => break,
                Some(b'\n') => {
                    self.line += 1;
                    self.line_start = self.offset;
                    break;
                }
                _ => continue,
            }
        }
    }

    /// For a byte obtained via `logical_peek()`, compute its source start.
    /// If the byte came from pushback, its raw position is `raw_end - 1`;
    /// otherwise the byte is at `self.offset`.
    fn peek_source_start(&self, default_start: usize) -> usize {
        self.logical_pushback
            .map(|(_, end)| end.saturating_sub(1))
            .unwrap_or(default_start)
    }

    // -- Main lex entry point --

    pub fn next_token(&mut self) -> Token {
        if self.recovering {
            self.recover_to_newline();
            self.recovering = false;
        }

        self.skip_whitespace();

        let raw_start = self.offset;
        let current_line = self.line;

        let b = match self.logical_peek() {
            None => return self.make_token(TokenKind::Eof, raw_start, raw_start, current_line),
            Some(b) => b,
        };

        if b == b'\n' {
            let start = self.peek_source_start(raw_start);
            self.logical_get();
            self.line += 1;
            self.line_start = self.offset;
            return self.make_token(TokenKind::Newline, start, self.offset, current_line);
        }

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
                        return self.error_token(
                            LexErrorKind::EmbeddedNul,
                            raw_start,
                            self.offset,
                            current_line,
                        );
                    }
                    _ => continue,
                }
            }
        }

        if b == b'\0' {
            self.logical_get();
            self.recovering = true;
            return self.error_token(
                LexErrorKind::EmbeddedNul,
                raw_start,
                self.offset,
                current_line,
            );
        }

        if b == b'"' || b == b'\'' {
            return self.lex_quoted(raw_start, current_line);
        }

        if b == b'-' || b.is_ascii_digit() {
            return self.lex_number_or_string(raw_start, current_line);
        }

        if is_string_start(b) {
            return self.lex_unquoted(raw_start, current_line);
        }

        if b.is_ascii_punctuation() {
            let start = self.peek_source_start(raw_start);
            self.logical_get();
            return self.make_token(TokenKind::Symbol(b), start, self.offset, current_line);
        }

        // Unrecognized byte — return as symbol (matching upstream).
        let start = self.peek_source_start(raw_start);
        self.logical_get();
        self.make_token(TokenKind::Symbol(b), start, self.offset, current_line)
    }

    // -----------------------------------------------------------------------
    // Number-or-string
    // -----------------------------------------------------------------------
    //
    // Positive digit prefix (e.g. `123abc`) falls back to a single
    // unquoted string token: String("123abc").
    //
    // Negative digit prefix (e.g. `-123abc`) splits into a minus Symbol
    // followed by a (non-number) String: Symbol('-'), String("123abc").

    fn lex_number_or_string(&mut self, start: usize, line: usize) -> Token {
        let saved = self.save_cursor();
        let first = self.logical_get();
        let start_negative = first == Some(b'-');

        if !start_negative && !first.map_or(false, |b| b.is_ascii_digit()) {
            self.restore_cursor(saved);
            return self.lex_unquoted(start, line);
        }

        // Save state after the potential minus (for negative fallback).
        let after_minus = if start_negative {
            Some(self.save_cursor())
        } else {
            None
        };
        let minus_end = if start_negative {
            Some(self.offset)
        } else {
            None
        };

        let mut digits = Vec::new();
        let mut end = self.offset;
        if let Some(b) = first {
            if b.is_ascii_digit() {
                digits.push(b);
            }
        }

        loop {
            match self.logical_get() {
                Some(b) if b.is_ascii_digit() => {
                    digits.push(b);
                    end = self.offset;
                    let token_len = digits.len() + usize::from(start_negative);
                    if token_len > MAX_UNQUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(
                            LexErrorKind::TokenTooLong,
                            start,
                            self.offset,
                            line,
                        );
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
            if let Some(am) = after_minus {
                self.restore_cursor(am);
            }
            return self.make_token(
                TokenKind::Symbol(b'-'),
                start,
                minus_end.unwrap_or(end),
                line,
            );
        }

        let terminator = self.logical_peek();

        if digits.is_empty() || !terminator.map_or(true, is_number_terminator) {
            if start_negative {
                // Negative fallback: return '-' as symbol with span
                // covering only the minus; remaining digits become the
                // next token (string).
                if let Some(am) = after_minus {
                    self.restore_cursor(am);
                }
                return self.make_token(
                    TokenKind::Symbol(b'-'),
                    start,
                    minus_end.unwrap_or(end),
                    line,
                );
            }
            self.restore_cursor(saved);
            return self.lex_unquoted(start, line);
        }

        match parse_i64_from_bytes(&digits, start_negative) {
            Some(n) => self.make_token(TokenKind::Number(n), start, end, line),
            None => {
                self.recovering = true;
                self.error_token(LexErrorKind::NumberOverflow, start, end, line)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Quoted string
    // -----------------------------------------------------------------------

    fn lex_quoted(&mut self, start: usize, line: usize) -> Token {
        // Consume the opening delimiter through the logical cursor so
        // that a logically-escaped quote (backslash + quote) is handled
        // correctly: the backslash is dropped by logical_get, and the
        // quote starts the quoted string.
        let quote = self
            .logical_get()
            .expect("lex_quoted called without an opening quote");

        debug_assert!(matches!(quote, b'\'' | b'"'));

        let mut bytes = Vec::new();

        loop {
            match self.bump_raw() {
                None => {
                    self.recovering = true;
                    return self.error_token(
                        LexErrorKind::UnterminatedQuote,
                        start,
                        self.offset,
                        line,
                    );
                }
                Some(b'\0') => {
                    self.recovering = true;
                    return self.error_token(LexErrorKind::EmbeddedNul, start, self.offset, line);
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
                            return self.error_token(
                                LexErrorKind::EmbeddedNul,
                                start,
                                self.offset,
                                line,
                            );
                        }
                        // Known escapes: active quote, space, tab.
                        // Only the target byte is included.
                        Some(c) if c == quote || c == b' ' || c == b'\t' => {
                            bytes.push(c);
                        }
                        // Unknown escape: append the backslash and
                        // reprocess the target byte on the next iteration
                        // (matching OpenNTPD's lgetc-based pushback).
                        Some(_) => {
                            bytes.push(b'\\');
                            self.offset = self.offset.saturating_sub(1);
                        }
                        None => {
                            self.recovering = true;
                            return self.error_token(
                                LexErrorKind::UnterminatedQuote,
                                start,
                                self.offset,
                                line,
                            );
                        }
                    }
                    if bytes.len() > MAX_QUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(
                            LexErrorKind::TokenTooLong,
                            start,
                            self.offset,
                            line,
                        );
                    }
                }
                Some(c) => {
                    bytes.push(c);
                    if bytes.len() > MAX_QUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(
                            LexErrorKind::TokenTooLong,
                            start,
                            self.offset,
                            line,
                        );
                    }
                }
            }
        }

        let config_str = ConfigString::new(bytes)
            .expect("quoted string contains NUL (should have been rejected above)");
        self.make_token(TokenKind::String(config_str), start, self.offset, line)
    }

    // -----------------------------------------------------------------------
    // Unquoted string / keyword
    // -----------------------------------------------------------------------

    fn lex_unquoted(&mut self, start: usize, line: usize) -> Token {
        let mut bytes = Vec::new();
        let mut end = start;

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
                    self.logical_unget(b'\0');
                    break;
                }
                Some(c) if !is_allowed_in_unquoted(c) => {
                    self.logical_unget(c);
                    break;
                }
                Some(c) => {
                    bytes.push(c);
                    end = self.offset;
                    if bytes.len() > MAX_UNQUOTED_LENGTH {
                        self.recovering = true;
                        return self.error_token(LexErrorKind::TokenTooLong, start, end, line);
                    }
                }
            }
        }

        if bytes.is_empty() {
            self.recovering = true;
            return self.error_token(LexErrorKind::InvalidNumber, start, end, line);
        }

        if let Some(kw) = Keyword::try_match(&bytes) {
            return self.make_token(TokenKind::Keyword(kw), start, end, line);
        }

        let config_str = ConfigString::new(bytes)
            .expect("unquoted string contains NUL (should have been rejected above)");
        self.make_token(TokenKind::String(config_str), start, end, line)
    }

    fn make_token(&self, kind: TokenKind, start: usize, end: usize, line: usize) -> Token {
        Token {
            kind,
            span: SourceSpan::new(start, end),
            line,
        }
    }

    fn error_token(&self, kind: LexErrorKind, start: usize, end: usize, line: usize) -> Token {
        Token {
            kind: TokenKind::Error(kind),
            span: SourceSpan::new(start, end),
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
    #[test]
    fn cursor_peek_after_continuation() {
        let mut l = Lexer::new(b"\\\nx");
        assert_eq!(l.logical_peek(), Some(b'x'));
        assert_eq!(l.logical_peek(), Some(b'x')); // idempotent
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
    #[test]
    fn negative_number_after_minus_fallback() {
        // -123abc -> Symbol('-'), String("123abc")
        assert_eq!(kinds(b"-123abc"), &["sym", "str"]);
    }
    #[test]
    fn negative_number_after_minus_dotted() {
        assert_eq!(kinds(b"-1.2.3"), &["sym", "str"]);
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
        // \x is unknown: both \ and x are included.
        assert_eq!(
            Lexer::new(b"\"hello\\x\"").next_token().kind,
            TokenKind::String(ConfigString::new(b"hello\\x".to_vec()).unwrap())
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
    #[test]
    fn backslash_before_double_quote_opens_quote() {
        // \ + " -> logical_get sees " (backslash dropped), starts quoted.
        assert_eq!(kinds(b"\\\"pool.ntp.org\"\n"), &["str", "nl"]);
        let mut l = Lexer::new(b"\\\"pool.ntp.org\"");
        if let TokenKind::String(s) = &l.next_token().kind {
            assert_eq!(s.as_bytes(), b"pool.ntp.org");
        } else {
            panic!("expected string token");
        }
    }
    #[test]
    fn backslash_before_single_quote_opens_quote() {
        assert_eq!(kinds(b"\\'pool.ntp.org'\n"), &["str", "nl"]);
    }
    #[test]
    fn quoted_escaped_unknown_escape_preserves_both() {
        // \x is unknown: both backslash and x appear in output.
        let mut l = Lexer::new(b"\"\\x\"");
        assert_eq!(
            l.next_token().kind,
            TokenKind::String(ConfigString::new(b"\\x".to_vec()).unwrap())
        );
    }
    #[test]
    fn quoted_two_backslashes_before_quote_is_unterminated() {
        // "\\" -> first backslash is escape, second backslash is
        // unknown -> \ pushed, second \ reprocessed as escape ->
        // " escaped -> no closing quote remains.
        assert_eq!(kinds(b"\"\\\\\""), &["err"]);
    }
    #[test]
    fn quoted_two_backslashes_then_two_quotes() {
        // "\\"" -> \ + \ (unknown -> \ pushed, \ reprocessed),
        // then \ + " (known -> " pushed), then " closes
        // Result: String containing backslash + quote.
        let mut l = Lexer::new(b"\"\\\\\"\"");
        let tok = l.next_token();
        assert_eq!(
            tok.kind,
            TokenKind::String(ConfigString::new(b"\\\"".to_vec()).unwrap()) // b"\\\"" is two bytes: backslash (0x5C) + quote (0x22)
        );
    }
    #[test]
    fn quoted_unknown_escape_reprocesses_target() {
        // \x in a quoted string: \ pushes, x is reprocessed as
        // regular character -> \\x becomes \x in output.
        let mut l = Lexer::new(b"\"\\x\"");
        assert_eq!(
            l.next_token().kind,
            TokenKind::String(ConfigString::new(b"\\x".to_vec()).unwrap())
        );
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
        assert_eq!(kinds(b"foo\0bar"), &["str", "err"]);
    }
    #[test]
    fn nul_quoted() {
        assert_eq!(kinds(b"\"foo\0bar\""), &["err"]);
    }
    #[test]
    fn nul_comment() {
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
    #[test]
    fn recovery_advances_to_next_line() {
        let mut lexer = Lexer::new(b"999999999999999999999999\nserver pool.ntp.org\n");
        assert!(matches!(
            lexer.next_token().kind,
            TokenKind::Error(LexErrorKind::NumberOverflow)
        ));
        let server = lexer.next_token();
        assert_eq!(server.line, 2);
        assert_eq!(server.kind, TokenKind::Keyword(Keyword::Server));
    }

    // -- Error recovery --
    #[test]
    fn recovery_after_nul() {
        assert_eq!(kinds(b"foo\0bar\nbaz\n"), &["str", "err", "str", "nl"]);
    }
    #[test]
    fn recovery_after_overflow() {
        assert_eq!(
            kinds(b"999999999999999999999999999999\nbaz\n"),
            &["err", "str", "nl"]
        );
    }
    #[test]
    fn recovery_after_unterminated_quote() {
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

    // -- Non-punctuation fallback as symbol --
    #[test]
    fn non_punctuation_as_symbol() {
        // Vertical tab after a number: number + symbol(0x0B)
        let input: Vec<u8> = b"123\x0B".to_vec();
        let toks = lex_all(&input);
        assert_eq!(toks.len(), 3); // includes Eof
        assert!(matches!(toks[0].kind, TokenKind::Number(123)));
        assert_eq!(toks[1].kind, TokenKind::Symbol(b'\x0B'));
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
        assert!(matches!(tok.kind, TokenKind::Error(_))); // overflow, not TooLong
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
        assert!(matches!(tok.kind, TokenKind::Error(_))); // overflow, not TooLong
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

    // -- Span correctness --
    #[test]
    fn span_keyword_before_space() {
        let mut l = Lexer::new(b"server ");
        let tok = l.next_token();
        assert_eq!(tok.span, SourceSpan::new(0, 6));
        assert!(matches!(tok.kind, TokenKind::Keyword(Keyword::Server)));
    }
    #[test]
    fn span_number_before_newline() {
        let mut l = Lexer::new(b"123\n");
        let tok = l.next_token();
        assert_eq!(tok.span, SourceSpan::new(0, 3));
        assert!(matches!(tok.kind, TokenKind::Number(123)));
    }
    #[test]
    fn span_slash_between_strings() {
        let toks = lex_all(b"foo/bar");
        assert_eq!(toks[0].span, SourceSpan::new(0, 3));
        assert!(matches!(toks[0].kind, TokenKind::String(_)));
        assert_eq!(toks[1].span, SourceSpan::new(3, 4));
        assert!(matches!(toks[1].kind, TokenKind::Symbol(b'/')));
        assert_eq!(toks[2].span, SourceSpan::new(4, 7));
        assert!(matches!(toks[2].kind, TokenKind::String(_)));
    }
    #[test]
    fn span_newline_after_comment() {
        let mut l = Lexer::new(b"# comment\n");
        let tok = l.next_token();
        assert_eq!(tok.kind, TokenKind::Newline);
        // Comment starts at 0, newline byte is at position 9.
        assert_eq!(tok.span, SourceSpan::new(9, 10));
    }
    #[test]
    fn span_across_continuation() {
        let mut l = Lexer::new(b"ser\\\nver");
        let tok = l.next_token();
        assert_eq!(tok.span, SourceSpan::new(0, 8));
        assert!(matches!(tok.kind, TokenKind::Keyword(Keyword::Server)));
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
