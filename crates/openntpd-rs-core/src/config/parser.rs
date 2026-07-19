//! Directive parser for `ntpd.conf` — OpenNTPD 7.9p1 grammar.
//!
//! Consumes the token stream from [`Lexer`] and produces a [`Config`] with
//! `Spanned<Directive>` values and a diagnostics list.
//!
//! ## Error recovery
//!
//! When a parse error is detected within a directive, the parser skips
//! tokens until the next `Newline` (or EOF), emits one error diagnostic
//! for the discarded directive, and resumes at the start of the next line.

use alloc::vec::Vec;
use core::net::IpAddr;

use super::diagnostic::{Diagnostic, ParseResult};
use super::directive::*;
use super::lexer::{Keyword, Lexer, Token, TokenKind};

// ---------------------------------------------------------------------------
// Tri-state option result
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OptionResult {
    Applied,
    Invalid,
    NotMatched,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    lexer: Lexer<'a>,
    lookahead: Option<Token>,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            lexer: Lexer::new(input),
            lookahead: None,
            diagnostics: Vec::new(),
        }
    }

    fn advance(&mut self) -> Token {
        self.lookahead
            .take()
            .unwrap_or_else(|| self.lexer.next_token())
    }

    fn peek(&mut self) -> &Token {
        if self.lookahead.is_none() {
            self.lookahead = Some(self.lexer.next_token());
        }
        self.lookahead.as_ref().unwrap()
    }

    fn error(&mut self, msg: impl Into<alloc::string::String>, span: Option<SourceSpan>) {
        self.diagnostics.push(Diagnostic::error(msg, span));
    }

    // -- Token classifiers --

    fn peek_name_and_span(&mut self) -> (alloc::string::String, SourceSpan) {
        let tok = self.peek();
        (token_kind_name(&tok.kind), tok.span)
    }

    fn is_keyword(&mut self, kw: Keyword) -> bool {
        matches!(&self.peek().kind, TokenKind::Keyword(k) if *k == kw)
    }

    fn is_newline_or_eof(&mut self) -> bool {
        matches!(&self.peek().kind, TokenKind::Newline | TokenKind::Eof)
    }

    fn recover_to_newline(&mut self) {
        loop {
            match self.peek().kind {
                TokenKind::Newline | TokenKind::Eof => break,
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn expect_keyword(&mut self, expected: Keyword) -> bool {
        if self.is_keyword(expected) {
            self.advance();
            true
        } else {
            let (name, span) = self.peek_name_and_span();
            self.error(
                alloc::format!("expected '{}', got {}", expected, name),
                Some(span),
            );
            self.recover_to_newline();
            false
        }
    }

    /// Expect end-of-line.  Returns `Ok(end_offset)` on clean newline/EOF;
    /// emits error and recovers on trailing tokens, returning `Err(())`.
    fn expect_line_end(&mut self) -> Result<usize, ()> {
        match self.peek().kind {
            TokenKind::Newline => Ok(self.advance().span.end),
            TokenKind::Eof => Ok(self.peek().span.end),
            _ => {
                self.emit_unexpected("end of line");
                self.recover_to_newline();
                Err(())
            }
        }
    }

    /// Try to consume a keyword-triggered option.  The closure receives
    /// the parser and returns `Ok(())` for valid values or `Err(())`
    /// for invalid ones (which triggers recovery and `Invalid`).
    fn try_option<F>(&mut self, keyword: Keyword, parse_value: F) -> OptionResult
    where
        F: FnOnce(&mut Self) -> Result<(), ()>,
    {
        if !self.is_keyword(keyword) {
            return OptionResult::NotMatched;
        }
        self.advance();
        match parse_value(self) {
            Ok(()) => OptionResult::Applied,
            Err(()) => {
                self.recover_to_newline();
                OptionResult::Invalid
            }
        }
    }

    fn take_string_token(&mut self) -> Option<(ConfigString, SourceSpan)> {
        match &self.peek().kind {
            TokenKind::String(s) => {
                let val = s.clone();
                let span = self.peek().span;
                self.advance();
                Some((val, span))
            }
            _ => None,
        }
    }

    fn take_number_token(&mut self) -> Option<(i64, SourceSpan)> {
        match &self.peek().kind {
            TokenKind::Number(n) => {
                let val = *n;
                let span = self.peek().span;
                self.advance();
                Some((val, span))
            }
            _ => None,
        }
    }

    fn emit_unexpected(&mut self, expected: &str) {
        let (name, span) = self.peek_name_and_span();
        self.error(
            alloc::format!("expected {}, got {}", expected, name),
            Some(span),
        );
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn parse_config(input: &[u8]) -> ParseResult {
    let mut parser = Parser::new(input);
    let mut directives: Vec<Spanned<Directive>> = Vec::new();

    loop {
        while parser.is_newline_or_eof() {
            if matches!(parser.peek().kind, TokenKind::Eof) {
                return ParseResult {
                    config: Config { directives },
                    diagnostics: parser.diagnostics,
                };
            }
            parser.advance();
        }

        let tok = parser.peek().clone();
        let start = tok.span.start;

        let result = match &tok.kind {
            TokenKind::Keyword(Keyword::Listen) => {
                parser.advance();
                if !parser.expect_keyword(Keyword::On) {
                    None
                } else {
                    parser.parse_listen(start)
                }
            }

            TokenKind::Keyword(Keyword::Server) => {
                parser.advance();
                parser.parse_server(start, ServerKind::Single)
            }

            TokenKind::Keyword(Keyword::Servers) => {
                parser.advance();
                parser.parse_server(start, ServerKind::Pool)
            }

            TokenKind::Keyword(Keyword::Constraint) => {
                parser.advance();
                if !parser.expect_keyword(Keyword::From) {
                    None
                } else {
                    parser.parse_constraint(start, false)
                }
            }

            TokenKind::Keyword(Keyword::Constraints) => {
                parser.advance();
                if !parser.expect_keyword(Keyword::From) {
                    None
                } else {
                    parser.parse_constraint(start, true)
                }
            }

            TokenKind::Keyword(Keyword::Sensor) => {
                parser.advance();
                parser.parse_sensor(start)
            }

            TokenKind::Keyword(Keyword::Query) => {
                parser.advance();
                if !parser.expect_keyword(Keyword::From) {
                    None
                } else {
                    parser.parse_query_from(start)
                }
            }

            TokenKind::Error(_) => {
                let err_tok = parser.advance();
                parser.error(
                    alloc::format!("lexical error: {}", token_kind_name(&err_tok.kind)),
                    Some(err_tok.span),
                );
                // The lexer already owns line recovery — its next_token()
                // skips the rest of the erroneous line.  Do NOT call
                // recover_to_newline() here or the following directive is lost.
                None
            }

            _ => {
                let bad = parser.advance();
                parser.error(
                    alloc::format!(
                        "unexpected {} at start of directive",
                        token_kind_name(&bad.kind),
                    ),
                    Some(bad.span),
                );
                parser.recover_to_newline();
                None
            }
        };

        if let Some(dir) = result {
            directives.push(dir);
        }
    }
}

// ---------------------------------------------------------------------------
// Directive helpers
// ---------------------------------------------------------------------------

impl<'a> Parser<'a> {
    /// `listen on <address> [rtable <num>]`
    fn parse_listen(&mut self, start: usize) -> Option<Spanned<Directive>> {
        let address = self.parse_listen_address()?;
        let mut rtable = RoutingTable::new(0);

        loop {
            if self.is_newline_or_eof() {
                break;
            }
            let rtable_ref = &mut rtable;
            match self.try_option(Keyword::Rtable, |p| {
                let (n, span) = p.take_number_token().ok_or_else(|| {
                    p.emit_unexpected("number after 'rtable'");
                })?;
                let value = u32::try_from(n).map_err(|_| {
                    p.error(
                        alloc::format!("rtable value must fit in u32, got {n}"),
                        Some(span),
                    );
                })?;
                *rtable_ref = RoutingTable::new(value);
                Ok(())
            }) {
                OptionResult::Invalid => return None,
                OptionResult::NotMatched => {
                    let (name, span) = self.peek_name_and_span();
                    self.error(
                        alloc::format!("unexpected option '{}' for listen", name),
                        Some(span),
                    );
                    self.recover_to_newline();
                    return None;
                }
                OptionResult::Applied => {}
            }
        }

        let end = match self.expect_line_end() {
            Ok(e) => e,
            Err(()) => return None,
        };
        Some(Spanned::new(
            Directive::Listen(ListenDirective { address, rtable }),
            SourceSpan::new(start, end),
        ))
    }

    // -- Server / pool --

    fn parse_server(&mut self, start: usize, kind: ServerKind) -> Option<Spanned<Directive>> {
        let address = self.parse_server_address()?;
        let mut options = ServerOptions::default();

        loop {
            if self.is_newline_or_eof() {
                break;
            }
            match self.try_server_option(&mut options) {
                OptionResult::Invalid => return None,
                OptionResult::NotMatched => {
                    let (name, span) = self.peek_name_and_span();
                    self.error(
                        alloc::format!("unexpected option '{}' for server", name),
                        Some(span),
                    );
                    self.recover_to_newline();
                    return None;
                }
                OptionResult::Applied => {}
            }
        }

        let end = match self.expect_line_end() {
            Ok(e) => e,
            Err(()) => return None,
        };
        let dir = match kind {
            ServerKind::Single => ServerDirective::Single { address, options },
            ServerKind::Pool => ServerDirective::Pool { address, options },
        };
        Some(Spanned::new(
            Directive::Server(dir),
            SourceSpan::new(start, end),
        ))
    }

    fn try_server_option(&mut self, opts: &mut ServerOptions) -> OptionResult {
        match self.try_option(Keyword::Weight, |p| {
            let (n, span) = p.take_number_token().ok_or_else(|| {
                p.emit_unexpected("number after 'weight'");
            })?;
            let min = Weight::MIN as i64;
            let max = Weight::MAX as i64;
            if !(min..=max).contains(&n) {
                p.error(
                    alloc::format!("weight must be {min}..={max}, got {n}"),
                    Some(span),
                );
                return Err(());
            }
            opts.weight = Weight::new(n as u8).expect("validated weight");
            Ok(())
        }) {
            OptionResult::Applied => return OptionResult::Applied,
            OptionResult::Invalid => return OptionResult::Invalid,
            OptionResult::NotMatched => {}
        }
        if self.is_keyword(Keyword::Trusted) {
            self.advance();
            opts.trusted = true;
            return OptionResult::Applied;
        }
        OptionResult::NotMatched
    }

    // -- Constraint / constraints --

    /// `constraint from <url> [<ip> ...]`
    /// `constraints from <url>`
    fn parse_constraint(&mut self, start: usize, is_pool: bool) -> Option<Spanned<Directive>> {
        let (url_str, url_span) = self.take_string_token().or_else(|| {
            self.emit_unexpected("constraint URL");
            self.recover_to_newline();
            None
        })?;

        let url_bytes = url_str.as_bytes();
        if is_wildcard(url_bytes) || url_bytes.starts_with(b"https://*") {
            self.error(
                alloc::format!("wildcard '*' is not valid for constraint URL"),
                Some(url_span),
            );
            self.recover_to_newline();
            return None;
        }

        let endpoint = parse_constraint_url(&url_str);

        let mut pinned = Vec::new();
        let mut pin_error = false;

        if !is_pool {
            loop {
                if self.is_newline_or_eof() {
                    break;
                }
                match self.peek().kind {
                    TokenKind::String(_) => {
                        let (s, span) = self.take_string_token().unwrap();
                        let bytes = s.as_bytes().to_vec();
                        match parse_ip_addr(&bytes) {
                            Some(ip) => pinned.push(ip),
                            None => {
                                self.error(
                                    alloc::format!(
                                        "invalid pinned address '{}'",
                                        StringRepr(&bytes),
                                    ),
                                    Some(span),
                                );
                                pin_error = true;
                                self.recover_to_newline();
                                break;
                            }
                        }
                    }
                    _ => {
                        if !self.is_newline_or_eof() {
                            self.emit_unexpected("pinned IP address");
                            self.recover_to_newline();
                            pin_error = true;
                        }
                        break;
                    }
                }
            }
        } else if !self.is_newline_or_eof() {
            // Pool constraints reject trailing tokens.
            match self.peek().kind {
                TokenKind::Newline | TokenKind::Eof => {}
                _ => {
                    let (name, span) = self.peek_name_and_span();
                    self.error(
                        alloc::format!("trailing token '{}' after constraints URL", name),
                        Some(span),
                    );
                    self.recover_to_newline();
                    pin_error = true;
                }
            }
        }

        if pin_error {
            return None;
        }

        let end = match self.expect_line_end() {
            Ok(e) => e,
            Err(()) => return None,
        };

        let dir = if is_pool {
            ConstraintDirective::Pool { endpoint }
        } else {
            ConstraintDirective::Single {
                endpoint,
                pinned_addresses: pinned,
            }
        };
        Some(Spanned::new(
            Directive::Constraint(dir),
            SourceSpan::new(start, end),
        ))
    }

    // -- Sensor --

    /// `sensor <device> [correction <n>] [refid <str>] [stratum <n>] [weight <n>] [trusted]`
    fn parse_sensor(&mut self, start: usize) -> Option<Spanned<Directive>> {
        let (device, _dev_span) = self.take_string_token().or_else(|| {
            self.emit_unexpected("sensor device string");
            self.recover_to_newline();
            None
        })?;

        let mut options = SensorOptions::default();

        loop {
            if self.is_newline_or_eof() {
                break;
            }
            match self.try_sensor_option(&mut options) {
                OptionResult::Invalid => return None,
                OptionResult::NotMatched => {
                    let (name, span) = self.peek_name_and_span();
                    self.error(
                        alloc::format!("unexpected option '{}' for sensor", name),
                        Some(span),
                    );
                    self.recover_to_newline();
                    return None;
                }
                OptionResult::Applied => {}
            }
        }

        let end = match self.expect_line_end() {
            Ok(e) => e,
            Err(()) => return None,
        };
        Some(Spanned::new(
            Directive::Sensor(SensorDirective { device, options }),
            SourceSpan::new(start, end),
        ))
    }

    fn try_sensor_option(&mut self, opts: &mut SensorOptions) -> OptionResult {
        macro_rules! try_sensor_kw {
            ($kw:expr, |$p:ident| $body:expr) => {
                match self.try_option($kw, |$p| $body) {
                    OptionResult::Applied => return OptionResult::Applied,
                    OptionResult::Invalid => return OptionResult::Invalid,
                    OptionResult::NotMatched => {}
                }
            };
        }

        try_sensor_kw!(Keyword::Correction, |p| {
            let (n, span) = p.take_number_token().ok_or_else(|| {
                p.emit_unexpected("number after 'correction'");
            })?;
            if !(CorrectionMicros::MIN as i64..=CorrectionMicros::MAX as i64).contains(&n) {
                p.error(
                    alloc::format!(
                        "correction must be {}..={}, got {n}",
                        CorrectionMicros::MIN,
                        CorrectionMicros::MAX,
                    ),
                    Some(span),
                );
                return Err(());
            }
            opts.correction = CorrectionMicros::new(n as i32).ok_or(())?;
            Ok(())
        });

        try_sensor_kw!(Keyword::RefId, |p| {
            let (s, span) = p.take_string_token().ok_or_else(|| {
                p.emit_unexpected("string after 'refid'");
            })?;
            match RefId::from_bytes(s.as_bytes()) {
                Some(r) => {
                    opts.refid = Some(r);
                    Ok(())
                }
                None => {
                    p.error(
                        alloc::format!(
                            "invalid refid '{}' (must be 1..=4 non-NUL bytes)",
                            StringRepr(s.as_bytes()),
                        ),
                        Some(span),
                    );
                    Err(())
                }
            }
        });

        try_sensor_kw!(Keyword::Stratum, |p| {
            let (n, span) = p.take_number_token().ok_or_else(|| {
                p.emit_unexpected("number after 'stratum'");
            })?;
            let min = Stratum::MIN as i64;
            let max = Stratum::MAX as i64;
            if !(min..=max).contains(&n) {
                p.error(
                    alloc::format!("stratum must be {min}..={max}, got {n}"),
                    Some(span),
                );
                return Err(());
            }
            opts.stratum = Stratum::new(n as u8).expect("validated stratum");
            Ok(())
        });

        try_sensor_kw!(Keyword::Weight, |p| {
            let (n, span) = p.take_number_token().ok_or_else(|| {
                p.emit_unexpected("number after 'weight'");
            })?;
            let min = Weight::MIN as i64;
            let max = Weight::MAX as i64;
            if !(min..=max).contains(&n) {
                p.error(
                    alloc::format!("weight must be {min}..={max}, got {n}"),
                    Some(span),
                );
                return Err(());
            }
            opts.weight = Weight::new(n as u8).expect("validated weight");
            Ok(())
        });

        if self.is_keyword(Keyword::Trusted) {
            self.advance();
            opts.trusted = true;
            return OptionResult::Applied;
        }

        OptionResult::NotMatched
    }

    // -- Query from --

    /// `query from <ip>`
    fn parse_query_from(&mut self, start: usize) -> Option<Spanned<Directive>> {
        let addr = match self.take_string_token() {
            Some((s, span)) => {
                let bytes = s.as_bytes().to_vec();
                match parse_ip_addr(&bytes) {
                    Some(ip) => ip,
                    None => {
                        self.error(
                            alloc::format!(
                                "'query from' requires a numeric IP address, got '{}'",
                                StringRepr(&bytes),
                            ),
                            Some(span),
                        );
                        self.recover_to_newline();
                        return None;
                    }
                }
            }
            None => {
                self.emit_unexpected("numeric IP address after 'query from'");
                self.recover_to_newline();
                return None;
            }
        };

        let end = match self.expect_line_end() {
            Ok(e) => e,
            Err(()) => return None,
        };
        Some(Spanned::new(
            Directive::QueryFrom(addr),
            SourceSpan::new(start, end),
        ))
    }

    // -- Address helpers --

    fn parse_listen_address(&mut self) -> Option<ListenAddress> {
        let (s, _span) = self.take_string_token().or_else(|| {
            self.emit_unexpected("address (IP, hostname, or '*')");
            self.recover_to_newline();
            None
        })?;
        let bytes = s.as_bytes().to_vec();
        if bytes.len() == 1 && bytes[0] == b'*' {
            Some(ListenAddress::Wildcard)
        } else {
            match parse_ip_addr(&bytes) {
                Some(ip) => Some(ListenAddress::Numeric(ip)),
                None => Some(ListenAddress::Name(ConfigString::new(bytes).unwrap())),
            }
        }
    }

    fn parse_server_address(&mut self) -> Option<ServerAddress> {
        let (s, span) = self.take_string_token().or_else(|| {
            self.emit_unexpected("address (IP or hostname)");
            self.recover_to_newline();
            None
        })?;
        let bytes = s.as_bytes().to_vec();
        if is_wildcard(&bytes) {
            self.error(
                alloc::format!("wildcard '*' is not valid for server address"),
                Some(span),
            );
            self.recover_to_newline();
            return None;
        }
        match parse_ip_addr(&bytes) {
            Some(ip) => Some(ServerAddress::Numeric(ip)),
            None => Some(ServerAddress::Name(ConfigString::new(bytes).unwrap())),
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint URL parsing (upstream rules)
// ---------------------------------------------------------------------------

/// Parse a constraint URL into a hostname and path.
///
/// OpenNTPD accepts the URL as one `STRING` token.  If the string begins
/// with `https://`, the scheme is removed, the hostname is split at the
/// first `/` or `\`, and the remainder becomes the path.  Without the
/// scheme, the entire string is the hostname and the path defaults to `/`.
fn parse_constraint_url(source: &ConfigString) -> ConstraintEndpoint {
    let bytes = source.as_bytes();

    let (host_bytes, path_bytes) = if let Some(rest) = bytes.strip_prefix(b"https://") {
        match rest.iter().position(|b| matches!(b, b'/' | b'\\')) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, b"/".as_slice()),
        }
    } else {
        (bytes, &b"/"[..])
    };

    let host = match parse_ip_addr(host_bytes) {
        Some(ip) => HostNameOrIp::Numeric(ip),
        None => HostNameOrIp::Name(
            ConfigString::new(host_bytes.to_vec()).expect("host bytes are non-NUL from lexer"),
        ),
    };

    ConstraintEndpoint {
        host,
        path: ConfigString::new(path_bytes.to_vec()).expect("path bytes are non-NUL from lexer"),
    }
}

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

enum ServerKind {
    Single,
    Pool,
}

// ---------------------------------------------------------------------------
// IP address parsing
// ---------------------------------------------------------------------------

fn parse_ip_addr(bytes: &[u8]) -> Option<IpAddr> {
    let s = core::str::from_utf8(bytes).ok()?;
    s.parse::<IpAddr>().ok()
}

fn is_wildcard(bytes: &[u8]) -> bool {
    bytes == b"*"
}

// ---------------------------------------------------------------------------
// Token kind name (for diagnostics)
// ---------------------------------------------------------------------------

fn token_kind_name(kind: &TokenKind) -> alloc::string::String {
    match kind {
        TokenKind::Keyword(k) => alloc::format!("keyword '{k}'"),
        TokenKind::String(s) => {
            alloc::format!("string '{}'", StringRepr(s.as_bytes()))
        }
        TokenKind::Number(n) => alloc::format!("number {n}"),
        TokenKind::Newline => "newline".into(),
        TokenKind::Symbol(b) => alloc::format!("symbol '{}'", *b as char),
        TokenKind::Eof => "end-of-file".into(),
        TokenKind::Error(e) => alloc::format!("lexer error ({e})"),
    }
}

// ---------------------------------------------------------------------------
// Byte-string display helper (for diagnostics)
// ---------------------------------------------------------------------------

struct StringRepr<'a>(&'a [u8]);

impl<'a> core::fmt::Display for StringRepr<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &b in self.0 {
            if b.is_ascii_graphic() || b == b' ' {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &[u8]) -> ParseResult {
        parse_config(input)
    }

    fn assert_valid(result: &ParseResult) {
        if !result.is_valid() {
            panic!("expected valid parse, got errors: {:?}", result.errors(),);
        }
    }

    fn assert_one_error(result: &ParseResult) {
        let errs: Vec<&str> = result.errors();
        assert_eq!(errs.len(), 1, "expected 1 error, got {errs:?}");
    }

    // -- Empty config --
    #[test]
    fn empty_config() {
        let r = parse(b"");
        assert_valid(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn blank_lines() {
        let r = parse(b"\n\n\n");
        assert_valid(&r);
        assert!(r.config.directives.is_empty());
    }

    // -- Listen --
    #[test]
    fn listen_wildcard() {
        let r = parse(b"listen on *\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Listen(l) => {
                assert_eq!(l.address, ListenAddress::Wildcard);
                assert_eq!(l.rtable, RoutingTable::new(0));
            }
            _ => panic!("expected listen"),
        }
    }

    #[test]
    fn listen_numeric() {
        let r = parse(b"listen on 0.0.0.0 rtable 7\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Listen(l) => {
                assert_eq!(
                    l.address,
                    ListenAddress::Numeric("0.0.0.0".parse().unwrap()),
                );
                assert_eq!(l.rtable, RoutingTable::new(7));
            }
            _ => panic!("expected listen"),
        }
    }

    #[test]
    fn listen_hostname() {
        let r = parse(b"listen on ntp.example.com rtable 0\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Listen(l) => {
                assert!(matches!(l.address, ListenAddress::Name(_)));
            }
            _ => panic!("expected listen"),
        }
    }

    #[test]
    fn listen_missing_on() {
        let r = parse(b"listen *\n");
        assert_one_error(&r);
    }

    #[test]
    fn invalid_listen_rtable_discards_directive() {
        let r = parse(b"listen on * rtable xyz\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn rtable_u32_overflow_rejected() {
        let r = parse(b"listen on * rtable 4294967296\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    // -- Server --
    #[test]
    fn server_minimal() {
        let r = parse(b"server pool.ntp.org\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Server(s) => match s {
                ServerDirective::Single { address, options } => {
                    assert!(matches!(address, ServerAddress::Name(_)));
                    assert_eq!(options.weight, Weight::ONE);
                    assert!(!options.trusted);
                }
                _ => panic!("expected single server"),
            },
            _ => panic!("expected server"),
        }
    }

    #[test]
    fn server_with_options() {
        let r = parse(b"server 192.168.1.1 weight 5 trusted\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Server(s) => match s {
                ServerDirective::Single { address, options } => {
                    assert_eq!(
                        *address,
                        ServerAddress::Numeric("192.168.1.1".parse().unwrap()),
                    );
                    assert_eq!(options.weight, Weight::new(5).unwrap());
                    assert!(options.trusted);
                }
                _ => panic!("expected single server"),
            },
            _ => panic!("expected server"),
        }
    }

    #[test]
    fn server_pool() {
        let r = parse(b"servers pool.ntp.org weight 3\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Server(s) => match s {
                ServerDirective::Pool { address, options } => {
                    assert!(matches!(address, ServerAddress::Name(_)));
                    assert_eq!(options.weight, Weight::new(3).unwrap());
                }
                _ => panic!("expected pool server"),
            },
            _ => panic!("expected server"),
        }
    }

    #[test]
    fn server_invalid_weight_rejected() {
        let r = parse(b"server pool.ntp.org weight 0\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn invalid_server_weight_discards_directive() {
        let r = parse(b"server pool.ntp.org weight xyz\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn server_weight_257_rejected() {
        let r = parse(b"server pool.ntp.org weight 257\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn server_weight_negative_wrap_rejected() {
        let r = parse(b"server pool.ntp.org weight -255\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn server_wildcard_rejected() {
        let r = parse(b"server *\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn servers_wildcard_rejected() {
        let r = parse(b"servers *\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    // -- Query from --
    #[test]
    fn query_from_ipv4() {
        let r = parse(b"query from 192.168.1.1\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::QueryFrom(ip) => {
                assert_eq!(*ip, "192.168.1.1".parse::<IpAddr>().unwrap());
            }
            _ => panic!("expected query from"),
        }
    }

    #[test]
    fn query_from_ipv6() {
        let r = parse(b"query from ::1\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::QueryFrom(ip) => {
                assert_eq!(*ip, "::1".parse::<IpAddr>().unwrap());
            }
            _ => panic!("expected query from"),
        }
    }

    #[test]
    fn query_from_hostname_rejected() {
        let r = parse(b"query from ntp.example.com\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn query_trailing_token_discards_directive() {
        let r = parse(b"query from 192.0.2.1 garbage\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    // -- Constraint --
    #[test]
    fn constraint_requires_from() {
        let r = parse(b"constraint www.example.com\n");
        assert_one_error(&r);
    }

    #[test]
    fn constraints_requires_from() {
        let r = parse(b"constraints www.example.com\n");
        assert_one_error(&r);
    }

    #[test]
    fn constraint_from_url() {
        let r = parse(b"constraint from www.example.com\n");
        assert_valid(&r);
        assert_eq!(r.config.directives.len(), 1);
    }

    #[test]
    fn constraint_from_quoted_https_url() {
        let r = parse(b"constraint from \"https://example.com/time\"\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Constraint(c) => match c {
                ConstraintDirective::Single { endpoint, .. } => {
                    assert!(matches!(endpoint.host, HostNameOrIp::Name(_)));
                    assert_eq!(endpoint.path.as_bytes(), b"/time");
                }
                _ => panic!("expected single constraint"),
            },
            _ => panic!("expected constraint"),
        }
    }

    #[test]
    fn constraint_https_url_defaults_path() {
        let r = parse(b"constraint from \"https://example.com\"\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Constraint(c) => match c {
                ConstraintDirective::Single { endpoint, .. } => {
                    assert_eq!(endpoint.path.as_bytes(), b"/");
                }
                _ => panic!("expected single constraint"),
            },
            _ => panic!("expected constraint"),
        }
    }

    #[test]
    fn constraint_with_pinned() {
        let r = parse(b"constraint from www.example.com 1.2.3.4 5.6.7.8\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Constraint(c) => match c {
                ConstraintDirective::Single {
                    endpoint,
                    pinned_addresses,
                } => {
                    assert!(matches!(endpoint.host, HostNameOrIp::Name(_)));
                    assert_eq!(pinned_addresses.len(), 2);
                }
                _ => panic!("expected single constraint"),
            },
            _ => panic!("expected constraint"),
        }
    }

    #[test]
    fn constraint_invalid_pinned_discards_directive() {
        let r = parse(b"constraint from example.com 192.0.2.1 not-an-ip\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn constraints_rejects_pinned() {
        let r = parse(b"constraints from example.com 192.0.2.1\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    // -- Sensor --
    #[test]
    fn sensor_single_name() {
        let r = parse(b"sensor nmea0\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Sensor(s) => {
                assert_eq!(s.device.as_bytes(), b"nmea0");
            }
            _ => panic!("expected sensor"),
        }
    }

    #[test]
    fn sensor_wildcard() {
        let r = parse(b"sensor *\n");
        assert_valid(&r);
    }

    #[test]
    fn sensor_quoted_path() {
        let r = parse(b"sensor \"/dev/pps0\"\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Sensor(s) => {
                assert_eq!(s.device.as_bytes(), b"/dev/pps0");
            }
            _ => panic!("expected sensor"),
        }
    }

    #[test]
    fn sensor_unquoted_path_rejected() {
        // /dev/pps0 starts with '/', which the lexer tokenizes as Symbol('/')
        let r = parse(b"sensor /dev/pps0\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_adjacent_strings_rejected() {
        let r = parse(b"sensor foo bar\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_number_rejected() {
        let r = parse(b"sensor 123\n");
        assert_one_error(&r);
    }

    #[test]
    fn sensor_all_options() {
        let r = parse(b"sensor nmea0 correction 1000 refid GPS stratum 3 weight 5 trusted\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Sensor(s) => {
                assert_eq!(s.options.correction, CorrectionMicros::new(1000).unwrap());
                assert_eq!(s.options.refid, RefId::from_bytes(b"GPS"));
                assert_eq!(s.options.stratum, Stratum::new(3).unwrap());
                assert_eq!(s.options.weight, Weight::new(5).unwrap());
                assert!(s.options.trusted);
            }
            _ => panic!("expected sensor"),
        }
    }

    #[test]
    fn sensor_invalid_stratum() {
        let r = parse(b"sensor nmea0 stratum 0\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_invalid_weight() {
        let r = parse(b"sensor nmea0 weight 11\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_invalid_correction() {
        let r = parse(b"sensor nmea0 correction 999999999\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_weight_257_rejected() {
        let r = parse(b"sensor nmea0 weight 257\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_stratum_257_rejected() {
        let r = parse(b"sensor nmea0 stratum 257\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn sensor_stratum_negative_wrap_rejected() {
        let r = parse(b"sensor nmea0 stratum -255\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn invalid_sensor_option_discards_directive() {
        let r = parse(b"sensor nmea0 stratum xyz\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    // -- Multiple directives --
    #[test]
    fn multiple_directives() {
        let input = b"listen on *\nserver pool.ntp.org\nsensor nmea0\n";
        let r = parse(input);
        assert_valid(&r);
        assert_eq!(r.config.directives.len(), 3);
    }

    // -- Span coverage --
    #[test]
    fn directive_span() {
        let r = parse(b"server pool.ntp.org weight 5\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        assert_eq!(d.span, SourceSpan::new(0, 29));
    }

    // -- Semantic error spans --
    #[test]
    fn semantic_error_span_weight() {
        let r = parse(b"server pool.ntp.org weight 0\n");
        assert_one_error(&r);
        // '0' is at position 27
        assert_eq!(r.diagnostics[0].span, Some(SourceSpan::new(27, 28)));
        assert!(r.diagnostics[0].message.contains("weight"));
    }

    #[test]
    fn semantic_error_span_stratum() {
        let r = parse(b"sensor nmea0 stratum 0\n");
        assert_one_error(&r);
        // '0' is at position 21
        assert_eq!(r.diagnostics[0].span, Some(SourceSpan::new(21, 22)));
        assert!(r.diagnostics[0].message.contains("stratum"));
    }

    #[test]
    fn semantic_error_span_pinned_address() {
        let r = parse(b"constraint from example.com not-an-ip\n");
        assert_one_error(&r);
        assert!(r.diagnostics[0].span.is_some());
    }

    #[test]
    fn semantic_error_span_query_address() {
        let r = parse(b"query from not-an-ip\n");
        assert_one_error(&r);
        assert!(r.diagnostics[0].span.is_some());
    }

    // -- Error recovery --
    #[test]
    fn error_skips_to_next_line() {
        let input = b"server pool.ntp.org invalid_opt\nlisten on *\n";
        let r = parse(input);
        let errs: Vec<&str> = r.errors();
        assert_eq!(errs.len(), 1, "expected 1 error, got {errs:?}");
        assert_eq!(r.config.directives.len(), 1, "listen should survive");
    }

    #[test]
    fn unknown_keyword_at_start() {
        let r = parse(b"foobar pool.ntp.org\nlisten on *\n");
        let errs: Vec<&str> = r.errors();
        assert_eq!(errs.len(), 1);
        assert_eq!(r.config.directives.len(), 1);
    }

    // -- Lexer error passthrough --
    #[test]
    fn lexer_error_passthrough() {
        let r = parse(b"listen on *\n\0bad\nserver pool.ntp.org\n");
        assert!(!r.is_valid());
    }

    #[test]
    fn lexer_error_preserves_following_directive() {
        let r = parse(b"\0bad\nserver pool.ntp.org\n");
        assert_eq!(r.errors().len(), 1);
        assert_eq!(r.config.directives.len(), 1);
        assert!(matches!(r.config.directives[0].value, Directive::Server(_)));
    }

    #[test]
    fn constraint_wildcard_rejected() {
        let r = parse(b"constraint from *\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }

    #[test]
    fn constraint_https_wildcard_rejected() {
        let r = parse(b"constraint from \"https://*\"\n");
        assert_one_error(&r);
        assert!(r.config.directives.is_empty());
    }
}
