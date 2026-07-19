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
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    lexer: Lexer<'a>,
    /// One-token lookahead buffer.  `None` means the buffer is empty and
    /// the next `advance()` must pull from the lexer.
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

    /// Pull the next token — from lookahead if available, otherwise from
    /// the lexer.
    fn advance(&mut self) -> Token {
        self.lookahead
            .take()
            .unwrap_or_else(|| self.lexer.next_token())
    }

    /// Peek at the next token without consuming it.
    fn peek(&mut self) -> &Token {
        if self.lookahead.is_none() {
            self.lookahead = Some(self.lexer.next_token());
        }
        self.lookahead.as_ref().unwrap()
    }

    /// Push a diagnostic.
    fn error(&mut self, msg: impl Into<alloc::string::String>, span: Option<SourceSpan>) {
        self.diagnostics.push(Diagnostic::error(msg, span));
    }

    fn warning(&mut self, msg: impl Into<alloc::string::String>, span: Option<SourceSpan>) {
        self.diagnostics.push(Diagnostic::warning(msg, span));
    }

    // -- Token classifier helpers --

    /// Return (name, span) for the peeked token, cloning to avoid
    /// borrow conflicts with `self.error()`.
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

    /// Skip tokens until the next Newline (or EOF).  Used for error
    /// recovery within a directive.
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

    // -- Option parser helpers --

    /// Expect the next token to be a specific keyword, consuming it.
    /// On mismatch, emit an error and recover to the next newline.
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

    /// Try to parse an optional keyword-triggered option.  `parser` is a
    /// closure that parses the option's value(s) after the keyword has
    /// been consumed.  Returns `true` if the keyword matched.
    fn try_option<F>(&mut self, keyword: Keyword, mut parse_value: F) -> bool
    where
        F: FnMut(&mut Self) -> bool,
    {
        if !self.is_keyword(keyword) {
            return false;
        }
        self.advance(); // consume keyword
        if !parse_value(self) {
            // parse_value already emitted an error
            self.recover_to_newline();
        }
        true
    }

    /// Consume and return a string token value.
    fn take_string(&mut self) -> Option<ConfigString> {
        match &self.peek().kind {
            TokenKind::String(s) => {
                let val = s.clone();
                self.advance();
                Some(val)
            }
            _ => None,
        }
    }

    /// Consume and return a number token value.
    fn take_number(&mut self) -> Option<i64> {
        match &self.peek().kind {
            TokenKind::Number(n) => {
                let val = *n;
                self.advance();
                Some(val)
            }
            _ => None,
        }
    }

    // -- Parse error helper --

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

/// Parse an `ntpd.conf` configuration.
///
/// Returns a [`ParseResult`] containing the parsed [`Config`] and any
/// diagnostics (errors and warnings).  The config is always populated
/// with whatever could be parsed; call `result.is_valid()` to check for
/// errors.
pub fn parse_config(input: &[u8]) -> ParseResult {
    let mut parser = Parser::new(input);
    let mut directives: Vec<Spanned<Directive>> = Vec::new();

    loop {
        // Skip blank lines
        while parser.is_newline_or_eof() {
            if matches!(parser.peek().kind, TokenKind::Eof) {
                return ParseResult {
                    config: Config { directives },
                    diagnostics: parser.diagnostics,
                };
            }
            parser.advance(); // consume Newline
        }

        let tok = parser.peek().clone();
        let start = tok.span.start;

        match &tok.kind {
            // `listen on <address> [rtable <num>]`
            TokenKind::Keyword(Keyword::Listen) => {
                parser.advance();
                if !parser.expect_keyword(Keyword::On) {
                    continue;
                }
                if let Some(dir) = parser.parse_listen_options(start) {
                    directives.push(dir);
                }
            }

            // `server <address> [weight <n>] [trusted]`
            TokenKind::Keyword(Keyword::Server) => {
                parser.advance();
                if let Some(dir) = parser.parse_server_options(start, ServerKind::Single) {
                    directives.push(dir);
                }
            }

            // `servers <address> [weight <n>] [trusted]`
            TokenKind::Keyword(Keyword::Servers) => {
                parser.advance();
                if let Some(dir) = parser.parse_server_options(start, ServerKind::Pool) {
                    directives.push(dir);
                }
            }

            // `constraint <host>[/<path>] [<ip> ...]`
            TokenKind::Keyword(Keyword::Constraint) => {
                parser.advance();
                if let Some(dir) = parser.parse_constraint_options(start, false) {
                    directives.push(dir);
                }
            }

            // `constraints <host>[/<path>]`
            TokenKind::Keyword(Keyword::Constraints) => {
                parser.advance();
                if let Some(dir) = parser.parse_constraint_options(start, true) {
                    directives.push(dir);
                }
            }

            // `sensor <device> [correction <n>] [refid <str>] [stratum <n>] [weight <n>] [trusted]`
            TokenKind::Keyword(Keyword::Sensor) => {
                parser.advance();
                if let Some(dir) = parser.parse_sensor_options(start) {
                    directives.push(dir);
                }
            }

            // `query from <ip>`
            TokenKind::Keyword(Keyword::Query) => {
                parser.advance();
                if !parser.expect_keyword(Keyword::From) {
                    continue;
                }
                if let Some(dir) = parser.parse_query_from_options(start) {
                    directives.push(dir);
                }
            }

            // Error token from lexer
            TokenKind::Error(_) => {
                let err_tok = parser.advance();
                parser.error(
                    alloc::format!("lexical error: {}", token_kind_name(&err_tok.kind)),
                    Some(err_tok.span),
                );
                parser.recover_to_newline();
            }

            // Unexpected token at line start
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
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Directive parsers
// ---------------------------------------------------------------------------

impl<'a> Parser<'a> {
    /// `listen on <address> [rtable <num>]`
    fn parse_listen_options(&mut self, start: usize) -> Option<Spanned<Directive>> {
        let address = self.parse_listen_address()?;

        let mut rtable = RoutingTable::new(0);
        let mut had_error = false;

        loop {
            if self.is_newline_or_eof() {
                self.advance(); // consume newline/eof
                break;
            }
            if !self.try_option(Keyword::Rtable, |p| match p.take_number() {
                Some(n) if n >= 0 => {
                    rtable = RoutingTable::new(n as u32);
                    true
                }
                Some(n) => {
                    p.error(
                        alloc::format!("rtable value must be non-negative, got {n}"),
                        None,
                    );
                    false
                }
                None => {
                    p.emit_unexpected("number after 'rtable'");
                    false
                }
            }) {
                // Unknown option
                let (name, span) = self.peek_name_and_span();
                self.error(
                    alloc::format!("unexpected option '{}' for listen", name),
                    Some(span),
                );
                self.recover_to_newline();
                had_error = true;
                break;
            }
        }

        if had_error {
            return None;
        }

        let end = self.lexer_offset();
        Some(Spanned::new(
            Directive::Listen(ListenDirective { address, rtable }),
            SourceSpan::new(start, end),
        ))
    }

    /// `server` / `servers <address> [weight <n>] [trusted]`
    fn parse_server_options(
        &mut self,
        start: usize,
        kind: ServerKind,
    ) -> Option<Spanned<Directive>> {
        let address = self.parse_server_address()?;

        let mut options = ServerOptions::default();
        let mut had_error = false;

        loop {
            if self.is_newline_or_eof() {
                self.advance();
                break;
            }
            if !self.try_server_option(&mut options) {
                let (name, span) = self.peek_name_and_span();
                self.error(
                    alloc::format!("unexpected option '{}' for server", name),
                    Some(span),
                );
                self.recover_to_newline();
                had_error = true;
                break;
            }
        }

        if had_error {
            return None;
        }

        let end = self.lexer_offset();
        let dir = match kind {
            ServerKind::Single => ServerDirective::Single { address, options },
            ServerKind::Pool => ServerDirective::Pool { address, options },
        };
        Some(Spanned::new(
            Directive::Server(dir),
            SourceSpan::new(start, end),
        ))
    }

    fn try_server_option(&mut self, opts: &mut ServerOptions) -> bool {
        if self.try_option(Keyword::Weight, |p| match p.take_number() {
            Some(n) if (1..=10).contains(&n) => {
                opts.weight = Weight::new(n as u8).unwrap();
                true
            }
            Some(n) => {
                p.error(alloc::format!("weight must be 1..=10, got {n}"), None);
                false
            }
            None => {
                p.emit_unexpected("number after 'weight'");
                false
            }
        }) {
            return true;
        }
        if self.is_keyword(Keyword::Trusted) {
            self.advance();
            opts.trusted = true;
            return true;
        }
        false
    }

    /// `constraint[s] <host>[/<path>] [<ip> ...]`
    fn parse_constraint_options(
        &mut self,
        start: usize,
        is_pool: bool,
    ) -> Option<Spanned<Directive>> {
        // Read host (string token).  May be followed by /path.
        let host_bytes = match self.take_string() {
            Some(s) => s.as_bytes().to_vec(),
            None => {
                self.emit_unexpected("constraint host");
                self.recover_to_newline();
                return None;
            }
        };

        // Check for `/path` suffix (lexed as separate Symbol('/') + String).
        let path_bytes = if matches!(self.peek().kind, TokenKind::Symbol(b'/')) {
            self.advance(); // consume '/'
                            // Consume the path string after '/'
            let path_token = self.take_string();
            path_token
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"/".to_vec())
        } else {
            b"/".to_vec()
        };

        let host = self.host_bytes_to_hostname(&host_bytes);

        let mut pinned = Vec::new();

        if !is_pool {
            // Pinned IP addresses until newline/EOF
            loop {
                if self.is_newline_or_eof() {
                    break;
                }
                match self.peek().kind {
                    TokenKind::String(_) => {
                        let s = self.take_string().unwrap();
                        let bytes = s.as_bytes().to_vec();
                        match parse_ip_addr(&bytes) {
                            Some(ip) => pinned.push(ip),
                            None => {
                                self.error(
                                    alloc::format!(
                                        "invalid pinned address '{}'",
                                        StringRepr(&bytes),
                                    ),
                                    None,
                                );
                            }
                        }
                    }
                    _ => {
                        self.emit_unexpected("pinned IP address");
                        self.recover_to_newline();
                        break;
                    }
                }
            }
        }

        if !self.is_newline_or_eof() {
            // consume the terminator
            self.advance();
        }

        let endpoint = ConstraintEndpoint {
            host,
            path: ConfigString::new(path_bytes)
                .unwrap_or_else(|| ConfigString::new(b"/".to_vec()).unwrap()),
        };

        let end = self.lexer_offset();
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

    fn host_bytes_to_hostname(&self, bytes: &[u8]) -> HostNameOrIp {
        match parse_ip_addr(bytes) {
            Some(ip) => HostNameOrIp::Numeric(ip),
            None => HostNameOrIp::Name(
                ConfigString::new(bytes.to_vec())
                    .unwrap_or_else(|| ConfigString::new(b"invalid".to_vec()).unwrap()),
            ),
        }
    }

    /// Read a token sequence that forms a device path (may start with `/`).
    fn parse_device_path(&mut self) -> Option<ConfigString> {
        let mut bytes = Vec::new();
        // Collect tokens until we see a known option keyword or newline/EOF.
        loop {
            match &self.peek().kind {
                TokenKind::Symbol(b'/') => {
                    self.advance();
                    bytes.push(b'/');
                }
                TokenKind::String(s) => {
                    bytes.extend_from_slice(s.as_bytes());
                    self.advance();
                }
                TokenKind::Number(n) => {
                    let s = alloc::format!("{n}");
                    bytes.extend_from_slice(s.as_bytes());
                    self.advance();
                }
                _ => break,
            }
        }
        if bytes.is_empty() {
            None
        } else {
            ConfigString::new(bytes)
        }
    }

    /// `sensor <device> [correction <n>] [refid <str>] [stratum <n>] [weight <n>] [trusted]`
    fn parse_sensor_options(&mut self, start: usize) -> Option<Spanned<Directive>> {
        let device = match self.parse_device_path() {
            Some(s) => s,
            None => {
                self.emit_unexpected("sensor device path");
                self.recover_to_newline();
                return None;
            }
        };

        let mut options = SensorOptions::default();
        let mut had_error = false;

        loop {
            if self.is_newline_or_eof() {
                self.advance();
                break;
            }
            if !self.try_sensor_option(&mut options) {
                let (name, span) = self.peek_name_and_span();
                self.error(
                    alloc::format!("unexpected option '{}' for sensor", name),
                    Some(span),
                );
                self.recover_to_newline();
                had_error = true;
                break;
            }
        }

        if had_error {
            return None;
        }

        let end = self.lexer_offset();
        Some(Spanned::new(
            Directive::Sensor(SensorDirective { device, options }),
            SourceSpan::new(start, end),
        ))
    }

    fn try_sensor_option(&mut self, opts: &mut SensorOptions) -> bool {
        if self.try_option(Keyword::Correction, |p| match p.take_number() {
            Some(n)
                if (CorrectionMicros::MIN as i64..=CorrectionMicros::MAX as i64).contains(&n) =>
            {
                opts.correction = CorrectionMicros::new(n as i32).unwrap();
                true
            }
            Some(n) => {
                p.error(
                    alloc::format!(
                        "correction must be {}..={}, got {n}",
                        CorrectionMicros::MIN,
                        CorrectionMicros::MAX,
                    ),
                    None,
                );
                false
            }
            None => {
                p.emit_unexpected("number after 'correction'");
                false
            }
        }) {
            return true;
        }
        if self.try_option(Keyword::RefId, |p| match p.take_string() {
            Some(s) => match RefId::from_bytes(s.as_bytes()) {
                Some(r) => {
                    opts.refid = Some(r);
                    true
                }
                None => {
                    p.error(
                        alloc::format!(
                            "invalid refid '{}' (must be 1..=4 non-NUL bytes)",
                            StringRepr(s.as_bytes()),
                        ),
                        None,
                    );
                    false
                }
            },
            None => {
                p.emit_unexpected("string after 'refid'");
                false
            }
        }) {
            return true;
        }
        if self.try_option(Keyword::Stratum, |p| match p.take_number() {
            Some(n) if (1..=15).contains(&n) => {
                opts.stratum = Stratum::new(n as u8).unwrap();
                true
            }
            Some(n) => {
                p.error(alloc::format!("stratum must be 1..=15, got {n}"), None);
                false
            }
            None => {
                p.emit_unexpected("number after 'stratum'");
                false
            }
        }) {
            return true;
        }
        if self.try_option(Keyword::Weight, |p| match p.take_number() {
            Some(n) if (1..=10).contains(&n) => {
                opts.weight = Weight::new(n as u8).unwrap();
                true
            }
            Some(n) => {
                p.error(alloc::format!("weight must be 1..=10, got {n}"), None);
                false
            }
            None => {
                p.emit_unexpected("number after 'weight'");
                false
            }
        }) {
            return true;
        }
        if self.is_keyword(Keyword::Trusted) {
            self.advance();
            opts.trusted = true;
            return true;
        }
        false
    }

    /// `query from <ip>`
    fn parse_query_from_options(&mut self, start: usize) -> Option<Spanned<Directive>> {
        let addr = match self.take_string() {
            Some(s) => {
                let bytes = s.as_bytes().to_vec();
                match parse_ip_addr(&bytes) {
                    Some(ip) => ip,
                    None => {
                        self.error(
                            alloc::format!(
                                "'query from' requires a numeric IP address, got '{}'",
                                StringRepr(&bytes),
                            ),
                            None,
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

        if !self.is_newline_or_eof() {
            self.emit_unexpected("newline after 'query from'");
            self.recover_to_newline();
        } else {
            self.advance();
        }

        let end = self.lexer_offset();
        Some(Spanned::new(
            Directive::QueryFrom(addr),
            SourceSpan::new(start, end),
        ))
    }

    // -- Address helpers --

    fn parse_listen_address(&mut self) -> Option<ListenAddress> {
        match self.peek().kind {
            TokenKind::String(_) => {
                let s = self.take_string().unwrap();
                let bytes = s.as_bytes().to_vec();
                // Wildcard
                if bytes.len() == 1 && bytes[0] == b'*' {
                    Some(ListenAddress::Wildcard)
                } else {
                    match parse_ip_addr(&bytes) {
                        Some(ip) => Some(ListenAddress::Numeric(ip)),
                        None => Some(ListenAddress::Name(ConfigString::new(bytes).unwrap())),
                    }
                }
            }
            _ => {
                self.emit_unexpected("address (IP, hostname, or '*')");
                self.recover_to_newline();
                None
            }
        }
    }

    fn parse_server_address(&mut self) -> Option<ServerAddress> {
        match self.peek().kind {
            TokenKind::String(_) => {
                let s = self.take_string().unwrap();
                let bytes = s.as_bytes().to_vec();
                match parse_ip_addr(&bytes) {
                    Some(ip) => Some(ServerAddress::Numeric(ip)),
                    None => Some(ServerAddress::Name(ConfigString::new(bytes).unwrap())),
                }
            }
            _ => {
                self.emit_unexpected("address (IP or hostname)");
                self.recover_to_newline();
                None
            }
        }
    }

    fn lexer_offset(&self) -> usize {
        // After consuming tokens, the lexer's offset is at the end of the
        // last consumed token.  We use the peek token's span.end, or if
        // there's nothing in lookahead, the lexer's offset.
        self.lookahead
            .as_ref()
            .map(|t| t.span.end)
            .unwrap_or(self.lexer.offset())
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
    use alloc::string::ToString;
    use alloc::vec;

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
                    ListenAddress::Numeric("0.0.0.0".parse().unwrap())
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
    }

    // -- Constraint --
    #[test]
    fn constraint_single() {
        let r = parse(b"constraint www.example.com\n");
        assert_valid(&r);
        assert_eq!(r.config.directives.len(), 1);
    }

    #[test]
    fn constraint_single_with_pinned() {
        let r = parse(b"constraint www.example.com 1.2.3.4 5.6.7.8\n");
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
    fn constraint_with_path() {
        let r = parse(b"constraint www.example.com/ntp\n");
        assert_valid(&r);
    }

    #[test]
    fn constraints_pool() {
        let r = parse(b"constraints www.example.com\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Constraint(c) => match c {
                ConstraintDirective::Pool { endpoint } => {
                    assert!(matches!(endpoint.host, HostNameOrIp::Name(_)));
                }
                _ => panic!("expected pool constraint"),
            },
            _ => panic!("expected constraint"),
        }
    }

    // -- Sensor --
    #[test]
    fn sensor_minimal() {
        let r = parse(b"sensor /dev/pps0\n");
        assert_valid(&r);
        let d = &r.config.directives[0];
        match &d.value {
            Directive::Sensor(s) => {
                assert_eq!(s.options.stratum, Stratum::ONE);
                assert_eq!(s.options.weight, Weight::ONE);
            }
            _ => panic!("expected sensor"),
        }
    }

    #[test]
    fn sensor_all_options() {
        let r = parse(b"sensor /dev/pps0 correction 1000 refid GPS stratum 3 weight 5 trusted\n");
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
        let r = parse(b"sensor /dev/pps0 stratum 0\n");
        assert_one_error(&r);
    }

    #[test]
    fn sensor_invalid_weight() {
        let r = parse(b"sensor /dev/pps0 weight 11\n");
        assert_one_error(&r);
    }

    #[test]
    fn sensor_invalid_correction() {
        let r = parse(b"sensor /dev/pps0 correction 999999999\n");
        assert_one_error(&r);
    }

    // -- Multiple directives --
    #[test]
    fn multiple_directives() {
        let input = b"listen on *\nserver pool.ntp.org\nsensor /dev/pps0\n";
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
        // "server" starts at 0, directive ends at 28 (after "5"),
        // newline at 28 consumed, span covers 0..29
        assert_eq!(d.span, SourceSpan::new(0, 29));
    }

    // -- Error recovery --
    #[test]
    fn error_skips_to_next_line() {
        let input = b"server pool.ntp.org invalid_opt\nlisten on *\n";
        let r = parse(input);
        // One error (invalid_opt), but listen should still parse
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
        let r = parse(b"listen on *\n\0bad\nserver p.ntp.org\n");
        // NUL error should produce a diagnostic
        assert!(!r.is_valid());
    }
}
