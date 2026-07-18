use super::directive;
use alloc::{string::String, vec::Vec};
use core::fmt;

pub use super::directive::SourceSpan;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
    Note,
}
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
            Self::Note => write!(f, "note"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub span: Option<SourceSpan>,
}
impl Diagnostic {
    pub fn error(message: impl Into<String>, span: Option<SourceSpan>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            span,
        }
    }
    pub fn warning(message: impl Into<String>, span: Option<SourceSpan>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            span,
        }
    }
    pub fn note(message: impl Into<String>, span: Option<SourceSpan>) -> Self {
        Self {
            severity: Severity::Note,
            message: message.into(),
            span,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParseResult {
    pub config: directive::Config,
    pub diagnostics: Vec<Diagnostic>,
}
impl ParseResult {
    pub fn is_valid(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
    pub fn errors(&self) -> Vec<&str> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.message.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn test_diag_error() {
        let d = Diagnostic::error("bad", Some(SourceSpan::new(5, 10)));
        assert_eq!(d.severity, Severity::Error);
    }
    #[test]
    fn test_parse_valid() {
        let r = ParseResult {
            config: directive::Config::new(),
            diagnostics: vec![Diagnostic::note("info", None)],
        };
        assert!(r.is_valid());
    }
    #[test]
    fn test_parse_invalid() {
        let r = ParseResult {
            config: directive::Config::new(),
            diagnostics: vec![Diagnostic::error("bad", None)],
        };
        assert!(!r.is_valid());
    }
}
