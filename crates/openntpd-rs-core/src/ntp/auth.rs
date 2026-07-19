//! Authentication modes and extension field types for NTP.
//!
//! OpenNTPD supports four authentication modes:
//!
//! - **None**: no authentication (symmetric key or Autokey may be
//!   negotiated but nothing is currently active).
//! - **Symmetric key**: pre-shared MD5 or SHA-1 keyed digest (RFC 5905).
//! - **Autokey**: automatic key management protocol (RFC 5906) — **stub**.
//! - **NTS**: Network Time Security (RFC 8915) — **stub**.

// ---------------------------------------------------------------------------
// AuthMode
// ---------------------------------------------------------------------------

/// Authentication modes supported by OpenNTPD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// No authentication.
    None,
    /// Symmetric key (MD5/SHA-1 keyed digest).
    SymmetricKey,
    /// Autokey protocol (RFC 5906) — stub.
    Autokey,
    /// Network Time Security (RFC 8915) — stub.
    NTS,
}

impl AuthMode {
    /// Human-readable description of the mode.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::None => "no authentication",
            Self::SymmetricKey => "symmetric key (MD5/SHA-1)",
            Self::Autokey => "Autokey (RFC 5906) — stub",
            Self::NTS => "NTS (RFC 8915) — stub",
        }
    }

    /// Whether this mode requires a key exchange or pre-shared key.
    #[must_use]
    pub const fn requires_credentials(&self) -> bool {
        match self {
            Self::None => false,
            Self::SymmetricKey | Self::Autokey | Self::NTS => true,
        }
    }
}

impl core::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.description())
    }
}

// ---------------------------------------------------------------------------
// Extension field type constants (RFC 5905 / RFC 7822)
// ---------------------------------------------------------------------------

/// Extension field type for Unique Identifier (RFC 7822 § 3).
///
/// Carries a nonce or session identifier that helps correlate requests
/// with responses.
pub const EXT_FIELD_UNIQUE_ID: u16 = 0x0104;

/// Extension field type for NTS Cookie (RFC 8915 § 5.3).
///
/// Contains an encrypted cookie used by the NTS client to authenticate
/// the server and derive session keys.
pub const EXT_FIELD_NTS_COOKIE: u16 = 0x0204;

/// Extension field type for NTS Cookie Placeholder (RFC 8915 § 5.3).
///
/// Used by the client to request that the server provide a fresh cookie.
pub const EXT_FIELD_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;

/// Extension field type for the Autokey (RFC 5906) association message.
pub const EXT_FIELD_AUTOKEY_ASSOC: u16 = 0x0404; // Not in spec — example placeholder

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_mode_display_none() {
        assert_eq!(AuthMode::None.description(), "no authentication");
    }

    #[test]
    fn test_auth_mode_display_symmetric_key() {
        assert_eq!(
            AuthMode::SymmetricKey.description(),
            "symmetric key (MD5/SHA-1)"
        );
    }

    #[test]
    fn test_auth_mode_display_autokey() {
        assert!(AuthMode::Autokey.description().contains("Autokey"));
    }

    #[test]
    fn test_auth_mode_display_nts() {
        assert!(AuthMode::NTS.description().contains("NTS"));
    }

    #[test]
    fn test_auth_mode_none_requires_no_credentials() {
        assert!(!AuthMode::None.requires_credentials());
    }

    #[test]
    fn test_auth_mode_symmetric_key_requires_credentials() {
        assert!(AuthMode::SymmetricKey.requires_credentials());
    }

    #[test]
    fn test_auth_mode_autokey_requires_credentials() {
        assert!(AuthMode::Autokey.requires_credentials());
    }

    #[test]
    fn test_auth_mode_nts_requires_credentials() {
        assert!(AuthMode::NTS.requires_credentials());
    }

    #[test]
    fn test_auth_mode_debug_clone() {
        let modes = [
            AuthMode::None,
            AuthMode::SymmetricKey,
            AuthMode::Autokey,
            AuthMode::NTS,
        ];
        for &m in &modes {
            let cloned = m;
            assert_eq!(m, cloned);
            let debug = alloc::format!("{m:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_auth_mode_partial_eq() {
        assert_eq!(AuthMode::None, AuthMode::None);
        assert_ne!(AuthMode::None, AuthMode::SymmetricKey);
        assert_ne!(AuthMode::Autokey, AuthMode::NTS);
    }

    #[test]
    fn test_auth_mode_display_trait() {
        assert_eq!(alloc::format!("{}", AuthMode::None), "no authentication");
        assert!(alloc::format!("{}", AuthMode::Autokey).contains("stub"));
    }

    #[test]
    fn test_extension_field_constants_unique() {
        // Verify that constants are distinct from each other
        assert_ne!(EXT_FIELD_UNIQUE_ID, 0);
        assert_ne!(EXT_FIELD_UNIQUE_ID, EXT_FIELD_NTS_COOKIE);
        assert_ne!(EXT_FIELD_NTS_COOKIE, EXT_FIELD_NTS_COOKIE_PLACEHOLDER);
        assert_ne!(EXT_FIELD_UNIQUE_ID, EXT_FIELD_AUTOKEY_ASSOC);
    }

    #[test]
    fn test_extension_field_nts_cookie_value() {
        assert_eq!(EXT_FIELD_NTS_COOKIE, 0x0204);
    }

    #[test]
    fn test_extension_field_nts_cookie_placeholder_value() {
        assert_eq!(EXT_FIELD_NTS_COOKIE_PLACEHOLDER, 0x0304);
    }

    #[test]
    fn test_extension_field_unique_id_value() {
        assert_eq!(EXT_FIELD_UNIQUE_ID, 0x0104);
    }
}
