//! Password and session token helpers for the Rust identity slice.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const HASH_SCHEME: &str = "pbkdf2-sha256";
const HASH_ITERATIONS: u32 = 65_535;
const HASH_LENGTH: usize = 64;
const SALT_LENGTH: usize = 16;
const SESSION_TOKEN_LENGTH: usize = 32;

/// Password and token helper failures.
#[derive(Debug, Error)]
pub enum PasswordError {
    /// Input validation failed.
    #[error("{0}")]
    Validation(String),
    /// Stored hash format is invalid.
    #[error("stored password hash is invalid: {0}")]
    InvalidHash(String),
}

/// Validates a username against the original Coder rules.
pub fn validate_username(username: &str) -> Result<(), PasswordError> {
    let length = username.chars().count();
    if length == 0 {
        return Err(PasswordError::Validation(
            "must be >= 1 character".to_owned(),
        ));
    }
    if length > 32 {
        return Err(PasswordError::Validation(
            "must be <= 32 characters".to_owned(),
        ));
    }
    if matches!(username, "new" | "create") {
        return Err(PasswordError::Validation(format!(
            "cannot use {username:?} as a name"
        )));
    }

    let mut previous_hyphen = false;
    for character in username.chars() {
        if character == '-' {
            if previous_hyphen {
                return Err(PasswordError::Validation(
                    "must be alphanumeric with hyphens".to_owned(),
                ));
            }
            previous_hyphen = true;
            continue;
        }

        if !character.is_ascii_alphanumeric() {
            return Err(PasswordError::Validation(
                "must be alphanumeric with hyphens".to_owned(),
            ));
        }
        previous_hyphen = false;
    }

    if username.starts_with('-') || username.ends_with('-') {
        return Err(PasswordError::Validation(
            "must be alphanumeric with hyphens".to_owned(),
        ));
    }

    Ok(())
}

/// Validates the user display name rules used by Coder.
pub fn validate_real_name(name: &str) -> Result<(), PasswordError> {
    if name.chars().count() > 128 {
        return Err(PasswordError::Validation(
            "must be <= 128 characters".to_owned(),
        ));
    }
    if name.trim() != name {
        return Err(PasswordError::Validation(
            "must not have leading or trailing whitespace".to_owned(),
        ));
    }
    Ok(())
}

/// Normalizes a real name according to Coder's existing behavior.
#[must_use]
pub fn normalize_real_name(name: &str) -> String {
    let trimmed = name.trim();
    trimmed.chars().take(128).collect()
}

/// Performs a minimal email validation suitable for the bootstrap flow.
pub fn validate_email(email: &str) -> Result<(), PasswordError> {
    let trimmed = email.trim();
    let mut parts = trimmed.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    let extra = parts.next();

    if trimmed.is_empty()
        || local.is_empty()
        || domain.is_empty()
        || extra.is_some()
        || !domain.contains('.')
    {
        return Err(PasswordError::Validation(
            "must be a valid email".to_owned(),
        ));
    }

    Ok(())
}

/// Validates a plain-text password.
pub fn validate_password(password: &str) -> Result<(), PasswordError> {
    let length = password.chars().count();
    if length == 0 {
        return Err(PasswordError::Validation(
            "must be >= 1 character".to_owned(),
        ));
    }
    if length > 64 {
        return Err(PasswordError::Validation(
            "password must be no more than 64 characters".to_owned(),
        ));
    }
    if length < 8 {
        return Err(PasswordError::Validation(
            "password must be at least 8 characters".to_owned(),
        ));
    }

    Ok(())
}

/// Hashes a password using the same PBKDF2-SHA256 string format as Coder.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let mut salt = [0_u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    Ok(encode_password_hash(password, &salt, HASH_ITERATIONS))
}

/// Verifies a plain-text password against a stored PBKDF2-SHA256 hash.
pub fn verify_password(stored_hash: &str, password: &str) -> Result<bool, PasswordError> {
    let components: Vec<&str> = stored_hash.split('$').collect();
    if components.len() != 5 || !components.first().is_some_and(|part| part.is_empty()) {
        return Err(PasswordError::InvalidHash(
            "unexpected hash component count".to_owned(),
        ));
    }
    if components[1] != HASH_SCHEME {
        return Err(PasswordError::InvalidHash(format!(
            "unexpected hash scheme: {}",
            components[1]
        )));
    }

    let iterations = components[2]
        .parse::<u32>()
        .map_err(|error| PasswordError::InvalidHash(error.to_string()))?;
    let salt = STANDARD_NO_PAD
        .decode(components[3])
        .map_err(|error| PasswordError::InvalidHash(error.to_string()))?;
    let expected = encode_password_hash(password, &salt, iterations);

    Ok(stored_hash.as_bytes().ct_eq(expected.as_bytes()).into())
}

/// Generates a new opaque session token.
#[must_use]
pub fn new_session_token() -> String {
    let mut bytes = [0_u8; SESSION_TOKEN_LENGTH];
    OsRng.fill_bytes(&mut bytes);
    STANDARD_NO_PAD.encode(bytes)
}

/// Hashes a session token for storage.
#[must_use]
pub fn hash_session_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn encode_password_hash(password: &str, salt: &[u8], iterations: u32) -> String {
    let mut derived = vec![0_u8; HASH_LENGTH];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut derived);

    format!(
        "${HASH_SCHEME}${iterations}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(derived)
    )
}
