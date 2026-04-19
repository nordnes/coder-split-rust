//! Parsing IDP group claims out of the merged OIDC claim set.
//!
//! Mirrors Go's `AGPLIDPSync.ParseGroupClaims` + `ParseStringSliceClaim`
//! from `coderd/idpsync/group.go` and `coderd/idpsync/idpsync.go`.

use coder_core::config::OidcConfig;
use serde_json::Value;

/// Parses the group list from `merged_claims[groups_field]`.
///
/// The field name is taken from `config.groups_field`; if empty, the
/// historical default `"groups"` is used.
///
/// Behaviour (mirroring Go):
/// * If the field is missing, not an array, or an empty array — returns
///   an empty `Vec`. Logs a debug line.
/// * Non-string elements are silently dropped (Go returns an error; we
///   downgrade to a debug log + drop because this function is called on
///   the login hot path and errors would fail logins for one bad claim).
/// * A single bare string is also accepted (ADFS quirk).
/// * Duplicates are removed; ordering is stable based on first occurrence.
pub fn parse_group_claims(config: &OidcConfig, merged_claims: &Value) -> Vec<String> {
    let field = if config.groups_field.is_empty() {
        "groups"
    } else {
        config.groups_field.as_str()
    };

    let raw = match merged_claims.get(field) {
        Some(v) => v,
        None => {
            tracing::debug!(field, "OIDC claim field absent; skipping group sync");
            return Vec::new();
        }
    };

    let parsed: Vec<String> = match raw {
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (idx, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    other => {
                        tracing::debug!(
                            field,
                            index = idx,
                            kind = other_kind(other),
                            "dropping non-string element in OIDC groups claim",
                        );
                    }
                }
            }
            out
        }
        // Some IdPs (ADFS) collapse a single-element list into a string.
        Value::String(s) if !s.is_empty() => vec![s.clone()],
        other => {
            tracing::debug!(
                field,
                kind = other_kind(other),
                "OIDC claim is not an array or string; skipping group sync",
            );
            return Vec::new();
        }
    };

    dedupe_stable(parsed)
}

fn other_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn dedupe_stable(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use url::Url;

    fn oidc_config(groups_field: &str) -> OidcConfig {
        OidcConfig {
            issuer_url: Url::parse("https://example.test/").unwrap(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: false,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            groups_field: groups_field.to_owned(),
            ignore_email_verified: false,
        }
    }

    #[test]
    fn present_array_of_strings() {
        let config = oidc_config("groups");
        let claims = json!({ "groups": ["admin", "devs", "admin"] });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["admin".to_owned(), "devs".to_owned()],
            "duplicates should be collapsed preserving first-seen order",
        );
    }

    #[test]
    fn absent_field_returns_empty() {
        let config = oidc_config("groups");
        let claims = json!({ "email": "x@y.z" });
        assert!(parse_group_claims(&config, &claims).is_empty());
    }

    #[test]
    fn non_array_returns_empty() {
        let config = oidc_config("groups");
        let claims = json!({ "groups": 42 });
        assert!(parse_group_claims(&config, &claims).is_empty());
    }

    #[test]
    fn single_string_collapsed_is_accepted() {
        let config = oidc_config("groups");
        let claims = json!({ "groups": "sole-group" });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["sole-group".to_owned()],
        );
    }

    #[test]
    fn mixed_types_drops_non_strings() {
        let config = oidc_config("groups");
        let claims = json!({ "groups": ["admin", 7, null, "devs"] });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["admin".to_owned(), "devs".to_owned()],
        );
    }

    #[test]
    fn custom_groups_field_name() {
        let config = oidc_config("roles");
        let claims = json!({ "roles": ["a", "b"], "groups": ["c"] });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["a".to_owned(), "b".to_owned()],
        );
    }

    #[test]
    fn empty_groups_field_falls_back_to_groups() {
        let config = oidc_config("");
        let claims = json!({ "groups": ["fallback"] });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["fallback".to_owned()],
        );
    }
}
