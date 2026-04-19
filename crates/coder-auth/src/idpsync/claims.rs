//! Parsing IDP claims out of the merged OIDC claim set.
//!
//! Mirrors Go's `AGPLIDPSync.ParseGroupClaims` / `ParseStringSliceClaim`
//! / `ParseOrganizationClaims` / `RolesFromClaim` from `coderd/idpsync/`.

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
/// * If `config.group_allow_list` is non-empty, any group not present
///   in the allow list is dropped. This matches Go's allow-list
///   short-circuit in `ParseGroupClaims` — except that here we simply
///   filter rather than failing the login; the callee handles an empty
///   list as "no groups to sync". Login rejection on an empty allow-list
///   intersection is deferred to the callback, where the full
///   `HTTPError` context is available.
pub fn parse_group_claims(config: &OidcConfig, merged_claims: &Value) -> Vec<String> {
    let field = if config.groups_field.is_empty() {
        "groups"
    } else {
        config.groups_field.as_str()
    };

    let parsed = parse_string_slice(field, merged_claims);

    if config.group_allow_list.is_empty() {
        return parsed;
    }
    let allow: std::collections::HashSet<&str> =
        config.group_allow_list.iter().map(String::as_str).collect();
    parsed
        .into_iter()
        .filter(|g| allow.contains(g.as_str()))
        .collect()
}

/// Parses the organization list from `merged_claims[field]`.
///
/// `field` is the org-claim name configured on
/// [`coder_core::api::OrganizationSyncSettings`]. Empty field or absent
/// claim yields an empty `Vec`. Parsing edge cases mirror
/// [`parse_group_claims`].
pub fn parse_org_claims(field: &str, merged_claims: &Value) -> Vec<String> {
    if field.is_empty() {
        return Vec::new();
    }
    parse_string_slice(field, merged_claims)
}

/// Parses the role list from `merged_claims[field]`.
///
/// Mirrors Go's `AGPLIDPSync.RolesFromClaim`. Absent claim yields an
/// empty vector (no diagnostics: Go treats "no claim" as "user is only
/// a member", which is the same as the empty-list case).
pub fn parse_role_claims(field: &str, merged_claims: &Value) -> Vec<String> {
    if field.is_empty() {
        return Vec::new();
    }
    parse_string_slice(field, merged_claims)
}

fn parse_string_slice(field: &str, merged_claims: &Value) -> Vec<String> {
    let raw = match merged_claims.get(field) {
        Some(v) => v,
        None => {
            tracing::debug!(field, "OIDC claim field absent; skipping");
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
                            "dropping non-string element in OIDC claim",
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
                "OIDC claim is not an array or string; skipping",
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
            group_allow_list: Vec::new(),
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

    #[test]
    fn group_allow_list_filters_out_disallowed() {
        let mut config = oidc_config("groups");
        config.group_allow_list = vec!["admin".to_owned(), "ops".to_owned()];
        let claims = json!({ "groups": ["admin", "devs", "ops", "contractors"] });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["admin".to_owned(), "ops".to_owned()],
        );
    }

    #[test]
    fn empty_allow_list_preserves_all_groups() {
        let config = oidc_config("groups");
        let claims = json!({ "groups": ["admin", "devs"] });
        assert_eq!(
            parse_group_claims(&config, &claims),
            vec!["admin".to_owned(), "devs".to_owned()],
        );
    }

    #[test]
    fn allow_list_with_no_match_returns_empty() {
        let mut config = oidc_config("groups");
        config.group_allow_list = vec!["staff".to_owned()];
        let claims = json!({ "groups": ["admin", "devs"] });
        assert!(parse_group_claims(&config, &claims).is_empty());
    }

    #[test]
    fn parse_org_claims_array() {
        let claims = json!({ "orgs": ["o1", "o2", "o1"] });
        assert_eq!(
            parse_org_claims("orgs", &claims),
            vec!["o1".to_owned(), "o2".to_owned()],
        );
    }

    #[test]
    fn parse_org_claims_empty_field() {
        let claims = json!({ "orgs": ["o1"] });
        assert!(parse_org_claims("", &claims).is_empty());
    }

    #[test]
    fn parse_org_claims_absent() {
        let claims = json!({ "email": "x@y.z" });
        assert!(parse_org_claims("orgs", &claims).is_empty());
    }

    #[test]
    fn parse_org_claims_non_array() {
        let claims = json!({ "orgs": 42 });
        assert!(parse_org_claims("orgs", &claims).is_empty());
    }

    #[test]
    fn parse_org_claims_single_string() {
        let claims = json!({ "orgs": "solo" });
        assert_eq!(parse_org_claims("orgs", &claims), vec!["solo".to_owned()],);
    }

    #[test]
    fn parse_role_claims_array() {
        let claims = json!({ "roles": ["a", "b"] });
        assert_eq!(
            parse_role_claims("roles", &claims),
            vec!["a".to_owned(), "b".to_owned()],
        );
    }

    #[test]
    fn parse_role_claims_empty_field() {
        let claims = json!({ "roles": ["a"] });
        assert!(parse_role_claims("", &claims).is_empty());
    }

    #[test]
    fn parse_role_claims_absent_returns_empty() {
        // Go treats absence as "user is only a member", which is identical
        // to an empty set — no error.
        let claims = json!({ "email": "x@y.z" });
        assert!(parse_role_claims("roles", &claims).is_empty());
    }
}
