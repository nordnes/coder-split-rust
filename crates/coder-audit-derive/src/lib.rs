//! Procedural macros for the audit-diff system.
//!
//! Provides `#[derive(Auditable)]` which generates an `impl Auditable` that
//! produces an [`AuditDiff`] by comparing two instances field-by-field.
//!
//! # Field attributes
//!
//! Fields may be annotated with `#[audit(...)]`:
//!
//! | Attribute | Behavior |
//! |-----------|----------|
//! | `track` | Include in the diff on change. **Default** when unspecified. |
//! | `secret` | Include in the diff on change, but set `secret: true` so viewers redact. |
//! | `ignore` | Never emit into the diff, regardless of change. |
//!
//! ```ignore
//! use coder_audit::Auditable;
//! use coder_audit_derive::Auditable;
//!
//! #[derive(Auditable)]
//! struct User {
//!     #[audit(track)]
//!     id: u64,
//!     #[audit(secret)]
//!     hashed_password: String,
//!     #[audit(ignore)]
//!     last_seen_at: i64,
//! }
//! ```
#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Data, DeriveInput, Field, Fields, Ident, Meta, Token, parse_macro_input,
    punctuated::Punctuated, spanned::Spanned,
};

/// Per-field audit policy extracted from `#[audit(...)]`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    Track,
    Secret,
    Ignore,
}

/// `#[derive(Auditable)]` entry point.
#[proc_macro_derive(Auditable, attributes(audit))]
pub fn derive_auditable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_name = input.ident.clone();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().collect::<Vec<_>>(),
            Fields::Unit => Vec::new(),
            Fields::Unnamed(_) => {
                return Err(syn::Error::new(
                    input.span(),
                    "#[derive(Auditable)] does not support tuple structs",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "#[derive(Auditable)] is only supported on structs",
            ));
        }
    };

    let mut entries = Vec::new();
    for field in fields {
        let policy = parse_policy(field)?;
        if policy == Policy::Ignore {
            continue;
        }
        let field_ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new(field.span(), "Auditable requires named fields"))?;
        let field_name = field_ident.to_string();
        let secret_lit = policy == Policy::Secret;

        entries.push(quote! {
            if self.#field_ident != other.#field_ident {
                let old_val = ::coder_audit::_macro_support::to_json_value(&self.#field_ident);
                let new_val = ::coder_audit::_macro_support::to_json_value(&other.#field_ident);
                diff.changes.insert(
                    #field_name.to_owned(),
                    ::coder_audit::AuditFieldDiff {
                        old: old_val,
                        new: new_val,
                        secret: #secret_lit,
                    },
                );
            }
        });
    }

    let auditable_path = quote!(::coder_audit::Auditable);
    let diff_path = quote!(::coder_audit::AuditDiff);

    let expanded = quote! {
        #[automatically_derived]
        impl #impl_generics #auditable_path for #struct_name #ty_generics #where_clause {
            fn audit_diff(&self, other: &Self) -> #diff_path {
                let mut diff = #diff_path::new();
                #(#entries)*
                diff
            }
        }
    };
    Ok(expanded)
}

fn parse_policy(field: &Field) -> syn::Result<Policy> {
    let mut policy: Option<Policy> = None;
    for attr in &field.attrs {
        if !attr.path().is_ident("audit") {
            continue;
        }
        let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        for meta in nested {
            let path = meta.path();
            let ident: &Ident = path.get_ident().ok_or_else(|| {
                syn::Error::new(
                    path.span(),
                    "expected a bare identifier: `track`, `secret`, or `ignore`",
                )
            })?;
            let new_policy = match ident.to_string().as_str() {
                "track" => Policy::Track,
                "secret" => Policy::Secret,
                "ignore" => Policy::Ignore,
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "unknown audit policy `{other}`: expected `track`, `secret`, or `ignore`"
                        ),
                    ));
                }
            };
            if let Some(existing) = policy
                && existing != new_policy
            {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "conflicting `#[audit(...)]` attributes on a single field",
                ));
            }
            policy = Some(new_policy);
        }
    }
    Ok(policy.unwrap_or(Policy::Track))
}
