# coder-core — Shared Types and Contracts

This crate defines the types shared across all other crates: API models, domain
types, configuration, storage trait contracts, and password utilities.

## Key Files

- `src/api.rs` — HTTP request/response models (~1,500 lines)
- `src/ports.rs` — Storage trait contracts (~2,000 lines)
- `src/identity.rs` — Domain types for users, orgs, API keys
- `src/config.rs` — `ServerConfig`, `DatabaseConfig`
- `src/password.rs` — PBKDF2 hashing and validation
- `src/build_info.rs` — `BuildMetadata`

## Adding API Types

Response-only:
```rust
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MyResponse { pub field: String }
```

Request-only:
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MyRequest { pub field: String }
```

Both (used in tests or round-trips):
```rust
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MyType { pub field: String }
```

Use `#[serde(default)]` for optional fields. Use `#[serde(skip_serializing_if = "Option::is_none")]` for Option fields.

## Adding Store Trait Methods

Storage contracts live in `src/ports.rs`. The trait hierarchy:

| Trait | Purpose |
|-------|---------|
| `DeploymentStore` | `ping()`, deployment metadata |
| `AuthStore` | Sessions, passwords, API keys, external auth |
| `IdentityStore` | User CRUD, org membership, roles |
| `OperationalStore` | Audit logs, health, deployment stats |
| `AppStore` | **Aggregate** — combines all of the above |

To add a new method:
1. Add it to the appropriate domain sub-trait (e.g., `IdentityStore`)
2. Also add it to `AppStore` (the aggregate used by the HTTP layer)
3. All methods must return `Result<T, StorageError>` (or a domain-specific error)

## Error Types

- `StorageError { Unavailable, InvalidData }` — generic store errors
- Domain-specific: `CreateFirstUserStoreError`, `CreateUserStoreError`, etc. — use `thiserror`
- Pattern: domain variant + `Storage(#[from] StorageError)` fallback

## Domain Types (`identity.rs`)

- Enums: implement `FromStr` + `as_str()` for DB ↔ Rust conversion
- Records: plain structs (`UserRecord`, `ApiKeyRecord`, `OrganizationRecord`)
- Input types: carry pre-processed data (e.g., `password_hash` not raw password)
