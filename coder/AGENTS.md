# ⛔ READ-ONLY REFERENCE — DO NOT MODIFY

This directory contains the original Go source code for Coder
(`https://github.com/coder/coder`). It exists solely as a **reference**
for the Rust rewrite happening in the parent directory.

## Rules

- **DO NOT edit, add, or delete any files in this directory or its subdirectories.**
- **DO NOT commit changes to this directory.**
- Use this code only to understand what the Go implementation does.
- All new code goes in `../crates/` and `../apps/`.

## Navigation Guide

- Backend route handlers: `coderd/*.go`
- SDK client and API models: `codersdk/*.go`
- Database SQL queries: `coderd/database/queries/*.sql`
- Database Go models: `coderd/database/*.go`
- Migrations: `coderd/database/migrations/`
