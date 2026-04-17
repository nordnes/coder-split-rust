# Remaining Behavioral Gaps

> **Scope:** This document enumerates places where the Rust handler is
> reachable and returns a sane shape, but the underlying semantics still
> differ from the Go reference in `coder/`. Additional categories tracked
> on the `devin/1776360969-remaining-behavioral-gaps` branch will merge
> here eventually; for now this file tracks gaps introduced or left open
> by in-flight feature work on `main`.

## Azure instance-identity: PKCS7 verification not yet implemented

**Location:** `crates/coder-server/src/instance_identity/azure.rs`

**Go reference:** `coder/coderd/azureidentity/azureidentity.go`

Standard Azure IMDS attested-data
(`http://169.254.169.254/metadata/attested/document?api-version=…`)
returns a **base64-encoded PKCS7/CMS envelope**, not a JWT. The Go
reference decodes the PKCS7, walks the cert chain to a bundled set of
Microsoft intermediate CAs, matches the signer cert's
`Subject.CommonName` against
`^(.*\.)?metadata\.(azure\.(com|us|cn)|microsoftazure\.de)$`, and reads
`vmId` from the inner JSON content.

The Rust port of the workspace-agent bootstrap endpoint currently
**short-circuits every Azure verification call to
`VerificationFailed`** with a `WARN`-level trace event. With
`verify_instance_identity = true`, the Azure endpoint will reject every
request. Failing closed is deliberate — silently accepting unverified
Azure tokens would be an identity-forgery vector.

**Consequences today:**

| Configuration | Azure bootstrap behaviour |
|---|---|
| `verify_instance_identity = false` (default) | Permissive verifier parses the JWT body and extracts `vmId`. Same behaviour as before this gap was introduced. |
| `verify_instance_identity = true` | Always returns 401. AWS + GCP verification still work against their real platform keys. |

**Work required to close the gap:**

1. Pick a Rust PKCS7/CMS crate (`cms` or `rasn-cms`) and add it to
   `[workspace.dependencies]`.
2. Port the Go PKCS7 parse + verify path, including signer-cert chain
   walk up to a bundled Microsoft intermediate CA set.
3. Apply the signer-cert `Subject.CommonName` pattern match (the
   `metadata.*` regex — which is *not* a JWT `iss` pattern; see the
   module docstring for why the earlier JWT-issuer approach was wrong).
4. Extract `vmId` from the inner JSON content and return it as the
   verified instance identifier.
5. Replace the short-circuit with a real call. The module already
   compiles a ready-to-use Entra ID issuer allow-list
   (`DEFAULT_ISSUER_REGEX`) for any future JWT-based managed-identity
   token exchange Coder chooses to layer on top of PKCS7.

**Why this is deferred:** the PKCS7 path requires (a) selecting and
adding a CMS crate, (b) bundling the Microsoft intermediate CA set
(Go ships them in `coder/coderd/azureidentity/azureidentity.go` as
embedded PEMs), and (c) writing a conservative cert-chain walker. This
is a real feature, not a one-line fix, and lands in a follow-up PR.

## AWS instance-identity: bundled certs do not cover every partition

**Location:** `crates/coder-server/src/instance_identity/aws.rs`

**Go reference:** `coder/coderd/awsidentity/awsidentity.go`

The `DEFAULT_CERTIFICATES` list ships 14 regional certs, matching the
Go reference (public commercial + 13 additional regions including
GovCloud and `cn-northwest-1`). The `Other` commercial-region cert is
refreshed ahead of the Go reference, which still carries the 2014 cert
that expired 2024-06-05.

**Still not covered by the bundled defaults:** any partitions Go has
not added yet (e.g. `us-iso*`, `us-isob*`, `eu-isoe*`, or
freshly-launched regions before we pick up new certs). Operators on
those partitions must inject additional PEM certs via either:

* `--aws-instance-identity-certs-dir <DIR>` on the CLI, or
* the `CODER_AWS_INSTANCE_IDENTITY_CERTS_DIR` environment variable, or
* programmatically through `AwsInstanceVerifier::with_certificates`.

The directory is scanned once at startup; `*.pem` / `*.crt` files are
appended to the bundled set, with successful loads logged at `INFO` and
parse/IO errors at `WARN`.

**Work required to close the gap (for a given partition):** add the
partition's current AWS-published RSA cert to `DEFAULT_CERTIFICATES`
with `notBefore` / `notAfter` annotated inline, following the Go
reference layout. This is a mechanical change per partition and is not
tracked here beyond the pointer to the AWS docs:
<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html>.
