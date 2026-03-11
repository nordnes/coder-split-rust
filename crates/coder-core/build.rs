use std::process::Command;

fn main() {
    // Detect git commit hash at build time and expose it via
    // `env!("GIT_COMMIT_HASH")`.  Falls back to "unknown" when git
    // is unavailable or the working directory is not a repository.
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=GIT_COMMIT_HASH={commit}");

    // Re-run if git HEAD changes (new commits).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
}
