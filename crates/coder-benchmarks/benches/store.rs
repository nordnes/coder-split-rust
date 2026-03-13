//! Criterion benchmarks for in-memory store query patterns.
//!
//! These benchmarks exercise `BenchStore` methods that mirror the FakeStore
//! used in unit tests, establishing a baseline for key store operations:
//! user lookup, user listing, and template queries.

use std::collections::HashMap;
use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use time::OffsetDateTime;
use uuid::Uuid;

use coder_benchmarks::BenchStore;
use coder_core::identity::{LoginType, UserRecord, UserStatus};
use coder_core::ports::AppStore;
use coder_core::template::{TemplateListFilter, TemplateRecord};

/// Populates the store with `n` users and returns one user ID for lookups.
fn seed_users(store: &BenchStore, n: usize) -> Uuid {
    let mut guard = store.users.lock().unwrap_or_else(|e| e.into_inner());
    let mut target_id = Uuid::nil();
    for i in 0..n {
        let id = Uuid::new_v4();
        if i == n / 2 {
            target_id = id;
        }
        guard.insert(
            id,
            UserRecord {
                id,
                email: format!("user{i}@bench.test"),
                username: format!("benchuser{i}"),
                name: format!("Bench User {i}"),
                created_at: OffsetDateTime::UNIX_EPOCH,
                updated_at: OffsetDateTime::UNIX_EPOCH,
                status: UserStatus::Active,
                login_type: LoginType::Password,
                avatar_url: String::new(),
                deleted: false,
                last_seen_at: None,
                organization_ids: Vec::new(),
                roles: Vec::new(),
                is_system: false,
            },
        );
    }
    target_id
}

/// Populates the store with `n` templates and returns one template ID for lookups.
fn seed_templates(store: &BenchStore, n: usize) -> Uuid {
    let mut guard = store.templates.lock().unwrap_or_else(|e| e.into_inner());
    let org_id = Uuid::new_v4();
    let mut target_id = Uuid::nil();
    for i in 0..n {
        let id = Uuid::new_v4();
        if i == n / 2 {
            target_id = id;
        }
        guard.insert(
            id,
            TemplateRecord {
                id,
                created_at: OffsetDateTime::UNIX_EPOCH,
                updated_at: OffsetDateTime::UNIX_EPOCH,
                organization_id: org_id,
                organization_name: String::new(),
                organization_display_name: String::new(),
                organization_icon: String::new(),
                name: format!("template-{i}"),
                display_name: format!("Template {i}"),
                provisioner: "echo".to_owned(),
                active_version_id: Uuid::nil(),
                description: String::new(),
                icon: String::new(),
                default_ttl: 0,
                activity_bump: 0,
                autostop_requirement_days_of_week: 0,
                autostop_requirement_weeks: 0,
                autostart_block_days_of_week: 0,
                failure_ttl: 0,
                time_til_dormant: 0,
                time_til_dormant_autodelete: 0,
                created_by: Uuid::nil(),
                created_by_avatar_url: String::new(),
                created_by_username: "admin".to_owned(),
                created_by_name: String::new(),
                deprecated: String::new(),
                max_port_sharing_level: String::new(),
                group_acl: HashMap::new(),
                user_acl: HashMap::new(),
                require_active_version: false,
                use_classic_parameter_flow: false,
                allow_user_cancel_workspace_jobs: true,
                allow_user_autostart: true,
                allow_user_autostop: true,
                deleted: false,
                cors_behavior: String::new(),
                disable_module_cache: false,
            },
        );
    }
    target_id
}

fn bench_find_user_by_id(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let store = Arc::new(BenchStore::new());
    let target_id = seed_users(&store, 1000);

    c.bench_function("store/find_user_by_id_1k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.find_user_by_id(black_box(target_id)).await;
            });
        });
    });
}

fn bench_find_user_by_id_10k(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let store = Arc::new(BenchStore::new());
    let target_id = seed_users(&store, 10_000);

    c.bench_function("store/find_user_by_id_10k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.find_user_by_id(black_box(target_id)).await;
            });
        });
    });
}

fn bench_list_users(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let store = Arc::new(BenchStore::new());
    let _ = seed_users(&store, 500);

    let filter = coder_core::identity::UserListFilter::default();

    c.bench_function("store/list_users_500", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.list_users(black_box(filter.clone())).await;
            });
        });
    });
}

fn bench_list_templates(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let store = Arc::new(BenchStore::new());
    let _ = seed_templates(&store, 200);

    let filter = TemplateListFilter::default();

    c.bench_function("store/list_templates_200", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.list_templates(black_box(filter.clone())).await;
            });
        });
    });
}

fn bench_find_template_by_id(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let store = Arc::new(BenchStore::new());
    let target_id = seed_templates(&store, 200);

    c.bench_function("store/find_template_by_id_200", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.find_template_by_id(black_box(target_id)).await;
            });
        });
    });
}

fn bench_find_user_by_username(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::abort());

    let store = Arc::new(BenchStore::new());
    let _ = seed_users(&store, 1000);

    c.bench_function("store/find_user_by_username_1k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = store.find_user_by_username(black_box("benchuser500")).await;
            });
        });
    });
}

criterion_group!(
    store_benches,
    bench_find_user_by_id,
    bench_find_user_by_id_10k,
    bench_list_users,
    bench_list_templates,
    bench_find_template_by_id,
    bench_find_user_by_username,
);

criterion_main!(store_benches);
