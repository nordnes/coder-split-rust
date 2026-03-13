//! Criterion benchmarks for RBAC authorization hot paths.
//!
//! These benchmarks measure `Authorizer::authorize()` latency across various
//! actor/resource/action combinations that represent real request patterns.

use std::collections::HashMap;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use uuid::Uuid;

use coder_rbac::{
    Action, Actor, Authorizer, Object, ROLE_AUDITOR, ROLE_MEMBER, ROLE_OWNER, ROLE_TEMPLATE_ADMIN,
    ROLE_USER_ADMIN, ResourceType,
};

/// Builds an actor with the given site roles and org memberships.
fn make_actor(site_roles: &[&str], org_ids: &[Uuid], org_roles: &[String]) -> Actor {
    Actor {
        user_id: Uuid::new_v4(),
        username: "benchuser".to_owned(),
        organization_ids: org_ids.to_vec(),
        site_roles: site_roles.iter().map(|s| (*s).to_owned()).collect(),
        org_roles: org_roles.to_vec(),
        groups: Vec::new(),
        scope: None,
    }
}

fn bench_authorize_owner_site_resource(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let actor = make_actor(&[ROLE_OWNER], &[], &[]);
    let object = Object::new(ResourceType::User);

    c.bench_function("rbac/owner_read_user", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Read),
                black_box(&object),
            );
        });
    });
}

fn bench_authorize_owner_all_actions(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let actor = make_actor(&[ROLE_OWNER], &[], &[]);

    let actions = [Action::Create, Action::Read, Action::Update, Action::Delete];
    let resources = [
        ResourceType::User,
        ResourceType::Template,
        ResourceType::Workspace,
        ResourceType::AuditLog,
        ResourceType::Organization,
    ];

    c.bench_function("rbac/owner_all_actions_resources", |b| {
        b.iter(|| {
            for action in &actions {
                for rt in &resources {
                    let obj = Object::new(*rt);
                    let _ = authorizer.authorize(
                        black_box(&actor),
                        black_box(*action),
                        black_box(&obj),
                    );
                }
            }
        });
    });
}

fn bench_authorize_member_own_resource(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let actor = make_actor(&[ROLE_MEMBER], &[], &[]);
    let object = Object::new(ResourceType::User).with_owner(actor.user_id);

    c.bench_function("rbac/member_read_own_user", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Read),
                black_box(&object),
            );
        });
    });
}

fn bench_authorize_member_denied(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let actor = make_actor(&[ROLE_MEMBER], &[], &[]);
    let object = Object::new(ResourceType::User);

    c.bench_function("rbac/member_create_user_denied", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Create),
                black_box(&object),
            );
        });
    });
}

fn bench_authorize_org_member(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let org_id = Uuid::new_v4();
    let actor = make_actor(
        &[ROLE_MEMBER],
        &[org_id],
        &[format!("organization-member:{org_id}")],
    );
    let object = Object::new(ResourceType::Template).in_org(org_id);

    c.bench_function("rbac/org_member_read_template", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Read),
                black_box(&object),
            );
        });
    });
}

fn bench_authorize_with_acl(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let actor = make_actor(&[ROLE_MEMBER], &[], &[]);
    let mut acl = HashMap::new();
    acl.insert(
        actor.user_id.to_string(),
        vec![Action::Read, Action::Update],
    );
    let object = Object::new(ResourceType::Workspace).with_acl_user_list(acl);

    c.bench_function("rbac/acl_user_list_grant", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Read),
                black_box(&object),
            );
        });
    });
}

fn bench_authorize_multiple_roles(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let org_id = Uuid::new_v4();
    let actor = make_actor(
        &[
            ROLE_MEMBER,
            ROLE_AUDITOR,
            ROLE_TEMPLATE_ADMIN,
            ROLE_USER_ADMIN,
        ],
        &[org_id],
        &[
            format!("organization-admin:{org_id}"),
            format!("organization-member:{org_id}"),
        ],
    );
    let object = Object::new(ResourceType::AuditLog).in_org(org_id);

    c.bench_function("rbac/multi_role_audit_read", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Read),
                black_box(&object),
            );
        });
    });
}

fn bench_authorize_no_roles_denied(c: &mut Criterion) {
    let authorizer = Authorizer::new();
    let actor = make_actor(&[], &[], &[]);
    let object = Object::new(ResourceType::Workspace);

    c.bench_function("rbac/no_roles_denied", |b| {
        b.iter(|| {
            let _ = authorizer.authorize(
                black_box(&actor),
                black_box(Action::Read),
                black_box(&object),
            );
        });
    });
}

criterion_group!(
    rbac_benches,
    bench_authorize_owner_site_resource,
    bench_authorize_owner_all_actions,
    bench_authorize_member_own_resource,
    bench_authorize_member_denied,
    bench_authorize_org_member,
    bench_authorize_with_acl,
    bench_authorize_multiple_roles,
    bench_authorize_no_roles_denied,
);

criterion_main!(rbac_benches);
