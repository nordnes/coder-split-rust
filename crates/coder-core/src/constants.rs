//! Compile-time notification template UUIDs.
//!
//! These constants mirror the Go reference definitions in
//! `coder/coderd/notifications/events.go` and correspond to rows seeded into the
//! `notification_templates` table by database migrations.
//!
//! Using the [`uuid::uuid!`] macro ensures the UUIDs are parsed at compile time,
//! eliminating runtime parsing overhead and the risk of a silently-defaulting
//! `Uuid::nil()`.

use uuid::{Uuid, uuid};

// ---------------------------------------------------------------------------
// Notification-related template IDs
// ---------------------------------------------------------------------------

/// Template UUID for the "send test notification" flow.
///
/// Corresponds to Go's `notifications.TemplateTestNotification`.
/// Seeded by migration `000295_test_notification`.
pub const TEMPLATE_TEST_NOTIFICATION: Uuid = uuid!("c425f63e-716a-4bf4-ae24-78348f706c3f");

/// Template UUID for custom (user-authored) notifications.
///
/// Corresponds to Go's `notifications.TemplateCustomNotification`.
/// Seeded by migration `000368_add_custom_notifications`.
pub const TEMPLATE_CUSTOM_NOTIFICATION: Uuid = uuid!("39b1e189-c857-4b0c-877a-511144c18516");

// ---------------------------------------------------------------------------
// Workspace-related template IDs
// ---------------------------------------------------------------------------

/// Template UUID for "workspace created" notifications.
pub const TEMPLATE_WORKSPACE_CREATED: Uuid = uuid!("281fdf73-c6d6-4cbb-8ff5-888baf8a2fff");

/// Template UUID for "workspace manually updated" notifications.
pub const TEMPLATE_WORKSPACE_MANUALLY_UPDATED: Uuid = uuid!("d089fe7b-d5c5-4c0c-aaf5-689859f7d392");

/// Template UUID for "workspace deleted" notifications.
pub const TEMPLATE_WORKSPACE_DELETED: Uuid = uuid!("f517da0b-cdc9-410f-ab89-a86107c420ed");

/// Template UUID for "workspace autobuild failed" notifications.
pub const TEMPLATE_WORKSPACE_AUTOBUILD_FAILED: Uuid = uuid!("381df2a9-c0c0-4749-420f-80a9280c66f9");

/// Template UUID for "workspace dormant" notifications.
pub const TEMPLATE_WORKSPACE_DORMANT: Uuid = uuid!("0ea69165-ec14-4314-91f1-69566ac3c5a0");

/// Template UUID for "workspace auto-updated" notifications.
pub const TEMPLATE_WORKSPACE_AUTO_UPDATED: Uuid = uuid!("c34a0c09-0704-4cac-bd1c-0c0146811c2b");

/// Template UUID for "workspace marked for deletion" notifications.
pub const TEMPLATE_WORKSPACE_MARKED_FOR_DELETION: Uuid =
    uuid!("51ce2fdf-c9ca-4be1-8d70-628674f9bc42");

/// Template UUID for "workspace manual build failed" notifications.
pub const TEMPLATE_WORKSPACE_MANUAL_BUILD_FAILED: Uuid =
    uuid!("2faeee0f-26cb-4e96-821c-85ccb9f71513");

/// Template UUID for "workspace out of memory" notifications.
pub const TEMPLATE_WORKSPACE_OUT_OF_MEMORY: Uuid = uuid!("a9d027b4-ac49-4fb1-9f6d-45af15f64e7a");

/// Template UUID for "workspace out of disk" notifications.
pub const TEMPLATE_WORKSPACE_OUT_OF_DISK: Uuid = uuid!("f047f6a3-5713-40f7-85aa-0394cce9fa3a");

// ---------------------------------------------------------------------------
// Account-related template IDs
// ---------------------------------------------------------------------------

/// Template UUID for "user account created" notifications.
pub const TEMPLATE_USER_ACCOUNT_CREATED: Uuid = uuid!("4e19c0ac-94e1-4532-9515-d1801aa283b2");

/// Template UUID for "user account deleted" notifications.
pub const TEMPLATE_USER_ACCOUNT_DELETED: Uuid = uuid!("f44d9314-ad03-4bc8-95d0-5cad491da6b6");

/// Template UUID for "user account suspended" (admin-facing) notifications.
pub const TEMPLATE_USER_ACCOUNT_SUSPENDED: Uuid = uuid!("b02ddd82-4733-4d02-a2d7-c36f3598997d");

/// Template UUID for "user account activated" (admin-facing) notifications.
pub const TEMPLATE_USER_ACCOUNT_ACTIVATED: Uuid = uuid!("9f5af851-8408-4e73-a7a1-c6502ba46689");

/// Template UUID for "your account suspended" (user-facing) notifications.
pub const TEMPLATE_YOUR_ACCOUNT_SUSPENDED: Uuid = uuid!("6a2f0609-9b69-4d36-a989-9f5925b6cbff");

/// Template UUID for "your account activated" (user-facing) notifications.
pub const TEMPLATE_YOUR_ACCOUNT_ACTIVATED: Uuid = uuid!("1a6a6bea-ee0a-43e2-9e7c-eabdb53730e4");

/// Template UUID for "user requested one-time passcode" notifications.
pub const TEMPLATE_USER_REQUESTED_ONE_TIME_PASSCODE: Uuid =
    uuid!("62f86a30-2330-4b61-a26d-311ff3b608cf");

// ---------------------------------------------------------------------------
// Template-related template IDs
// ---------------------------------------------------------------------------

/// Template UUID for "template deleted" notifications.
pub const TEMPLATE_TEMPLATE_DELETED: Uuid = uuid!("29a09665-2a4c-403f-9648-54301670e7be");

/// Template UUID for "template deprecated" notifications.
pub const TEMPLATE_TEMPLATE_DEPRECATED: Uuid = uuid!("f40fae84-55a2-42cd-99fa-b41c1ca64894");

/// Template UUID for "workspace builds failed report" notifications.
pub const TEMPLATE_WORKSPACE_BUILDS_FAILED_REPORT: Uuid =
    uuid!("34a20db2-e9cc-4a93-b0e4-8569699d7a00");

/// Template UUID for "workspace resource replaced" notifications.
pub const TEMPLATE_WORKSPACE_RESOURCE_REPLACED: Uuid =
    uuid!("89d9745a-816e-4695-a17f-3d0a229e2b8d");

// ---------------------------------------------------------------------------
// Prebuild-related template IDs
// ---------------------------------------------------------------------------

/// Template UUID for "prebuild failure limit reached" notifications.
pub const TEMPLATE_PREBUILD_FAILURE_LIMIT_REACHED: Uuid =
    uuid!("414d9331-c1fc-4761-b40c-d1f4702279eb");

// ---------------------------------------------------------------------------
// Task-related template IDs
// ---------------------------------------------------------------------------

/// Template UUID for "task working" notifications.
pub const TEMPLATE_TASK_WORKING: Uuid = uuid!("bd4b7168-d05e-4e19-ad0f-3593b77aa90f");

/// Template UUID for "task idle" notifications.
pub const TEMPLATE_TASK_IDLE: Uuid = uuid!("d4a6271c-cced-4ed0-84ad-afd02a9c7799");

/// Template UUID for "task completed" notifications.
pub const TEMPLATE_TASK_COMPLETED: Uuid = uuid!("8c5a4d12-9f7e-4b3a-a1c8-6e4f2d9b5a7c");

/// Template UUID for "task failed" notifications.
pub const TEMPLATE_TASK_FAILED: Uuid = uuid!("3b7e8f1a-4c2d-49a6-b5e9-7f3a1c8d6b4e");

/// Template UUID for "task paused" notifications.
pub const TEMPLATE_TASK_PAUSED: Uuid = uuid!("2a74f3d3-ab09-4123-a4a5-ca238f4f65a1");

/// Template UUID for "task resumed" notifications.
pub const TEMPLATE_TASK_RESUMED: Uuid = uuid!("843ee9c3-a8fb-4846-afa9-977bec578649");

// ---------------------------------------------------------------------------
// System user IDs
// ---------------------------------------------------------------------------

/// The UUID of the system user responsible for prebuilds.
///
/// Corresponds to Go's `database.PrebuildsSystemUserID`.
pub const PREBUILDS_SYSTEM_USER_ID: Uuid = uuid!("c42fdf75-3097-471c-8c33-fb52454d81c0");
