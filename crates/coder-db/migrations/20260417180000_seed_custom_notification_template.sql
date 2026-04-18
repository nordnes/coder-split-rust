-- Seed the Custom Notification template used by POST /api/v2/notifications/custom.
-- Mirrors Go migration 000368_add_custom_notifications.up.sql.  The row is
-- inserted idempotently so re-running migrations (or older deployments that
-- already contain the template) stays a no-op.

INSERT INTO notification_templates (
    id,
    name,
    title_template,
    body_template,
    actions,
    "group",
    method,
    kind,
    enabled_by_default
) VALUES (
    '39b1e189-c857-4b0c-877a-511144c18516',
    'Custom Notification',
    '{{.Labels.custom_title}}',
    '{{.Labels.custom_message}}',
    '[]'::jsonb,
    'Custom Events',
    NULL,
    'custom'::notification_template_kind,
    TRUE
)
ON CONFLICT (id) DO NOTHING;
