import Knex from 'knex';
import path from 'path';

// ---------------------------------------------------------------------------
// Database client
// ---------------------------------------------------------------------------

export const db = Knex({
  client: 'better-sqlite3',
  connection: {
    filename: path.join(__dirname, '..', 'scim-ad-bridge.db'),
  },
  useNullAsDefault: true,
});

// ---------------------------------------------------------------------------
// Schema bootstrap — idempotent, safe to call on every startup
// ---------------------------------------------------------------------------

export async function initDb(): Promise<void> {
  // --- incoming_requests ---------------------------------------------------
  // Logs the full HTTP round-trip (populated by onRequest + onSend hooks).
  if (!(await db.schema.hasTable('incoming_requests'))) {
    await db.schema.createTable('incoming_requests', (t) => {
      t.increments('id').primary();
      t.string('method').notNullable();
      t.text('url').notNullable();
      t.text('query_string').nullable();
      t.string('ip').nullable();
      t.text('request_body').nullable();
      t.integer('response_status').nullable();
      t.text('response_body').nullable();
      t.integer('duration_ms').nullable();
      t.timestamp('created_at').defaultTo(db.fn.now());
    });
  }

  // --- powershell_executions -----------------------------------------------
  // Audit log for every AD cmdlet invocation.
  if (!(await db.schema.hasTable('powershell_executions'))) {
    await db.schema.createTable('powershell_executions', (t) => {
      t.increments('id').primary();
      t.string('cmdlet').notNullable();
      t.text('parameters').nullable();
      t.text('stdout').nullable();
      t.text('stderr').nullable();
      t.integer('exit_code').nullable();
      t.integer('duration_ms').nullable();
      t.string('scim_user_id').nullable();
      t.timestamp('created_at').defaultTo(db.fn.now());
    });
  }

  // --- scim_users ----------------------------------------------------------
  // Local cache — the source of truth for sync state.
  if (!(await db.schema.hasTable('scim_users'))) {
    await db.schema.createTable('scim_users', (t) => {
      t.string('id').primary();
      t.text('ad_object_guid').nullable();
      t.text('sam_account_name').unique().nullable();
      t.text('scim_resource').notNullable();          // full SCIM JSON (IdP view)
      t.text('ad_resource').nullable();               // full AD JSON (Get-ADUser -Properties *)
      t.string('sync_status').notNullable().defaultTo('pending'); // synced | pending | error
      t.text('last_error').nullable();
      t.timestamp('created_at').defaultTo(db.fn.now());
      t.timestamp('updated_at').defaultTo(db.fn.now());
    });
  }
}
