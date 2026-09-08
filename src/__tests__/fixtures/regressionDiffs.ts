/**
 * Regression fixtures for the tier-2 precision work.
 *
 * Every line below is REAL TEXT lifted verbatim (trimmed for width, never
 * reworded) from the two pull requests whose Data Compliance Gate runs
 * motivated this change:
 *
 *   PR #852 (merge 9605892, v2.175.2) — the unstable-offset-pagination fix.
 *     Gate reported: needs_review, 4 findings, all `dc-dpia-required`, all
 *     matching the single English word "scoring" in prose.
 *
 *   PR #854 (merge 4dd568a) — the backup-table relocation.
 *     Gate reported: needs_review, 34 findings — 16 × `dc-retention-policy`
 *     + 16 × `dc-erasure-path` (the same 16 lines, double-counted because
 *     both rules share one signature key) + 2 × `dc-select-star`.
 *
 * Both counts were reproduced exactly by running the shipped ruleset against
 * the real diffs before any of this was written; these fixtures are the
 * reduced form of that reproduction, kept small enough to read in a review.
 */

/** Build a minimal unified diff for one file's added lines. */
export function addedDiff(file: string, lines: string[]): string {
  return [
    `diff --git a/${file} b/${file}`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -1,1 +1,${lines.length + 1} @@`,
    ' context',
    ...lines.map((l) => `+${l}`),
  ].join('\n');
}

/** Build a diff carrying removed lines as well as added ones. */
export function pairedDiff(file: string, removed: string[], added: string[]): string {
  return [
    `diff --git a/${file} b/${file}`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -1,${removed.length + 1} +1,${added.length + 1} @@`,
    ' context',
    ...removed.map((l) => `-${l}`),
    ...added.map((l) => `+${l}`),
  ].join('\n');
}

// ---------------------------------------------------------------------------
// PR #852 — the four `dc-dpia-required` false positives. All four are prose.
// ---------------------------------------------------------------------------

export const PR852_FALSE_POSITIVES: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'Architecture.md — incident narrative',
    file: 'Architecture.md',
    line: 'scoring ~90% of its issues, a different tenth missing each run, for four weeks.',
  },
  {
    label: 'PITCH.md — buyer-facing trust narrative',
    file: 'PITCH.md',
    line:
      'This one is the product fetching the data correctly and then quietly scoring only ' +
      'about nine tenths of it: the reads that load a customer’s issues for evaluation ' +
      'were paginating without a guaranteed row order.',
  },
  {
    // The one that matters most: a real .ts code file, so no path exclusion
    // could ever have fixed this case. Only pattern SHAPE fixes it.
    label: 'src/config/version.ts — changelog entry describing the bug',
    file: 'src/config/version.ts',
    line:
      '    "2.175.2 - fix(compliance,pagination): every paged read of an org’s issues was ' +
      'skipping and duplicating rows, so the compliance evaluator had been scoring ~90% of ' +
      'each org’s issues since 2026-07-31.",',
  },
  {
    label: 'src/tests/golden-dataset.json — automation_notes prose',
    file: 'src/tests/golden-dataset.json',
    line:
      '      "automation_notes": "The same defect in its acute form was found in ' +
      'auto-evaluate-compliance, where it had been scoring ~90% of every org’s issues ' +
      'since 2026-07-31."',
  },
];

// ---------------------------------------------------------------------------
// PR #854 — the `dc-retention-policy` / `dc-erasure-path` false positives.
// Three distinct shapes, none of which creates a new personal-data entity.
// ---------------------------------------------------------------------------

export const PR854_FALSE_POSITIVES: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'planning doc — prose quoting DDL inside a sentence',
    file: 'docs/plans/backup-table-exposure-root-cause.md',
    line:
      'instant *anyone* runs `create table public._backup_x as select …`, both public-facing API',
  },
  {
    label: 'planning doc — a section heading naming a DDL statement',
    file: 'docs/plans/backup-table-exposure-root-cause.md',
    line: '### C. Event trigger refusing `public._backup%` at `CREATE TABLE`',
  },
  {
    label: 'guard test — a string literal naming the DDL it forbids',
    file: 'src/services/__tests__/backupSchemaRelocation.test.ts',
    line: '      offenders.map(c => `${c.file} — CREATE TABLE ${c.table}`),',
  },
  {
    label: 'rollback script — relocating an EXISTING backup table, creating nothing',
    file: 'supabase/migrations/rollback/20260630120300_enable_rls_on_backup_tables.down.sql',
    line: 'alter table public._backup_20260721150000_dora_deployment_frequency  set schema backup;',
  },
  {
    label: 'forward migration — enabling RLS on an existing table, creating nothing',
    file: 'supabase/migrations/20260901152549_secure_backup_v2175_uat_table.sql',
    line: 'alter table public._backup_v2175_uat enable row level security;',
  },
];

/** PR #854's two `dc-select-star` hits — both read a backup table, not personal data. */
export const PR854_SELECT_STAR: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'backup-table read inside a rollback script',
    file: 'supabase/migrations/rollback/20260901192319_move_backup_tables_to_backup_schema.down.sql',
    line: '    SELECT * FROM backup._backup_remove_email_scheduled_reports',
  },
  {
    label: 'backup-table read inside a rollback script',
    file: 'supabase/migrations/rollback/20260901192319_move_backup_tables_to_backup_schema.down.sql',
    line: '    SELECT * FROM backup._backup_20260803120100_investment_snapshots',
  },
];

// ---------------------------------------------------------------------------
// TRUE positives. Every one of these MUST still fire after the precision work,
// or recall has silently gone to zero — the worst possible outcome here.
//
// Deliberately spread across four schema/ORM dialects so the assertions also
// prove the rules do not depend on OUR repo layout: a Rails, Django or Prisma
// customer must get the same answer.
// ---------------------------------------------------------------------------

export const ART22_TRUE_POSITIVES: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'Postgres — a credit score column on an applicants table',
    file: 'supabase/migrations/20270101000000_add_scoring.sql',
    line: 'ALTER TABLE public.applicants ADD COLUMN credit_score numeric NOT NULL DEFAULT 0;',
  },
  {
    label: 'Rails — a risk-rating table with a fraud score (db/migrate, not our layout)',
    file: 'db/migrate/20270101000000_create_applicant_risk_rating.rb',
    line: '    create_table :applicant_risk_rating do |t| t.integer :fraud_score end',
  },
  {
    label: 'Prisma — a camelCase score field in a schema file',
    file: 'prisma/schema.prisma',
    line: '  riskScore  Float',
  },
  {
    label: 'Django — a model field carrying a fraud rating',
    file: 'app/models.py',
    line: '    fraud_rating = models.IntegerField(default=0)',
  },
  {
    label: 'Application code — an automated credit decision about a person',
    file: 'src/services/underwriting.ts',
    line: '  const creditDecision = await model.predict(applicant);',
  },
];

/** New-entity DDL that genuinely creates a persistent table — must still fire. */
export const NEW_ENTITY_TRUE_POSITIVES: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'a real new table in a forward migration',
    file: 'supabase/migrations/20270101000000_create_patients.sql',
    line: 'CREATE TABLE public.patient_contacts (id uuid PRIMARY KEY, email text NOT NULL);',
  },
  {
    label: 'a real new column added to an existing table',
    file: 'supabase/migrations/20270101000001_add_dob.sql',
    line: 'ALTER TABLE public.profiles ADD COLUMN date_of_birth date;',
  },
  {
    label: 'Rails — a real new table, outside our migration layout',
    file: 'db/migrate/20270101000000_create_patients.rb',
    line: '    create_table :patient_contacts do |t| t.string :email end',
  },
  {
    // THE ONE PR #854 FINDING THAT SURVIVES, and it should.
    //
    // Running the new ruleset against #854's full real diff takes it from 34
    // findings to 2 — and these are the 2: this line, under both the
    // retention and the erasure rule. That is the gate working, not residual
    // noise. `CREATE TABLE … AS SELECT` genuinely creates a new persistent
    // table populated from an existing one, and a backup table holding
    // personal data needs a retention policy and an erasure path exactly like
    // its source does. PR #854 exists BECAUSE an ad-hoc `public._backup_*`
    // table became an exposure incident, so "you just created a backup table
    // — confirm retention and erasure" is the single most useful thing the
    // gate could have said on that PR.
    //
    // Pinned as a true positive so nobody later "finishes the job" by
    // excluding backup tables to drive #854 to zero. Driving it to zero is
    // the failure mode, not the goal.
    label: 'a backup table created from an existing one (real PR #854 line, correctly flagged)',
    file: 'supabase/migrations/rollback/20260729100000_gate_recurrence_annual.down.sql',
    line: 'CREATE TABLE IF NOT EXISTS backup._backup_gate_recurrence_annual AS',
  },

  // ---------------------------------------------------------------------------
  // CR7 / SEC3. The first cut of these rules was line-anchored to
  // `create table | create_table | add_column | alter table X add column`, which
  // detected 4 of the 16 forms below. The migration's own rule description claimed
  // it fired "in any schema dialect"; measured, only Postgres CREATE TABLE,
  // Postgres ALTER…ADD COLUMN and Rails create_table were covered — Django, Prisma
  // and Alembic were entirely invisible, and so were six ordinary Postgres spellings.
  // ---------------------------------------------------------------------------
  {
    label: 'Postgres — ALTER TABLE ONLY (what pg_dump emits)',
    file: 'db/dump.sql',
    line: 'ALTER TABLE ONLY public.profiles ADD COLUMN ssn text;',
  },
  {
    label: 'Postgres — ALTER TABLE IF EXISTS',
    file: 'supabase/migrations/20270101000002_add_ssn.sql',
    line: 'ALTER TABLE IF EXISTS public.profiles ADD COLUMN ssn text;',
  },
  {
    label: 'Postgres — ADD without the optional COLUMN keyword',
    file: 'supabase/migrations/20270101000003_add_ssn.sql',
    line: 'ALTER TABLE public.profiles ADD ssn text;',
  },
  {
    label: 'Postgres — CREATE UNLOGGED TABLE',
    file: 'supabase/migrations/20270101000004_staging.sql',
    line: 'CREATE UNLOGGED TABLE public.patients_staging (id uuid, email text);',
  },
  {
    label: 'Postgres — CREATE TEMP TABLE',
    file: 'supabase/migrations/20270101000005_temp.sql',
    line: 'CREATE TEMP TABLE patients_tmp (id uuid, email text);',
  },
  {
    // The scanner is line-at-a-time, and multi-line ALTER is the dominant style in
    // this repo's own migrations — so BOTH Art 5(1)(e) and Art 17 were blind to it.
    label: 'Postgres — the continuation line of a multi-line ALTER',
    file: 'supabase/migrations/20270101000006_multiline.sql',
    line: '  ADD COLUMN date_of_birth date;',
  },
  {
    label: 'Alembic — op.add_column',
    file: 'alembic/versions/8f2a_add_ssn.py',
    line: '    op.add_column("profiles", sa.Column("ssn", sa.String()))',
  },
  {
    label: 'Alembic — op.create_table',
    file: 'alembic/versions/9c1b_create_patients.py',
    line: '    op.create_table("patients", sa.Column("id", sa.Uuid()))',
  },
  {
    label: 'Django — migrations.AddField',
    file: 'app/migrations/0007_profile_ssn.py',
    line: '        migrations.AddField(model_name="profile", name="ssn", field=models.CharField()),',
  },
  {
    label: 'Django — migrations.CreateModel',
    file: 'app/migrations/0008_patient.py',
    line: '        migrations.CreateModel(name="Patient", fields=[("id", models.UUIDField())]),',
  },
  {
    label: 'Prisma — a model block',
    file: 'prisma/schema.prisma',
    line: 'model Patient {',
  },
];

/**
 * DDL the new-entity rules deliberately do NOT see, pinned so the boundary is a
 * stated decision rather than something rediscovered later.
 *
 * Every alternative in the pattern is LINE-ANCHORED, and that anchor is precisely
 * what keeps prose out. DDL inside a string literal cannot be distinguished from
 * prose quoting DDL by a line-scoped regex: three of the five pinned PR #854 false
 * positives ARE quote-adjacent DDL (two backticked in markdown, one in a template
 * literal inside a guard test), so any "match DDL after a quote" alternative would
 * resurrect them. Catching dynamic SQL properly needs parsing, not a regex.
 *
 * If a future change makes one of these detectable WITHOUT reviving the PR #854
 * class, move it up into NEW_ENTITY_TRUE_POSITIVES.
 */
export const NEW_ENTITY_DOCUMENTED_MISSES: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'dynamic SQL executed from application code',
    file: 'src/db/bootstrap.ts',
    line: 'await db.query("CREATE TABLE public.patients (id uuid)");',
  },
  {
    label: 'plpgsql EXECUTE of a DDL string',
    file: 'supabase/migrations/20270101000007_dynamic.sql',
    line: "  EXECUTE 'CREATE TABLE public.patients (id uuid)';",
  },
];

/**
 * Statements that ALTER a table without creating a personal-data entity. These are
 * new negatives introduced with the widened pattern: relaxing `ADD COLUMN` to make
 * the COLUMN keyword optional (it is optional in Postgres) would otherwise have
 * caught every `ADD CONSTRAINT` / `ADD PRIMARY KEY` / `ADD FOREIGN KEY` in the repo.
 */
export const NEW_ENTITY_NON_COLUMN_ALTERS: Array<{ label: string; file: string; line: string }> = [
  {
    label: 'ADD CONSTRAINT creates no column',
    file: 'supabase/migrations/20270101000010_pk.sql',
    line: 'ALTER TABLE public.profiles ADD CONSTRAINT profiles_pkey PRIMARY KEY (id);',
  },
  {
    label: 'ADD PRIMARY KEY creates no column',
    file: 'supabase/migrations/20270101000011_pk.sql',
    line: 'ALTER TABLE public.profiles ADD PRIMARY KEY (id);',
  },
  {
    label: 'a continuation line adding a foreign key creates no column',
    file: 'supabase/migrations/20270101000012_fk.sql',
    line: '  ADD FOREIGN KEY (org_id) REFERENCES public.orgs(id);',
  },
  {
    label: 'DROP COLUMN removes an entity rather than creating one',
    file: 'supabase/migrations/20270101000013_drop.sql',
    line: 'ALTER TABLE public.profiles DROP COLUMN ssn;',
  },
];
