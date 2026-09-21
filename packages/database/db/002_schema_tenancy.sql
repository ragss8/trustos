-- Tenancy, identity, capability and policy tables (architecture.md §6.2).
--
-- Two conventions carry the isolation guarantee, and both matter:
--
-- 1. COMPOSITE FOREIGN KEYS. Every scoped reference carries tenant_id (and
--    environment_id where the row is environment-owned) INTO the foreign key, so a
--    syntactically valid ID belonging to another tenant cannot be attached. A plain
--    FK on (id) would accept it; the row exists, after all. §6.1.
--
-- 2. Every scoped table carries UNIQUE (tenant_id, id), which is what makes those
--    composite keys referenceable.
--
-- uuidv7() (PostgreSQL 18) is time-ordered, so primary keys cluster by creation
-- time and the (tenant_id, created_at, id) cursor indexes stay compact.


-- ── Tenancy ──────────────────────────────────────────────────────────────────

CREATE TABLE organizations (
  id                uuid PRIMARY KEY DEFAULT uuidv7(),
  name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  region            text NOT NULL CHECK (length(region) BETWEEN 2 AND 32),
  -- Bumped to invalidate every session and token issued before a containment event.
  auth_epoch        integer NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
  retention_profile text NOT NULL DEFAULT 'default',
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE environments (
  id                      uuid NOT NULL DEFAULT uuidv7(),
  tenant_id               uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  name                    text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  -- 'enforced' issues consumable grants. 'shadow' never does (INVARIANT 3, AUT-08).
  mode                    text NOT NULL CHECK (mode IN ('sandbox', 'production')),
  enforcement             text NOT NULL DEFAULT 'shadow' CHECK (enforcement IN ('shadow', 'enforced')),
  status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  -- Monotonic. Publishing increments it, which invalidates unconsumed grants (ADR-009).
  current_bundle_revision integer NOT NULL DEFAULT 0 CHECK (current_bundle_revision >= 0),
  -- Emergency stop, checked before policy evaluation (prd.md §8 step 2).
  kill_switch_engaged     boolean NOT NULL DEFAULT false,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);

-- ── Human identity ───────────────────────────────────────────────────────────

CREATE TABLE memberships (
  id         uuid NOT NULL DEFAULT uuidv7(),
  tenant_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  -- Subject claim from the identity provider. TrustOS never stores a password.
  user_id    text NOT NULL CHECK (length(user_id) BETWEEN 1 AND 255),
  role       text NOT NULL CHECK (role IN ('org_admin', 'security_admin', 'developer', 'approver', 'operator', 'auditor')),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'removed')),
  auth_epoch integer NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, user_id)
);

CREATE TABLE approver_groups (
  id         uuid NOT NULL DEFAULT uuidv7(),
  tenant_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  group_key  text NOT NULL CHECK (group_key ~ '^[a-z][a-z0-9_]{1,62}$'),
  name       text NOT NULL,
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, group_key)
);

CREATE TABLE approver_group_members (
  id            uuid NOT NULL DEFAULT uuidv7(),
  tenant_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  group_id      uuid NOT NULL,
  membership_id uuid NOT NULL,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, group_id, membership_id),
  -- Composite: a group and a member from a different tenant cannot be joined.
  FOREIGN KEY (tenant_id, group_id) REFERENCES approver_groups (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, membership_id) REFERENCES memberships (tenant_id, id) ON DELETE CASCADE
);

-- ── Agent identity ───────────────────────────────────────────────────────────

CREATE TABLE principals (
  id                  uuid NOT NULL DEFAULT uuidv7(),
  tenant_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  -- NULL for humans and tenant-level service principals; REQUIRED for agents.
  environment_id      uuid,
  type                text NOT NULL CHECK (type IN ('human', 'agent', 'service', 'gateway')),
  name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  -- IDN-02: an active agent must have an active owner.
  owner_membership_id uuid,
  status              text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'suspended', 'revoked')),
  auth_epoch          integer NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
  -- IDN-05: self-reported unless independently attested. Never authorization input.
  metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
  owner_acknowledged_at timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, environment_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, owner_membership_id) REFERENCES memberships (tenant_id, id) ON DELETE RESTRICT,
  -- IDN-03 + IDN-02 as a database constraint, not an application convention.
  CONSTRAINT agents_are_environment_scoped CHECK (type <> 'agent' OR environment_id IS NOT NULL),
  CONSTRAINT active_agents_have_owners CHECK (
    type <> 'agent' OR status <> 'active' OR (owner_membership_id IS NOT NULL AND owner_acknowledged_at IS NOT NULL)
  )
);

CREATE TABLE credential_bindings (
  id                 uuid NOT NULL DEFAULT uuidv7(),
  tenant_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id     uuid NOT NULL,
  principal_id       uuid NOT NULL,
  issuer             text NOT NULL,
  provider_client_id text NOT NULL,
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotating', 'revoked')),
  -- IDN-04: revocation is an epoch bump, not waiting for a token to expire.
  credential_epoch   integer NOT NULL DEFAULT 1 CHECK (credential_epoch > 0),
  created_at         timestamptz NOT NULL DEFAULT now(),
  revoked_at         timestamptz,
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (issuer, provider_client_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, environment_id, principal_id) REFERENCES principals (tenant_id, environment_id, id) ON DELETE RESTRICT
);

-- ── Capability ───────────────────────────────────────────────────────────────

CREATE TABLE capabilities (
  id                   uuid NOT NULL DEFAULT uuidv7(),
  tenant_id            uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id       uuid NOT NULL,
  -- Must exist in the @trustos/contracts catalog. POL-01.
  action_key           text NOT NULL CHECK (action_key ~ '^[a-z]+\.[a-z]+\.[a-z]+$'),
  resource_type        text NOT NULL,
  input_schema_version integer NOT NULL DEFAULT 1 CHECK (input_schema_version > 0),
  schema               jsonb NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, environment_id, action_key),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE capability_grants (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  principal_id   uuid NOT NULL,
  action_key     text NOT NULL,
  -- Resource and parameter bounds. POL-07: policy cannot widen these.
  constraints    jsonb NOT NULL DEFAULT '{}'::jsonb,
  revision       integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, environment_id, principal_id, action_key),
  FOREIGN KEY (tenant_id, environment_id, principal_id) REFERENCES principals (tenant_id, environment_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, environment_id, action_key) REFERENCES capabilities (tenant_id, environment_id, action_key) ON DELETE RESTRICT
);

-- ── Policy ───────────────────────────────────────────────────────────────────

CREATE TABLE policies (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  name           text NOT NULL,
  status         text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'retired')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, environment_id, name),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE policy_versions (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  policy_id      uuid NOT NULL,
  version        integer NOT NULL CHECK (version > 0),
  content        jsonb NOT NULL,
  -- sha256 of canonical content. What the reviewer signs off on (SEC-01).
  hash           text NOT NULL CHECK (hash ~ '^sha256:[0-9a-f]{64}$'),
  author_id      uuid NOT NULL,
  published_at   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, policy_id, version),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES policies (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, author_id) REFERENCES memberships (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE policy_reviews (
  id            uuid NOT NULL DEFAULT uuidv7(),
  tenant_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  version_id    uuid NOT NULL,
  -- SEC-01: the reviewer attests to an exact hash, so a later edit voids the review.
  reviewed_hash text NOT NULL CHECK (reviewed_hash ~ '^sha256:[0-9a-f]{64}$'),
  reviewer_id   uuid NOT NULL,
  decision      text NOT NULL CHECK (decision IN ('approved', 'rejected')),
  reviewed_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, version_id) REFERENCES policy_versions (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, reviewer_id) REFERENCES memberships (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE policy_bundles (
  id               uuid NOT NULL DEFAULT uuidv7(),
  tenant_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id   uuid NOT NULL,
  revision         integer NOT NULL CHECK (revision > 0),
  version_ids      uuid[] NOT NULL,
  compiled         jsonb NOT NULL,
  compiled_hash    text NOT NULL CHECK (compiled_hash ~ '^sha256:[0-9a-f]{64}$'),
  -- Replay needs the evaluator build, not just the rules (§7.2).
  evaluator_version text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, environment_id, revision),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);
