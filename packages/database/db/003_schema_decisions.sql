-- Decision, enforcement and evidence tables (architecture.md §6.3).
--
-- The load-bearing constraints here are the UNIQUE ones. They are not tuning: each
-- turns an application rule into something the database refuses to break, even under
-- concurrency, even if the application logic is wrong.
--
--   consumption_receipts.grant_id UNIQUE  -> one consume per grant, ever (INVARIANT 4)
--   idempotency_records (...) UNIQUE      -> one original decision per key  (AUT-02)
--   execution_grants.decision_id UNIQUE   -> a decision cannot mint a second grant
--   audit_events (tenant, env, seq) UNIQUE-> no gaps or forks in the hash chain


CREATE TABLE authorization_requests (
  id                   uuid NOT NULL DEFAULT uuidv7(),
  tenant_id            uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id       uuid NOT NULL,
  principal_id         uuid NOT NULL,
  gateway_principal_id uuid,
  action_key           text NOT NULL,
  resource_type        text NOT NULL,
  resource_id          text NOT NULL,
  resource_version     text,
  -- Canonical digest over normalized agent, action, resource, parameters, deadline,
  -- trusted facts and gateway audience (§8.1 step 2). Binds a grant to one request.
  request_hash         text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  -- Digest only. The replayable context lives encrypted with its own retention (§6.3).
  context_snapshot_ref text,
  context_digest       text,
  business_deadline    timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, environment_id, principal_id) REFERENCES principals (tenant_id, environment_id, id) ON DELETE RESTRICT
);

CREATE TABLE decisions (
  id               uuid NOT NULL DEFAULT uuidv7(),
  tenant_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id   uuid NOT NULL,
  request_id       uuid NOT NULL,
  effect           text NOT NULL CHECK (effect IN ('allow', 'deny', 'approval_required')),
  -- 'shadow' decisions never produce a grant (INVARIANT 3, AUT-08).
  mode             text NOT NULL CHECK (mode IN ('shadow', 'enforced')),
  reason_codes     text[] NOT NULL DEFAULT '{}',
  obligations      text[] NOT NULL DEFAULT '{}',
  bundle_revision  integer NOT NULL,
  -- Epochs at decision time. Consumption compares against current values (§8.3 step 3).
  principal_epoch  integer NOT NULL,
  credential_epoch integer NOT NULL,
  org_epoch        integer NOT NULL,
  expires_at       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  -- One decision per request: the original effect is immutable (§9.2).
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES authorization_requests (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE idempotency_records (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  caller_id      uuid NOT NULL,
  route          text NOT NULL,
  key_hash       text NOT NULL,
  -- Same key + same body returns the original; same key + different body is 409.
  request_hash   text NOT NULL,
  response_ref   uuid,
  status_code    integer,
  expires_at     timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, environment_id, caller_id, route, key_hash),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE approval_requests (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  decision_id    uuid NOT NULL,
  group_id       uuid NOT NULL,
  state          text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
  -- Optimistic concurrency for the resolution race (APR-02, §8.2).
  version        integer NOT NULL DEFAULT 1 CHECK (version > 0),
  -- Server time governs, even if the expiry worker is late (APR-01).
  expires_at     timestamptz NOT NULL,
  resolved_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, decision_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES decisions (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, group_id) REFERENCES approver_groups (tenant_id, id) ON DELETE RESTRICT,
  CONSTRAINT terminal_states_have_resolution_time CHECK (
    (state = 'pending') = (resolved_at IS NULL)
  )
);

CREATE TABLE approval_events (
  id               uuid NOT NULL DEFAULT uuidv7(),
  tenant_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  request_id       uuid NOT NULL,
  actor_id         uuid,
  effect           text NOT NULL CHECK (effect IN ('approved', 'rejected', 'expired', 'cancelled')),
  reason           text,
  session_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES approval_requests (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, actor_id) REFERENCES memberships (tenant_id, id) ON DELETE RESTRICT,
  -- Expiry and cancellation have no human actor; approve and reject must have one.
  CONSTRAINT human_effects_have_actors CHECK (
    effect IN ('expired', 'cancelled') OR actor_id IS NOT NULL
  )
);

CREATE TABLE execution_grants (
  id               uuid NOT NULL DEFAULT uuidv7(),
  tenant_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id   uuid NOT NULL,
  decision_id      uuid NOT NULL,
  -- Grant is valid only for this gateway and this exact request (AUT-07).
  gateway_audience text NOT NULL,
  request_hash     text NOT NULL,
  state            text NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'consumed', 'expired', 'revoked')),
  bundle_revision  integer NOT NULL,
  principal_epoch  integer NOT NULL,
  credential_epoch integer NOT NULL,
  -- Default 60s, never beyond the business deadline (§8.3).
  expires_at       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  -- A decision mints at most one grant. No implicit refresh (§9.2).
  UNIQUE (tenant_id, decision_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES decisions (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE consumption_receipts (
  id            uuid NOT NULL DEFAULT uuidv7(),
  tenant_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  grant_id      uuid NOT NULL,
  gateway_id    uuid NOT NULL,
  -- Gateway's durable key. Same caller + same key recovers this receipt after a lost
  -- response; a different key gets GRANT_ALREADY_CONSUMED (§8.3).
  execution_key text NOT NULL CHECK (length(execution_key) BETWEEN 1 AND 255),
  consumed_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  -- INVARIANT 4. The whole enforcement model rests on this one line.
  UNIQUE (grant_id),
  UNIQUE (tenant_id, gateway_id, execution_key),
  FOREIGN KEY (tenant_id, grant_id) REFERENCES execution_grants (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE execution_outcomes (
  id                    uuid NOT NULL DEFAULT uuidv7(),
  tenant_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id        uuid NOT NULL,
  decision_id           uuid NOT NULL,
  receipt_id            uuid NOT NULL,
  -- Caller-supplied, unique per decision: append-only reports, no overwrite (AUT-04).
  report_id             text NOT NULL,
  state                 text NOT NULL CHECK (state IN ('started', 'succeeded', 'failed', 'unknown')),
  external_operation_id text,
  detail                jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_reconciliation     boolean NOT NULL DEFAULT false,
  reported_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, decision_id, report_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES decisions (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, receipt_id) REFERENCES consumption_receipts (tenant_id, id) ON DELETE RESTRICT
);

-- ── Evidence ─────────────────────────────────────────────────────────────────

CREATE TABLE audit_stream_heads (
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  next_sequence  bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
  previous_hash  text,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  -- One row per stream. Locked inside the business transaction to allocate a
  -- sequence and chain the hash (§10.2).
  PRIMARY KEY (tenant_id, environment_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE audit_events (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  sequence       bigint NOT NULL CHECK (sequence > 0),
  actor_type     text NOT NULL CHECK (actor_type IN ('human', 'agent', 'service', 'gateway', 'system')),
  actor_id       uuid,
  event_type     text NOT NULL,
  subject_type   text NOT NULL,
  subject_id     uuid,
  -- Masked before insert. Never raw prompts, payloads or secrets (INVARIANT 13).
  safe_payload   jsonb NOT NULL DEFAULT '{}'::jsonb,
  previous_hash  text,
  payload_hash   text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  occurred_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  -- A gap or a fork in the chain becomes an insert failure.
  UNIQUE (tenant_id, environment_id, sequence),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE outbox_events (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  event_type     text NOT NULL,
  payload        jsonb NOT NULL,
  dispatch_state text NOT NULL DEFAULT 'pending' CHECK (dispatch_state IN ('pending', 'claimed', 'dispatched', 'dead_lettered')),
  -- Bounded lease so a crashed dispatcher's work returns to the queue (§10.1).
  claimed_until  timestamptz,
  attempts       integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE webhook_endpoints (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  url            text NOT NULL,
  -- Secret ref, never the secret. Old/new overlap during rotation (§10.3).
  secret_ref     text NOT NULL,
  previous_secret_ref text,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  event_types    text[] NOT NULL DEFAULT '{}',
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT,
  -- Blocking private ranges happens at connection time too (DNS rebinding, §10.3);
  -- this only stops the obvious case at write time.
  CONSTRAINT webhook_url_is_https CHECK (url ~ '^https://')
);

CREATE TABLE webhook_deliveries (
  id              uuid NOT NULL DEFAULT uuidv7(),
  tenant_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  event_id        uuid NOT NULL,
  endpoint_id     uuid NOT NULL,
  attempt         integer NOT NULL CHECK (attempt > 0),
  status          text NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'dead_lettered')),
  response_code   integer,
  next_attempt_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, event_id, endpoint_id, attempt),
  FOREIGN KEY (tenant_id, event_id) REFERENCES outbox_events (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES webhook_endpoints (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE export_jobs (
  id             uuid NOT NULL DEFAULT uuidv7(),
  tenant_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  environment_id uuid NOT NULL,
  requester_id   uuid NOT NULL,
  filters        jsonb NOT NULL DEFAULT '{}'::jsonb,
  status         text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  object_ref     text,
  expires_at     timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, requester_id) REFERENCES memberships (tenant_id, id) ON DELETE RESTRICT
);
