const BASE = import.meta.env['VITE_CONTROL_API'] ?? 'http://localhost:53001';

export class ApiError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(
  token: string,
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    method: init.method ?? 'GET',
    headers: {
      authorization: `Bearer ${token}`,
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const e = payload as { code?: string; message?: string } | null;
    throw new ApiError(e?.code ?? 'UNKNOWN', response.status, e?.message ?? 'request failed');
  }
  return payload as T;
}

export interface Session {
  membership_id: string;
  organization: { id: string; name: string };
  role: string;
  user_id: string;
}

export interface Approval {
  id: string;
  decision_id: string;
  state: string;
  expires_at: string;
  action_key: string;
  resource_type: string;
  resource_id: string;
  resource_version: string | null;
  reason_codes: string[];
  agent_name: string;
  agent_owner: string | null;
  overdue: boolean;
}

export interface Agent {
  id: string;
  name: string;
  status: string;
  owner: string | null;
  auth_epoch: number;
  capabilities: string;
  last_activity: string | null;
}

export interface Overview {
  evaluated: string;
  denied: string;
  pending_approvals: string;
  consumed_grants: string;
  succeeded: string;
  missing_outcomes: string;
}

export interface AuditEvent {
  id: string;
  sequence: string;
  event_type: string;
  actor_type: string;
  subject_type: string;
  occurred_at: string;
}
