# TrustOS Product Requirements Document

| Field | Value |
| --- | --- |
| Version | 1.1 Markdown specification |
| Status | Proposed requirements for validation and implementation |
| Date | 20 September 2026 |
| Source | TrustOS_Product_Requirements_Document.docx v1.0 |
| Audience | Founder, product, engineering, design, security, QA and pilot partners |
| Companion | [architecture.md](architecture.md) |
| Initial market | Organizations deploying AI sales or customer-support agents |

## 1. Executive decision

Build an enterprise control layer that identifies AI agents, assigns accountable human owners, restricts their capabilities, evaluates individual action requests, obtains human approval where required, and records decisions and outcomes.

The first release governs one CRM-connected sales or support workflow. It does not build agents, replace enterprise identity providers, process payments, or create public reputation scores for people.

The long-term vision includes portable trust evidence for humans, organizations and agents. This is a direction to validate, not a claim that the product cannot be replaced. Defensibility should come from effective controls, integration quality, reliability and customer trust—not withholding customer history.

### 1.1 Relationship to the earlier PRD

This file carries forward the earlier product scope, requirement identifiers, workflows and phased plan. The following proposed refinements remove implementation ambiguities; they are not evidence of functionality already built:

1. Approvals and idempotency records are durable in PostgreSQL; Redis is an accelerator, not their source of truth.
2. An authorization decision is not proof of execution. Protected writes require an online, single-use execution grant consumed by a trusted enforcement point.
3. Fail-closed behavior is the MVP default for enforced actions. Shadow mode never produces executable grants.
4. Execution reporting is required for enforced writes. Missing results remain visibly unknown rather than counted as successful actions.
5. The 16-week schedule targets pilot entry. Broad release requires four consecutive weeks of operational evidence and may occur later.
6. Retention periods, capacity figures and latency figures are proposed targets. They are not legal requirements, customer commitments or measured results.
7. Product credentials establish registered organizational ownership, not verified legal identity or agent competence. Legal verification and external attestation remain later capabilities.

## 2. Problem and opportunity

Agents can read customer records, send messages, update CRMs and request commercial exceptions. Broad credentials make it difficult to distinguish what an agent can technically access from what it is authorized to do in a particular business situation.

For any action, a customer should be able to answer:

- Which agent requested it, and which organization and human own that agent?
- What exact resource, parameters and purpose were involved?
- Which policy version allowed, denied or escalated it?
- Who approved it, if approval was required?
- Was the action attempted, completed, rejected by the destination, or left uncertain?

### 2.1 Positioning hypotheses

These are discovery hypotheses, not an exhaustive competitive assessment. Some existing identity, authorization and agent-security products overlap substantially.

| Existing category | Relevant capability | TrustOS differentiation to test |
| --- | --- | --- |
| Identity providers | Authentication, users, roles and machine identities | Business-action decisions, owner accountability and approval evidence |
| Authorization engines | Fine-grained permission decisions | Agent lifecycle, packaged workflows and operations experience |
| API gateways | Traffic, authentication and request controls | Business context and human approval before a specific action |
| Workflow platforms | Approvals and task orchestration | Shared policy enforcement across multiple agent runtimes |
| Observability and SIEM | Investigation and monitoring | Linked pre-action decision, approval, consumption and outcome |
| Model guardrails | Prompt and output filtering | Permissions on external tool actions regardless of model output |

### 2.2 First customer profile

- Has an agent already using or preparing to use external business tools.
- Has a platform or security owner and a business approver.
- Can place a trusted integration gateway between the agent and destination.
- Can define at most ten initial actions and provide representative test requests.
- Has an identifiable operational or security budget and willingness to discuss a paid pilot.

Initial geography is India, with global-ready tenant isolation and timestamp handling. Hosting region and data processing terms must be agreed with the first partner before production onboarding.

## 3. Vision, goals and non-goals

### 3.1 Vision

Provide portable evidence and enforceable authority for autonomous actions across systems, while retaining clear organizational ownership and human accountability.

### 3.2 MVP goals

| Goal | Acceptance measure |
| --- | --- |
| Accountability | Every active agent has an active owner and scoped credentials |
| Controlled autonomy | Policies distinguish allow, deny and approval_required |
| Enforcement | Protected writes pass through a trusted gateway that consumes a valid grant |
| Explainability | Operators see matched rules, reason codes and policy version |
| Containment | Suspension/revocation prevents new decisions and grant consumption within 10 seconds |
| Developer usability | A developer completes the sandbox quickstart within one working day |
| Evidence | Decision, approval, grant consumption and outcome are linked |

### 3.3 Principles

- Deny by default when no published policy authorizes an action.
- Reject or fail closed when identity, policy integrity or required context cannot be established.
- Keep policy evaluation deterministic; no LLM on the enforcement path.
- Distinguish registered ownership, authentication, authorization and successful execution.
- Preserve policy history and exportable evidence, subject to configured retention.
- Collect the minimum business context needed to decide and investigate.
- Never treat an approval notification, a dashboard badge or an agent's claim as execution authority.

### 3.4 Out of scope

- General-purpose agent builders, model training or model hosting.
- Replacement of IAM, SIEM, endpoint protection or secrets-management products.
- Public human reputation or competence scores; employment and credit decisions.
- Consumer career passports, blockchain, cryptocurrency or a token economy.
- Cross-company delegated authority, arbitrary agent-to-agent delegation and federation.
- Actual payment or refund execution, aggregate spending budgets and financial settlement.
- Multi-stage/quorum approval, native mobile apps and a connector marketplace.
- Automatic compliance certification or guarantees of preventing every malicious action.

## 4. Users and roles

| Persona | Main job | Required experience |
| --- | --- | --- |
| Developer | Integrate an agent and test action requests | SDK, API contract, sandbox and precise errors |
| Security administrator | Grant capabilities and publish controls | Policy simulation, change history and revocation |
| Business approver | Resolve a specific sensitive action | Masked context, consequence, reason and expiry |
| Operations manager | Monitor and contain incidents | Search, unknown outcomes and suspension |
| Auditor | Review evidence without changing controls | Read-only timeline and scoped export |
| AI software vendor | Embed governance for customers | Future tenant provisioning and delegated administration |

### 4.1 Default console role boundaries

| Role | Register agents | Change capabilities or publish policy | Resolve assigned approvals | Suspend agents | Read/export audit |
| --- | --- | --- | --- | --- | --- |
| Organization admin | Yes | Yes, with production review rules | Only if separately eligible | Yes | Yes |
| Security admin | Yes | Yes | Only if separately eligible | Yes | Yes |
| Developer | Draft and sandbox access | Draft/simulate only | No by default | Own sandbox agents | Scoped development evidence |
| Approver | No | No | Yes, if separation rules pass | No | Assigned request only |
| Operator | No | No | No by default | Yes | Scoped read; export by explicit grant |
| Auditor | No | No | No | No | Yes |

Production policy publication requires a second eligible administrator to review the exact draft hash. Approver eligibility is not implied by administrative status. Disallow approval by the request initiator or agent owner where separation of duties is configured; enable this by default for sensitive pilot actions.

## 5. Release scope

### 5.1 Included

Organizations; sandbox and production environments; memberships and privileged MFA; agent registry; owner assignment; credential lifecycle; action/resource catalog; grants; deterministic policies; immutable versions; simulation; authorization API; single-approver workflow; single-use execution grants; signed webhooks; audit search/export; kill switches; TypeScript SDK; one CRM reference integration.

Python SDK, polished health dashboards and reminders are secondary priorities. The Python SDK must pass the same contract tests before advertising full parity.

### 5.2 Pilot envelope

Start each partner with one workflow, one agent, up to ten action types, two approvers and one CRM integration. Plan an initial allowance of up to 100,000 authorization evaluations per month per partner. Burst capacity is a separate engineering target, not sustained usage included in that allowance.

Recruit two design partners; a third is optional. Three integrated workflows across two partners is a stretch outcome, not an MVP-entry prerequisite.

## 6. End-to-end workflows

### 6.1 Organization onboarding

1. An administrator establishes the organization and confirms the supported region.
2. Create sandbox and production environments with separate credentials and policies.
3. Invite members and assign roles; require MFA for privileged actions.
4. Configure retention, masked fields, approvers and emergency contacts.
5. Show an integration checklist, including the requirement to remove direct tool credentials from the agent runtime.

### 6.2 Register and activate an agent

1. Developer records name, purpose, runtime metadata and accountable owner.
2. Security administrator assigns specific capabilities and resource constraints.
3. Owner acknowledges responsibility; security administrator activates the agent.
4. Issue environment-scoped credentials through the configured authentication service.
5. Test an allowed, denied and approval-required request before production activation.

Owner departure suspends owned agents unless ownership is transferred first. Revoked identity IDs are never reused. Resuming a suspended agent is an explicit audited action; it does not revive old grants.

### 6.3 Routine protected action

1. Agent asks the customer-controlled tool gateway to perform an action.
2. Gateway resolves agent identity and trusted business attributes, then calls TrustOS.
3. TrustOS validates credentials, active status, capability grant and context schema.
4. Evaluate the current published policy bundle and durably record the result.
5. If allowed, issue a short-lived grant bound to the exact action fingerprint and gateway audience.
6. Gateway atomically consumes that grant online and invokes the destination using its own restricted credential.
7. Gateway reports the outcome and destination operation ID. Unknown results require reconciliation before retry.

### 6.4 Approval-required action

1. Create a pending approval with policy explanation, eligible approver group and expiry.
2. Notify the group; notification delivery is not approval authority.
3. Approver opens the authenticated console, reviews parameters and approves or rejects.
4. Server rechecks current role, separation rules, request state and server-side expiry.
5. On approval, make a grant available to the gateway for the original request only.
6. Consumption rechecks active identities and current policy revision; a policy change requires a new decision and, if still required, a new approval.

### 6.5 Incident response

1. Operator finds suspicious activity by agent, resource, decision or time.
2. Suspend the agent or revoke its credential and append an audit event.
3. Block subsequent decisions and grant consumption; show propagation status.
4. Review outcomes, including actions already in flight, and coordinate destination-side remediation.
5. Export evidence; rotate credentials and explicitly review reactivation.

Suspension cannot undo actions already executed or guarantee cancellation after a grant has been consumed.

## 7. Functional requirements

Must = required for enforced pilot. Should = desirable if capacity allows. Added requirements clarify v1.0 rather than asserting completed work.

### 7.1 Organization and identity

| ID | Priority | Requirement and acceptance condition |
| --- | --- | --- |
| ORG-01 | Must | Isolated tenants/environments; cross-boundary requests, cache keys and exports fail isolation tests |
| ORG-02 | Must | Invite, remove and role-change members; authority is checked server-side and changes are audited |
| ORG-03 | Must | MFA on privileged console access and step-up for sensitive changes |
| ORG-04 | Should | Explicit timezone, region and retention settings with change history; no self-service region migration |
| IDN-01 | Must | Stable IDs for human, agent and service principals; no reuse after revocation |
| IDN-02 | Must | Active owner required for every active agent; ownership transfer is audited |
| IDN-03 | Must | Draft, active, suspended and revoked states; only active agents receive authority |
| IDN-04 | Must | Scoped credential issue/rotate/revoke; token expiry alone is not the revocation mechanism |
| IDN-05 | Should | Runtime/model/deployment metadata is labeled self-reported unless independently attested |

### 7.2 Capability and policy management

| ID | Priority | Requirement and acceptance condition |
| --- | --- | --- |
| POL-01 | Must | Namespaced action and resource schema; unknown actions or unsupported parameters cannot authorize |
| POL-02 | Must | Typed conditions on identities, resources, amounts, environment and time; required trusted attributes cannot come solely from the agent |
| POL-03 | Must | Immutable published versions, review, retirement and rollback by new publication; decision records the bundle hash |
| POL-04 | Must | Draft simulation and regression cases; simulation cannot yield consumable grants |
| POL-05 | Must | Explicit deny wins; missing capability and schema errors cannot be overridden by allow |
| POL-06 | Must | approval_required effect specifies one approver group, timeout and obligations |
| POL-07 | Must | Added: approval thresholds do not override baseline resource/capability constraints; conflicting approval routes reject publication |

### 7.3 Decisions and execution

| ID | Priority | Requirement and acceptance condition |
| --- | --- | --- |
| AUT-01 | Must | Authenticated evaluation returns decision ID, effect, reasons, version, fingerprint and expiry |
| AUT-02 | Must | Same idempotency key and same normalized payload returns original decision; changed payload returns 409 |
| AUT-03 | Must | Machine-readable reasons and obligations; gateway refuses obligations it cannot enforce |
| AUT-04 | Must | Append-only outcome reporting linked to consumed grant; enforced writes require a report or visible unknown state |
| AUT-05 | Should | Signed decision/approval webhooks with retries and delivery history; polling remains supported |
| AUT-06 | Must | Tenant and principal limits, bounded payloads and predictable 429 responses |
| AUT-07 | Must | Added: online single-use grant consumption rejects replay, stale policy, wrong audience, wrong fingerprint and revoked authority |
| AUT-08 | Must | Added: shadow decisions never create execution authority; environment/mode shown throughout |

### 7.4 Approvals, evidence and operations

| ID | Priority | Requirement and acceptance condition |
| --- | --- | --- |
| APR-01 | Must | Durable expiring requests; expiry checks use server time even if scheduler is delayed |
| APR-02 | Must | Atomic approve/reject with actor/session evidence, reason and timestamp; conflicting resolutions cannot both succeed |
| APR-03 | Must | Eligible membership and configured separation of duties checked when resolving, not just when routing |
| AUD-01 | Must | Append-only application audit evidence; integrity manifests detect changes against protected checkpoints |
| AUD-02 | Must | Tenant-scoped cursor search and CSV/JSON export; mask sensitive context and audit downloads |
| OPS-01 | Must | Suspend/revoke/kill switch; stop new decisions and grant consumption within 10 seconds |
| OPS-02 | Should | Integration health, webhook backlog, approval age and missing-outcome dashboard |
| SEC-01 | Must | Added: production policy publication requires independent review of the exact version hash |

## 8. Decision semantics and example

Evaluation order:

1. Validate authentication, tenant and environment; reject malformed requests.
2. Check active credential, agent and owner, plus emergency stop state.
3. Validate action schema, capability grant and trusted context freshness.
4. Match explicit deny rules.
5. Match approval-required rules and merge compatible obligations.
6. Match allow rules and merge compatible obligations.
7. Deny if nothing permits the request; error or conflict never becomes allow.

Approval authorizes one request, not future requests with similar text. Published bundle revision changes invalidate unconsumed grants in the MVP.

### 8.1 Sales discount example

All paths require `crm.discount.apply`, an assigned customer region, permitted CRM resource, a business reason and a supported gateway. Discounts use integer basis points: 1,000 basis points = 10%.

| Condition after baseline checks | Effect |
| --- | --- |
| 0–1,000 basis points | allow |
| 1,001–2,000 basis points | approval_required from regional sales manager |
| Above 2,000, below zero or invalid type | deny or input validation failure |
| Region outside assigned set | deny, regardless of discount |

Default approval lifetime: 10 minutes. Default executable grant lifetime: 60 seconds after creation and never beyond the request's business deadline. Both are configurable downward for a pilot; increasing limits needs review.

Amounts use integer minor units plus explicit currency; percentage thresholds do not implicitly implement daily/cumulative spend limits.

## 9. Information model and API boundaries

Core records: organization, environment, membership, principal, credential binding, capability, capability grant, policy, immutable policy version, environment bundle revision, authorization request, decision, approval request, approval event, execution grant, consumption receipt, execution outcome, audit event, outbox event and webhook delivery.

All environment-owned references include tenant and environment scope. Memberships and organization configuration are tenant-scoped without an artificial environment. Published decisions/events are immutable; lifecycle and workflow projections may change through audited state transitions.

| Endpoint group | Required operations |
| --- | --- |
| Identity | Register/read agents, acknowledge ownership, activate/suspend/resume/revoke, rotate credentials |
| Policies | Create draft, validate, simulate, review, publish and retire |
| Decisions | POST /v1/authorize; GET /v1/decisions/{id} |
| Approval | Approve/reject/cancel pending request; list assigned queue |
| Enforcement | POST /v1/grants/{id}/consume; authenticated receipt lookup |
| Outcome | POST /v1/decisions/{id}/outcomes |
| Audit | Search events, request scoped export and retrieve export status |

Use versioned JSON/HTTPS contracts and OpenAPI 3.1. See architecture.md for sample payloads, authentication, idempotency, transactions and endpoint details.

## 10. User experience

| Screen | Required information and actions |
| --- | --- |
| Overview | Evaluated actions, completed governed actions, denies, pending approvals and missing outcomes |
| Agents | Owner, status, capability summary, last activity and emergency suspend |
| Agent detail | Credentials metadata, grants, deployment metadata and lifecycle history |
| Policies | Draft/published views, test cases, version diff, review and publish |
| Approvals | Exact action/resource/parameters, risk explanation, requester/owner, expiry and equal clarity for approve/reject |
| Decision explorer | Request → decision → approval → grant → consumption → outcome timeline |
| Audit/export | Tenant-safe filters, masking, export manifest and retention boundary |
| Developer setup | Sandbox credentials, quickstart, three decision examples and gateway checklist |

Production and sandbox must remain visually distinct. Never preselect approval. Require reason and confirmation for sensitive changes. Approval review works on mobile web; policy authoring is desktop-first. Errors must differentiate forbidden actions, expired requests, infrastructure failures and unknown external outcomes.

## 11. Security, privacy and responsible use

- Use an established identity provider for authentication; require privileged MFA and secure sessions.
- Keep destination tool credentials outside the agent runtime; otherwise enforcement is bypassable.
- Enforce tenant scope in services and database access, including jobs, caches and exports.
- Encrypt transport and stored data; use managed key and secret services.
- Redact secrets and minimize customer data before persistence; observability excludes raw prompts and credentials.
- Restrict audit modification by application roles and protect signed checkpoints separately from the main database.
- Run threat modeling, dependency/secret scanning, tenant isolation tests and independent security review before enforced pilot.
- Treat signed audit evidence as service-attested history, not legal proof that a human personally signed every action.
- Do not infer protected traits or create universal personal trust scores.

### 11.1 Retention proposal

Propose 365 days of decision/audit retention and 30 days of operational logs, subject to partner data minimization and contract review. Seven-year approval retention from v1.0 is an optional future configuration, not a universal regulated requirement. Do not sell retention or legal-hold guarantees before implementing and testing them.

Separate optional sensitive context from minimal evidence so approved deletion can remove it without silently rewriting history. Document archive and backup expiry, authorized deletion and affected integrity segments. No certification, legal sufficiency or regulatory coverage is claimed by this specification.

## 12. Nonfunctional targets

These targets require benchmarks and recovery drills before customer commitment.

| ID | Area | Proposed target and measurement |
| --- | --- | --- |
| NFR-01 | Latency | authorize p50 <50 ms and p95 <150 ms; server ingress to durable response, in-region, ≤10 rules/action and ≤16 KiB request |
| NFR-02 | Availability | 99.9% monthly for valid authorization/consumption requests; correct denies count as successful service responses |
| NFR-03 | Revocation | ≤10 seconds from committed suspension/revocation to blocking new authorization and grant consumption |
| NFR-04 | Pilot load | 100 RPS/tenant for a 60-second burst; initial pooled test at 300 RPS; sustained partner demand measured separately |
| NFR-05 | Storage | Validate search/retention with 10 million retained events for one synthetic tenant |
| NFR-06 | Durability | No loss of acknowledged decisions/audit events under a single database-node failure with configured synchronous failover |
| NFR-07 | Recovery | Disaster recovery RPO ≤5 minutes and RTO ≤60 minutes; must be demonstrated, not inferred from backups |
| NFR-08 | Accessibility | Core workflows target WCAG 2.1 AA; keyboard, focus and screen-reader checks |
| NFR-09 | Compatibility | Current and prior major browser versions at release; UTC storage and locale-aware display |

Report authorization and grant-consumption latency separately; end-to-end protected-write latency includes both calls and the destination. External approval time and destination latency are not hidden within the authorization SLO. Disaster recovery may lose data within the stated RPO; that is distinct from single-node failover durability.

## 13. Metrics and analytics

North star: monthly completed governed actions—distinct external actions with an enforced decision, valid consumed grant and successful gateway-reported outcome, deduplicated by decision and external operation ID. This is integration-reported evidence, not independent proof of destination truth.

Keep denied requests, shadow evaluations, approvals, failed executions and unknown outcomes as separate metrics.

| Metric | Pilot target |
| --- | --- |
| Partners | Two sandbox integrations; at least one enforced production workflow |
| Coverage | ≥90% of sensitive actions in the selected workflow pass through the gateway |
| Volume | 50,000 completed governed actions/month is a stretch validation target |
| Integration time | Under one working day with the documented sandbox quickstart |
| Approval time | Median <5 minutes during configured staffed hours; track expired requests separately |
| Test safety | All agreed unauthorized cases blocked; never extrapolate to zero real-world risk |
| Reliability | Meet NFR targets over an agreed observation period |
| Commercial signal | At least one explicit paid-conversion discussion and two partners willing to continue |

Measure coverage using the destination's action inventory/logs as well as TrustOS events; TrustOS cannot discover bypassed actions from its own logs alone. Track false denies, discovered false allows, missing outcomes, review reversals and operator time saved.

## 14. Step-by-step delivery plan

The 16-week plan assumes a product lead, two backend engineers, one frontend engineer, and part-time security, design, platform and QA support. A solo implementation will need a smaller scope or longer schedule.

| Step | Weeks | Work | Exit gate |
| --- | --- | --- | --- |
| 1. Validate | 1–2 | Interview 12–15 buyers; inventory five workflows; recruit partners; prototype onboarding/approval | Two partner commitments, budget owner and explicit protected-action list |
| 2. Foundations | 3–4 | Monorepo, CI, tenants, environments, identity provider, membership, agent/credential lifecycle | Active sandbox identity authenticates; isolation and suspension tests pass |
| 3. Policy | 5–6 | Typed schema, capability bounds, precedence, versioning, review, simulation | Deterministic partner cases including region/threshold boundaries pass |
| 4. Runtime | 7–8 | Authorize, durable idempotency, grants/consumption, outcomes, transactional audit/outbox, SDK | Allow/deny end-to-end gateway path; concurrency/replay tests pass |
| 5. Approval and console | 9–10 | Pending queue, routing, resolution, expiry, mobile review, webhook/polling | One valid resolution; no self-approval, expired consumption or replay |
| 6. Hardening | 11–12 | Evidence/export, restore drill, load tests, threat review, runbooks, isolation audit | No unresolved high/critical findings and verified containment/recovery |
| 7. Partner shadow | 13–14 | CRM adapter, historical replay, live shadow, outcome comparison | Agreed false-deny tolerance and no false allows in safety test suite |
| 8. Enforced pilot | 15–16 | Limited actions/agents, daily monitoring, weekly partner review | Stable protected workflow, accepted export and explicit continuation decision |
| 9. Release assessment | After sufficient evidence | Four consecutive weeks meeting SLOs; security and commercial review | Go, narrow scope, iterate or stop |

### 14.1 Per-step completion checklist

- Requirement ID, acceptance cases and failure behavior documented.
- API/SDK contract updated with examples and migration notes.
- Unit, integration, concurrency and tenant-isolation tests pass.
- Security review covers credentials, permissions, logs and trusted context.
- Metrics, audit events, alerts and rollback/recovery instructions exist.
- Product owner accepts staging behavior; accessibility checked where applicable.

## 15. Pilot and launch strategy

Roll out through historical replay, live shadow, advisory review, limited enforcement and then expanded enforcement. Shadow/advisory modes cannot grant execution authority. Expansion requires approval by partner security and business owners.

Launch gates:

1. No unresolved critical/high security findings.
2. At least two sandbox partners and one stable enforced production workflow.
3. Four consecutive weeks of measured availability and latency meeting targets.
4. Expired, replayed, altered, cross-tenant and revoked requests blocked in the safety suite.
5. Evidence export accepted by a partner reviewer; restore and kill-switch drills passed.
6. Support ownership, incident contacts, contract scope and pricing discussion established.

Pause enforcement expansion if coverage is unmeasurable, destination credentials remain accessible to the agent, or approvals are routinely bypassed. A pause does not mean silently enabling fail-open behavior.

## 16. Commercial model and defensibility

Test a base platform subscription with included governed-action allowance, then metered usage and enterprise controls. Potential buyers include security, platform and AI-product leadership; interviews must establish who actually owns budget.

| Offering | Hypothesis |
| --- | --- |
| Developer | Free sandbox, limited volume and retention |
| Team | Production base fee plus usage |
| Enterprise | Annual terms, volume commitments, support and independently validated controls |
| Embedded | Later vendor/tenant provisioning plus usage |

Do not set prices from assumptions alone. Measure inference-free decision cost, durable storage, archive/export cost, support hours and partner willingness to pay. No market-size or margin claim is established here.

The potential moat is integration depth, reliable enforcement, historical evidence and a shared capability vocabulary. Support evidence export and avoid artificial lock-in.

## 17. Risks and open decisions

| Risk | Mitigation or decision |
| --- | --- |
| Buyers already use overlapping products | Validate a differentiated workflow and willingness to pay before expanding scope |
| Weak adoption or unclear budget | Paid-pilot discussion and explicit go/stop gate |
| Gateway bypass | Remove direct credentials, restrict egress and compare destination logs |
| Policy mistakes | Typed DSL, deny precedence, boundary tests, independent publication review |
| Inline outage | Fail closed, bounded retries, queue safe work; no silent authorization fallback |
| Ambiguous external result | Reconcile by destination operation ID before retry |
| Sensitive context leakage | Minimize, redact, separate payload retention and restrict exports |
| Broad platform ambition | Hold scope to one workflow; defer reputation and federation |

Proposed defaults requiring owner confirmation before production: first partner/action list; cloud region/provider; authentication provider; approver coverage; retention and deletion terms; capacity/SLO commitment; destination idempotency support. architecture.md records the technical defaults.

## 18. End-to-end acceptance suite

| Test | Expected result |
| --- | --- |
| Correct active agent, granted resource, discount 10% | allow; one consumable grant |
| Same action at 15% | approval_required; no grant before approval |
| Discount 25% or unassigned region | deny even if an approver is available |
| Missing trusted region or malformed amount | No authority; explicit validation/context reason |
| Agent impersonation or cross-environment credential | Authentication/scope rejection |
| Same request idempotency key and body | Same original decision; no second approval or grant |
| Same key and changed body | 409 conflict |
| Two approval resolutions race | One winner, other gets terminal-state response |
| Owner attempts own sensitive approval | Rejected by server |
| Approval expires while notification is delayed | Cannot approve or consume |
| Policy published while grant waits | Consumption rejected; new decision required |
| Two gateways consume one grant | Only one consumption receipt authorizes one execution intent |
| Consumption response lost | Same consumer/key can retrieve receipt; no second consume |
| Destination times out after write | Outcome unknown; reconciliation required before retry |
| Agent suspended after approval | New authorize/consume blocked within target; in-flight limits disclosed |
| Audit database write fails | No success/grant acknowledgement |
| Webhook delivery fails | Retry/dead-letter; durable approval remains accessible by polling |
| Auditor tries policy update | Denied; read/export still scoped |
| Owner removed | Owned active agents suspended or previously transferred |
| CRM logs contain bypassed write | Coverage warning; do not count as governed |

## 19. Future roadmap

1. After pilot: enterprise SSO/SCIM, multi-stage approvals, SIEM integration, richer connectors and configurable archive tiers.
2. Growth: delegated authority chains, verified vendor identities, regional runtimes and organization policy packs.
3. Platform: portable capability attestations and independently verifiable evidence formats.
4. Long term: user-controlled contextual passports for humans, organizations, devices and agents, only after privacy and market validation.

## 20. Initial action catalog

Select no more than ten for the first partner. Action keys below are the canonical proposed vocabulary; adapters map native CRM names to these keys.

| Domain | Candidate action keys |
| --- | --- |
| CRM | crm.lead.read, crm.lead.update, crm.lead.assign, crm.note.create, crm.discount.apply |
| Communication | communication.call.initiate, communication.email.send |
| Calendar | calendar.availability.read, calendar.meeting.create, calendar.meeting.cancel |
| Support | support.ticket.read, support.ticket.update, support.refund.request |

Payment/refund movement stays outside TrustOS. Regulating an action does not itself establish customer consent or other business/legal permission; the gateway must supply and enforce applicable business constraints.
