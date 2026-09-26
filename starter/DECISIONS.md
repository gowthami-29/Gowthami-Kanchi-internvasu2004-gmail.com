# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### <the decision, as a claim — not "permissions", but "the org-level view counts device-scoped grants">

**What I chose:**
**Why:** _(evidence: test, log line, commit)_
**What I rejected:** _(the plausible alternative, and the specific reason it fails)_
**What would change my mind:**

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

## The permission catalogue is authoritative for grant validation

**What I chose:** Validate every requested grant permission against `permission_patterns` before checking whether the caller is allowed to grant it.

**Why:** My first implementation called `assertMayGrant()` before the catalogue lookup. The D19 test for `device:teleport` then returned `403 missing_permission` instead of the required `400 unknown_permission`. Moving the catalogue check first changed the result to `400 unknown_permission`, and the complete D19 section subsequently passed.

**What I rejected:** Treating an unknown permission as simply another permission the caller does not possess. That loses the distinction between an invalid permission name and a valid permission that the caller lacks.

**What would change my mind:** A test or schema rule explicitly requiring unknown permissions to be treated as authorization failures rather than input validation failures.

---

## Self-grants are rejected explicitly

**What I chose:** A caller cannot grant permissions to their own user ID, even when the caller already possesses those permissions.

**Why:** The D9 test explicitly exercises a self-grant and expects `FORBIDDEN`. The check is therefore performed against the target user ID rather than relying only on permission resolution.

**What I rejected:** Allowing a caller to grant themselves an authority they already hold. That would make the grant mechanism unnecessary for the caller and would create an avoidable privilege-laundering path.

**What would change my mind:** A requirement allowing self-grants for a documented administrative use case.

---

## Organization isolation is structural

**What I chose:** Resource queries include the current organization ID instead of fetching a resource first and checking its organization afterward.

**Why:** The cross-organization tests require foreign resources to appear as `404 NOT_FOUND`, without leaking organization data. The session and membership queries therefore constrain the resource lookup to `ctx.orgId`.

**What I rejected:** Fetching an object by ID first and returning `403` when its organization differs. That would reveal that the foreign resource exists and would violate the required invisible cross-organization behavior.

**What would change my mind:** A documented API requirement that distinguishes resource existence across organizations.

---

## Role changes use authority rules rather than a simple role ranking

**What I chose:** Member role modification uses the existing role-authority rules and explicitly prevents self-role changes and unauthorized owner grants.

**Why:** The D8 tests include both self-role modification and an admin attempting to confer owner. Both must be rejected, while demoting a non-last owner remains allowed.

**What I rejected:** Treating roles as a simple numeric hierarchy where every higher role can freely assign every lower or equal role.

**What would change my mind:** A schema or policy definition establishing a complete total ordering for every role and allowing role assignment solely from that ordering.

---

## The final owner cannot leave

**What I chose:** Leaving an organization is rejected when the caller is the last active owner.

**Why:** The D8 test creates a new organization where the creator is the sole owner and then expects the leave operation to return `LAST_OWNER`.

**What I rejected:** Allowing the organization to temporarily have zero owners. That would create an organization with no remaining authority to administer it.

**What would change my mind:** A documented ownership-transfer or automatic-admin mechanism that guarantees another administrator before the final owner is removed.

---

## Invite tokens are stored only as hashes

**What I chose:** Store only `hashInviteToken(rawToken)` in the database and return the raw token only during invite creation.

**Why:** The invite schema explicitly provides `token_hash` and describes it as hash-only storage. The API test also requires the raw token to be returned once and verifies that the public preview does not expose sensitive organization information.

**What I rejected:** Storing the raw invite token so it could be retrieved later. That would turn a database read into possession of a usable bearer credential.

**What would change my mind:** A requirement for server-side token recovery that could not be satisfied through one-time delivery.

---

## Invite acceptance is single-use

**What I chose:** Acceptance checks the invite state and performs the accepted-state update as part of the same database transaction as user and membership creation.

**Why:** The invite test requires the first acceptance to succeed and reuse of the same token to return `409`. The database also defines the invite lifecycle fields and a unique live-invite constraint.

**What I rejected:** Marking the invite accepted in a separate operation after creating the user. That creates a race window where the same invite could be accepted more than once.

**What would change my mind:** A database-level mechanism that provided equivalent atomic single-use guarantees without the transaction.

---

## Session authorization requires both permissions

**What I chose:** Starting a session requires `session:start` plus the permission corresponding to the requested mode on the exact device.

**Why:** The session tests distinguish missing session-start authority from missing device capability. The implemented `assertCanStartSession()` preserves those two failure reasons.

**What I rejected:** Treating a device permission such as `device:view` or `device:control` as sufficient to start a session.

**What would change my mind:** A requirement explicitly defining device capability as the complete authorization for session creation.


## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.


### The written permission matrix is not the complete permission model

**Written statements:** `PERMISSIONS.md` describes `roles` as “five rows” and `permissions` as “the nineteen permissions,” including a fixed role-permission matrix. It also says the database/reference data is the single source of truth.

`DISCOVERY-BRIEF.md`, however, explicitly says the personalized database contains “a role that appears in none of the documents” and “a permission that appears in none of the documents,” and warns that implementing the documented 5-role / 19-permission matrix will fail grading.

**What I built against:** I treated the runtime database as authoritative and resolved roles, permissions, role baselines, permission patterns, and grants from the database rather than hardcoding the documented matrix.

**Why:** The assignment explicitly states that hidden grading uses a different personalized overlay. Hardcoding the published matrix would pass the visible fixture but fail the intended personalization test.

---

### Unknown permissions are both a database invariant and an API validation concern

**Written statements:** The database documentation says the `grant_permissions` foreign key rejects unknown permission strings and specifically describes `device:teleport` as a database-level error when foreign keys are enabled.

The D19 API behavior, however, requires the request to be rejected as `400 unknown_permission`, before authorization produces a `403`. The implemented route therefore validates the permission catalogue before calling `assertMayGrant()`.

**What I built against:** I kept the database foreign key as the integrity backstop, but performed explicit catalogue validation at the API boundary first.

**Why:** The database constraint protects persistence, but it cannot by itself produce the required HTTP error semantics. The earlier implementation called `assertMayGrant()` first and produced `403 missing_permission` for `device:teleport`; the D19 test exposed that ordering problem.

## Deliberately not built

### No additional authentication or account-recovery features

I did not build password reset, email delivery, or rate limiting. These are explicitly outside the requested scope; the brief lists them under “Deliberately not here.” Invite tokens are therefore returned through the API rather than implementing an email-delivery system.

### No multi-region infrastructure

I did not add multi-region deployment, replication, or distributed coordination. The brief explicitly excludes “Multi-region anything,” so adding it would increase complexity without addressing the assignment requirements.

### No hardcoded frontend permission matrix

I did not add a role-to-permission table to the frontend. The brief requires the server to remain the single permission-resolution engine, with the console rendering from resolved API permissions.

### No permission caching that could serve stale authority

I did not introduce a permission cache. The permission model requires fresh resolution, and the brief specifically warns that cached authority must not become stale after role or grant changes.

### No features outside the Q1 scope

I did not implement features identified as outside the exercise scope, including password reset, rate limiting, email delivery, and multi-region functionality. This keeps the implementation focused on the authentication, organization, membership, permission, grant, invite, session, and audit requirements that were actually exercised.
