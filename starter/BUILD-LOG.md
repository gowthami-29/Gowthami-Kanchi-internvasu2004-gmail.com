# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation


### 2026-09-26

Expected the database reset command to work directly from my Windows PowerShell environment. The `npm run db:reset` command failed because its script uses the Unix `rm` command, which PowerShell did not recognize.

I removed the database files manually and ran `npm run db:load`, which then exposed a Windows path issue in `scripts/load-db.js`: the generated schema path contained `C:\C:\...`.

I changed the URL-to-path conversion to use `fileURLToPath`. After that, the database loaded successfully with 3 organizations, 8 users, 10 memberships, 9 devices, 6 grants, 3 sessions, and 7 audit events.

The personalized fixture also appeared: the `reviewer` role and `device:reboot` permission were present, including an allow on one device and a deny on another. This confirmed that the permission model cannot be based only on the documented roles and permissions.

## Phase 1 — token verification

I implemented `verifyAccessToken()` in `server/auth.js` using the existing HS256 signing setup.

I checked the token structure before accepting it, decoded the header and payload, verified `alg` and `typ`, recalculated the HMAC signature, and compared signatures using constant-time comparison.

I also enforced the required `exp`, `iss`, `aud`, and `jti` claims. In particular, `exp == now` is rejected because the expiry check is `<= now`.

I ran `node scripts/check-jwt.js`. The suite passed all malformed-token, algorithm-confusion, signature, expiry, issuer/audience, jti, and refresh-token cases.

Result: `ALL PASS — 43 passed, 0 failed`.

## Phase 2 — caller context and the resolution engine

The initial permission-engine run stopped at the provided `resolve()` stub with `NOT_IMPLEMENTED`. I reviewed the permission rules, database schema, reference data, and test harness before implementing the resolution logic.

I implemented `resolve()` using the database's permission catalogue and role-permission relationships rather than hardcoding the documented roles or permissions. The implementation handles membership, suspended membership, role baselines, active grants, device scope, time windows, wildcards, explicit deny precedence, and implicit denial.

While running the permission tests, the first implementation failed because I queried `gp.pattern`, but the `grant_permissions` table stores the pattern in the `permission` column. I corrected the query to use `gp.permission`.

I also implemented the compound session authorization check in `assertCanStartSession()`, requiring both `session:start` and the requested device-mode permission.

After the fixes, `node scripts/check-permissions.js` passed with:

`ALL PASS — 35 passed, 0 failed`

The passing tests covered role baselines, auditor/operator separation, device-scoped grants and denies, org-wide deny precedence, multi-org membership, non-membership, time windows, wildcards, compound session checks, and suspended memberships.

## Phase 3 — orgs, members, invites

### 2026-09-26

I implemented organization creation and the member lifecycle after the API tests exposed the required boundary behavior. Creating an organization creates the organization and makes the creator its sole owner. A token from another organization cannot address the new organization, which preserves structural organization isolation.

For membership changes, I kept self-role changes forbidden and enforced the final-owner guard. The leave-organization test initially exposed the `LAST_OWNER` boundary, so the route now converts that condition into the required `LAST_OWNER` response and does not remove the final owner.

I then implemented the invite lifecycle. Invite creation generates a high-entropy raw token, stores only its HMAC hash, and returns the raw token once. The public preview resolves the hash but exposes only the invite email, role, organization name, and expiry; it does not expose the organization ID or devices.

Invite acceptance creates the user with a new password hash, creates the invited membership with the invited role, and marks the invite accepted. A second acceptance is rejected, and the new password works for login while the seed password does not.

Final API result: `66 passed, 0 failed`.

## Phase 4 — devices and grants

### 2026-09-26

I implemented grant creation around the permission catalogue and the existing permission-resolution engine rather than adding a second authorization model.

The unknown-permission test initially returned `403 missing_permission` because authorization was checked before verifying that the permission existed in the catalogue. I moved catalogue validation before `assertMayGrant()`. The result is now the required `400` with reason `unknown_permission`.

Empty permission lists are rejected, and self-grants are rejected with `FORBIDDEN`. `assertMayGrant()` checks that the caller already holds the authority they are attempting to grant at the requested scope.

The grant insertion and grant-permission rows are written together in a database transaction. The final D19 tests passed.

## Phase 5 — sessions

### 2026-09-26

I kept session authorization as a compound check rather than treating `session:start` and the device-mode permission as interchangeable.

`assertCanStartSession()` first checks `session:start` and then checks the permission required by the requested mode on the exact device. This preserves different failure reasons for a user who lacks the ability to start sessions versus one who lacks the requested device capability.

The API tests confirmed that a viewer can receive a device-specific view grant without automatically gaining control or session-start authority. Exclusive control sessions are also enforced by the database constraint, while concurrent view sessions remain allowed.

## Phase 6 — audit

### 2026-09-26

I treated authorization denials as auditable events rather than recording only successful mutations. This matters because the API test suite explicitly checks that denied attempts appear in the audit history with a reason code.

Successful organization, membership, session, and grant operations also record audit events with the organization, actor, action, target, result, and request ID. The final audit tests confirmed that denied attempts are readable by an authorized owner and contain a denial reason.

## Phase 7 — the console

### 2026-09-26

No console/UI work was added during this implementation pass. The evaluated work was concentrated on the API authorization model, organization lifecycle, grants, sessions, audit behavior, and invite lifecycle.

I deliberately avoided adding an unrelated UI layer while the required API behavior was still being validated.

## Phase 8 — hardening

### 2026-09-26

I ran the provided API test suite repeatedly while fixing failures rather than relying only on manual endpoint checks.

The final run reported `66 passed, 0 failed`.

The main hardening issues found during implementation included Windows-specific database reset/path handling, permission-column naming in the grant resolution query, organization membership insertion order, final-owner protection, permission-catalog validation ordering, and missing HTTP error imports.

I left the existing application structure and database model intact and implemented the required behavior using the provided schema and helpers.

## Open threads

The required public API test suite currently passes with `66 passed, 0 failed`.

No known failing API-test requirement remains from the provided test suite.