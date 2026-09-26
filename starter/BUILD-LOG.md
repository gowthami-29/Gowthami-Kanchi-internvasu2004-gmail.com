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

### 2026-09-26

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

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
