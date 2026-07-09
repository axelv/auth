# GoTrue-patch feasibility for scoped sessions

> Written on branch `claude/gotrue-scoped-sessions-research-br43vc` in the
> `axelv/auth` fork of `supabase/auth`. The referenced integration repo (which
> holds `design/scoped-sessions.md`, `docker-compose.gotrue.yml`, `infra/…`,
> `scripts/…`, `supabase/migrations/…`) is out-of-tree from this fork; copy
> this file into that repo's `design/` directory to file it alongside its
> sibling design doc. All GoTrue code references below cite paths inside the
> fork's tree at commit tip of the branch (upstream ≈ v2.192.0).

## TL;DR

**Recommendation: (c) stick with the workaround indefinitely.** Do **not** pursue
an upstream PR — three separate asks for the exact capability
([#104](https://github.com/supabase/auth/issues/104),
[#719](https://github.com/supabase/auth/issues/719),
[PR #1993](https://github.com/supabase/auth/pull/1993)) have been declined by
maintainers, the most recent (Apr 2025) with an explicit `wontfix` label and
"fork it if you must" guidance. A private fork is technically small (~60–100
LOC across ~15 files) but the merge burden is real: upstream has cut ~1 minor
release per month for 13 months, has touched hook-payload code three times in
the last six months, and shows no interest in taking the change back. The
`scoped_grant_pending` table costs one row per exchange (deleted immediately)
and two GoTrue calls that were already cheap — it is objectively less
expensive than paying merge cost on every release for a diff we cannot
upstream. **Runner-up: (d) adopt `raw_app_meta_data.pending_grant_id`** if the
workaround table becomes operationally painful — analysed under Q6 below.

---

## 1. Does GoTrue already have a "context through the hook" mechanism?

**No.** The event delivered to `custom_access_token_hook` has four fields, none
of them caller-supplied except the client's IP address:

```
CustomAccessTokenInput {
    UserID               uuid.UUID
    Claims               *AccessTokenClaims     // built from persisted user row
    AuthenticationMethod string
    Metadata             *Metadata              // { uuid, time, name, ip_address }
}
```

Source: `internal/hooks/v0hooks/v0hooks.go:168-187`. Field-level derivation:

- `Claims.AppMetadata` / `UserMetadata` ← `params.User.AppMetaData` / `UserMetaData`
  read from `auth.users` (`internal/tokens/service.go:709-710`). Persistent
  row, not per-request.
- `Claims.SessionID`, `AAL`, `AMR`, `Scopes` ← session lookup +
  `CalculateAALAndAMR` (`internal/tokens/service.go:664-697`).
- `Claims.ClientID` ← `params.ClientID` (OAuth server flows only).
- `Metadata.IPAddress` ← `utilities.GetIPAddress(r)` (`v0hooks.go:48-55`) — the
  ONLY request-derived field.

No query params, no request body, no headers besides IP flow into the hook.
Every other hook (`SendSMS`, `SendEmail`, `MFAVerification`,
`PasswordVerification`, `BeforeUserCreated`, `AfterUserCreated` — all in
`v0hooks.go:18-26`) uses the identical `Metadata` wrapper; there is no
established "arbitrary caller context" pattern anywhere in the hook subsystem.

**We are not re-inventing something that exists.** `raw_app_meta_data` reaches
the hook, but it reaches it via the persistent `auth.users.raw_app_meta_data`
column — writing it just before session mint is exactly the race-prone
workaround Q6 evaluates, not a supported context channel.

---

## 2. How large is the change in the GoTrue codebase?

**Modest but wide.** ~60–100 LOC touching ~15 files. Almost all mechanical
plumbing; no algorithmic changes.

| File | Change | ~LOC |
|---|---|---|
| `internal/hooks/v0hooks/v0hooks.go:168-187` | Add `SessionContext map[string]any` field + JSON tag; extend `NewCustomAccessTokenInput` | ~5 |
| `internal/tokens/service.go:118-124` | Add `SessionContext` to `GenerateAccessTokenParams` | ~1 |
| `internal/tokens/service.go:722-727` | Wire through into `NewCustomAccessTokenInput` | ~1 |
| `internal/tokens/service.go:592`, `:926` (`RefreshTokenGrant`, session issuance) | Populate param | ~2 |
| `internal/api/token.go:291-297` (`generateAccessToken`), `:380` (MFA), `:299-301` (`issueRefreshToken`) | Thread arg through | ~5–10 |
| Existing callers with **no source to populate from today**: `verify.go:185,285`, `anonymous.go:47`, `signup.go:315`, `external.go:241`, `token_oidc.go:346`, `samlacs.go:347`, `passkey_authentication.go:192`, `web3.go:168,314`, `token.go:195,265` | Nil-pass or new request-body field | ~1–2 each |
| `internal/hooks/v0hooks/manager_test.go:175,326,348,385,437`, `internal/api/e2e_test.go:952` | Fixture updates | ~10 |

The core insertion point is trivial: the hook input struct + one plumbing hop
into `Service.GenerateAccessToken`. The tax is the ~10 caller sites that must
now decide whether to nil-pass or route a new field from their request body.
For our use case only two matter — `POST /verify` (where `verifyOtp` fires
after `generateLink`) and `POST /token?grant_type=password` — so a pragmatic
patch only wires up those two and nil-passes everywhere else.

**Nothing in the hook dispatch layer changes.** The Postgres path
(`internal/hooks/hookspgfunc/hookspgfunc.go:50-71` — `select hookname(?)`
with marshalled JSON) and the HTTPS path
(`internal/hooks/hookshttp/hookshttp.go:84-105` — standard-webhooks signed) are
schema-agnostic: they marshal whatever you hand them.

**Shape reference — recent PRs that made comparable single-field additions:**

- [PR #2274](https://github.com/supabase/auth/pull/2274) — `amr` shape change
  in the hook payload. Merged Dec 2025. Roughly matches the surface area we'd
  touch.
- [PR #2576](https://github.com/supabase/auth/pull/2576) — per-provider
  `custom_claims_allowlist`. Merged Jun 2026 as v2.192.0. Extends
  `raw_user_meta_data.custom_claims` — same subsystem, precedent for adding
  claim-shaped fields.

Neither is caller-supplied per-request; both live in the "extend persistent
storage" mold that upstream prefers.

---

## 3. Is there upstream interest?

**No — actively negative signal.** Three prior asks for the exact capability
(or a superset) have all been declined:

- **[#104](https://github.com/supabase/auth/issues/104)** (Sep 2021, opened by
  `@awalias`, Supabase MEMBER) — "Generate access_tokens via API." The
  admin-mints-token feature is closed **`not_planned`** in Sep 2022.
- **[#719](https://github.com/supabase/auth/issues/719)** (2022) — "Add
  ability to set non-persistent custom claims on JWTs." The exact per-session
  claims use case. Closed **`not_planned`** Sep 2022. Multi-tenant motivation.
- **[PR #1993](https://github.com/supabase/auth/pull/1993)** (Apr 2025) —
  "add endpoint to allow admins to generate an auth code for a user based on
  their user id." Closed with **`wontfix`** label by `@cstockton` (core
  contributor). Explicit rationale (paraphrased from the closing comment):
  *"it's best to not include it in the mainline release … it introduces a
  custom flow that diverges from established standards"* — with fork-or-wait
  guidance. This is the most direct rejection and it's recent.

**No active PR or roadmap issue targets caller-supplied per-request hook
context.** Hook-related work in the last six months is all orthogonal:

- **[PR #1913](https://github.com/supabase/auth/pull/1913)** — relaxes
  required claims in the hook output (open).
- **[PR #2274](https://github.com/supabase/auth/pull/2274)** — `amr` shape
  loosening (merged).
- **[PR #2576](https://github.com/supabase/auth/pull/2576)** — per-provider
  `custom_claims_allowlist` on the persistent path (merged v2.192.0).
- **[PR #2012](https://github.com/supabase/auth/pull/2012)** — before/after
  user creation hooks (closed unmerged May 2025).

**One bystander wants the underlying capability.**
[#1615](https://github.com/supabase/auth/issues/1615) has a comment from
`@lauri865` complaining that they have to "resort to contrived backend code and
re-creating JWTs to add custom logic" because GoTrue doesn't expose
per-request context. Open, no maintainer response on that point.

No matches for `session_context`, `hook context`, `per-session claims`,
`pending_grant_id`, `raw_app_meta_data race`, `session-scoped`, or
`access token hook context` in either open or closed issues. This absence is
itself informative: nobody has argued the concurrency-race angle for
`raw_app_meta_data` upstream, which suggests the maintainers have not
considered (and would not be primed to sympathise with) our specific problem.

Confidence: the "upstream declined" reading is strong (three closures, one
recent, with explicit fork guidance). The "no matching PR" reading is very
strong (comprehensive keyword search). The "no maintainer would take this
PR if opened" reading is inference from pattern, not a verbatim quote —
graded as "highly likely, not certain."

---

## 4. Is there an admin endpoint that mints a session for a `user_id` directly?

**No.** The admin surface (`internal/api/api.go:345-429`) exposes
`/admin/audit`, `/admin/users` (CRUD, factors, passkeys), `/admin/generate_link`,
`/admin/sso`, `/admin/oauth`, `/admin/custom-providers`. There is no
`/admin/sessions`, no `/admin/users/{id}/sessions`, no `/impersonate`.

The closest primitive is `POST /admin/generate_link` — which we already use —
producing an `action_link`/`hashed_token` the caller must redeem via
`POST /verify` (`internal/api/verify.go:229-290`). That second call is where
`GenerateAccessToken` runs and the hook fires. **We cannot skip the
`verifyOtp` step**: the hook only fires on token issuance, and token issuance
requires session creation, and there is no admin path to session creation.

PR #1993 (see Q3) tried to add exactly this endpoint. It was refused.

Impersonation in the wider Supabase ecosystem exists only in
[supabase/supabase PR #32603](https://github.com/supabase/supabase) at the
dashboard layer, using the same
`admin.generateLink` → `verify` two-step flow under the hood.

---

## 5. What is the maintenance cost of a fork?

**Active repo, non-trivial merge burden, no CVE-driven emergency patches in
the recent window.**

**Cadence** (from `CHANGELOG.md`, verified against
[releases](https://github.com/supabase/auth/releases)):

- v2.174.0 → v2.192.0 = **18 minor releases in ~13 months** (2025-05-23 →
  2026-06-29). Rough rate: **~1 minor/month**, accelerating in 2026 (6 minors
  in Feb–Jun 2026 alone). Automated release-please cadence.
- Three patch releases in the window (v2.176.1, v2.182.1, v2.188.1) — routine
  fixes, none security-driven.
- v2.192.0 includes [PR #2602](https://github.com/supabase/auth/pull/2602)
  excluding GO-2026-5004 (pgx/v4 not reachable) — routine `govulncheck` hygiene.

**Hook-payload code churn in the last six months** — the exact subsystem we'd
be patching — is meaningful:

- PR #2274 (`amr`), PR #2576 (`custom_claims_allowlist`), PR #1913 (open,
  claim requirements), PR #2012 (closed, before/after user hooks). Every
  one touches files we'd be patching (`internal/hooks/v0hooks/v0hooks.go` or
  its neighbours).

**Merge-burden estimate:** conflicts are near-certain on ~1 in 4 upstream
releases (12–15 per year), most trivially resolvable. Once per year expect a
harder conflict from a struct-shape change like PR #2274. Budget ~0.5–1 hour
of engineer time per upstream sync, ~1–2 days/year total.

**Test story:** hook-payload changes are exercised by
`internal/hooks/v0hooks/manager_test.go` (unit) and
`internal/api/e2e_test.go` (integration with pg-functions). Adding a field
is straightforward to test but the surface is real. Any patch should update
both.

**Container-build cost:** the fork must be rebuilt from source in Cloud Run's
Artifact Registry rather than pulled from `supabase/gotrue`. Adds one CI
pipeline; no per-request cost.

Verdict: forkable, but the ratchet is one-way — every month of divergence
costs a little more, and we cannot amortise it via upstream because upstream
does not want it.

---

## 6. Alternative in-band mechanisms

### 6a. `raw_app_meta_data.pending_grant_id`

**Sketch:** Exchange endpoint writes
`raw_app_meta_data.pending_grant_id = "<grant_id>"` via admin API immediately
before calling `verifyOtp`. Hook reads it, embeds it in claims, clears it in
the same transaction. Since `raw_app_meta_data` flows into
`claims.app_metadata` (see Q1), the hook already has read access at no extra
plumbing cost.

**Race analysis:**
- **Concurrent exchanges for the same user** overwrite each other. If flow A
  writes `grant_id=A` at t=0 and flow B writes `grant_id=B` at t=1 before A's
  `verifyOtp` fires, A gets B's grant baked into its token. Silent
  compromise of the least-privilege guarantee that motivates scoped sessions.
- **Concurrent exchanges for different users** are safe — the row key is
  `user.id`.
- **Interaction with normal auth**: any concurrent normal sign-in for the
  user during the write→verify window will read the stale grant_id from
  `raw_app_meta_data` and (unless the hook is defensive) mint a scoped
  token for a non-scoped grant. This is arguably worse than the
  cross-scope race.

**Severity for the four flows** in `design/scoped-sessions.md`:
- Slice 0 (single-user, single-device provisioning) — **P2**, race window is
  seconds and single-actor.
- Multi-agent/multi-device — **P0**, this is a designed-in silent auth
  vulnerability.

**Mitigations that get you back to safety** collapse into re-inventing
`scoped_grant_pending`: a per-write lock keyed on `user_id`, a "confirm
grant_id matches what I wrote" recheck, etc. None of these are simpler than
what we already have.

**Recommendation:** viable as a **fallback** if the workaround table becomes
operationally painful AND only Slice 0 ships. Not viable long-term.

### 6b. `session_bootstrap` table keyed on grant secret

**Sketch:** Instead of a user-id-keyed row we insert in the exchange endpoint,
use a row keyed on the grant secret (or a hash of it), and have the hook read
it. Requires the hook to know the grant secret somehow.

**Blocker:** the hook event doesn't carry any grant secret or anything derived
from one. The only per-request field is IP address (Q1). To key on anything
grant-specific we'd need to smuggle it via `raw_app_meta_data` — at which
point we're back to 6a's race.

Effectively equivalent to what we have. No improvement. **Don't pursue.**

### 6c. Ephemeral GoTrue user per session

**Sketch:** Mint a throwaway `auth.users` row for each scoped session; delete
after use. `raw_app_meta_data` on the throwaway row carries the grant_id
without race because no one else writes to it.

**Costs:**
- Audit / operational: `auth.users` table cardinality grows by
  N-scoped-sessions-per-user, then shrinks on deletion. Backup/restore
  storyline breaks — a point-in-time restore mid-session leaves orphaned
  users. `auth.audit_log_entries` inflates.
- Downstream `auth.users` FK ripple: any RLS policy or foreign key that joins
  on `auth.uid()` sees a user that is not the "real" identity. Every consumer
  needs to know about scoped vs primary identity.
- Delete-after-use failure mode: crash between session mint and delete leaves
  a permanent orphan.

**Verdict:** worse than the workaround. **Don't pursue.**

### 6d. Skip GoTrue entirely for scoped sessions (custom JWT signer)

**Sketch:** Exchange endpoint hand-mints JWTs signed with the same JWKS as
GoTrue and never calls GoTrue at all for narrow sessions.

**What breaks:**
- **`session_id` semantics** — `auth.sessions` doesn't know about these
  sessions. `auth.session_id()` in RLS policies returns null or "unknown."
- **Refresh tokens** — no refresh path. Every scoped session becomes a
  short-lived bearer with no rotation. Might be acceptable for exchange-style
  ephemeral grants; is not acceptable for long-lived scoped agents.
- **Revocation** — no admin path to invalidate. Rely on short TTL only.
- **Audit** — no `auth.audit_log_entries` for these sign-ins.
- **JWKS rotation coordination** — our signer and GoTrue's signer need to be
  the same key. If GoTrue is switched to KMS-backed keys (v2.191.0,
  [PR #2571](https://github.com/supabase/auth/pull/2571)), signing outside
  GoTrue becomes harder.

**Verdict:** viable **only** for narrow, ephemeral, one-shot grants that don't
need refresh. For the design's stated flows (background agents that hold
sessions for hours), this loses too much. **Don't pursue as primary.**

---

## Cost estimate — recommended path (c) stick with the workaround

- **Engineering time to keep the workaround:** effectively zero — it already
  ships with Slice 0.
- **Storage:** N rows in `scoped_grant_pending` where N = concurrent
  in-flight exchanges. Empirically < 100 rows outside a load spike. Delete
  on `verifyOtp` completion; add a TTL sweep for orphans (e.g. 5 min).
- **Latency:** one extra Postgres round-trip per exchange (insert + delete).
  Sub-millisecond.
- **GoTrue calls per exchange:** 2 (unavoidable — see Q4). We cannot collapse
  this without either a fork or admin session mint, neither of which is
  cheap.
- **Merge burden avoided by NOT forking:** ~1–2 engineer-days/year.

---

## What'd change in our repo

**Nothing.** The recommendation is to keep both "optionality seams" from
`design/scoped-sessions.md` untouched:

- Seam 1 (the `scoped_grant_pending` table): stays as-is. It is the
  workaround. Add a TODO comment marking that the seam exists specifically
  because of Q1's findings, with a link to this report.
- Seam 2 (`custom_access_token_hook`): stays as-is. It reads `grant_id` from
  the table keyed on `user_id` (or whatever key the exchange endpoint chose)
  and clears the row.

If the operational cost of the workaround changes materially — e.g. we hit
enough concurrent scoped-session mints for the table to become a hot spot,
or the delete-on-verify path develops a P1 bug — revisit and consider the
fork (option b) or the `raw_app_meta_data` alternative (option d, with
per-user serialization to close the race).

---

## Open questions

1. **Would the design accept a "single-flight per user" constraint on
   scoped-session exchanges?** If yes, alternative 6a
   (`raw_app_meta_data.pending_grant_id`) becomes race-safe by construction
   and the workaround table can be retired. Needs a human call on whether
   the four flows can tolerate serialization per user.
2. **Is there budget for a Cloud Run image built from a fork if the
   workaround later proves painful?** The fork itself is ~60–100 LOC (Q2) —
   the ongoing cost is CI + ~1–2 days/year of merge conflicts. A yes here
   preserves optionality.
3. **What did `@cstockton` mean by "first class support for a generic OIDC
   provider/relying party architecture"** in the PR #1993 close comment?
   That framing suggests upstream envisions a different pattern for our
   use case. Worth a follow-up read of any 2025–2026 OIDC-provider work in
   the repo before committing to the workaround long-term.
4. **Does the hosted-Supabase managed dashboard have a private path** that
   solves this? We're self-hosted so it doesn't matter for us, but if any
   Supabase-internal "impersonate" or "issue token for user_id" primitive
   surfaces publicly (e.g. via `supabase/supabase` #32603 or its successors),
   we'd want to switch to it. Currently the answer is "no such public path,"
   but that could change.
5. **Verbatim maintainer quotes** on session_context requests could not be
   retrieved for this report (issue_read and gh CLI both blocked/absent).
   Confidence in the "no upstream PR ever" reading is high (Q3, three
   closures) but not backed by a direct "we will never accept this" quote
   from `@kangmingtay` or `@J0`. A human should skim `@kangmingtay`'s
   recent PR reviews before spending engineering time on an upstream ask.
