# Handover: scoped sessions via one-time-token URL + custom OIDC provider

> Fresh-agent brief. You have no context from the conversation that produced
> this. Read `design/scoped-sessions.md` and
> `design/scoped-sessions-gotrue-patch-feasibility-report.md` first — this
> document builds directly on them. Your job is to design and implement a
> production-quality replacement for the `scoped_grant_pending` workaround
> using a mechanism GoTrue already supports (server-to-server ID token grant
> with a custom OIDC provider). Written on branch
> `claude/gotrue-scoped-sessions-research-br43vc` in `axelv/auth`; copy this
> file into the integration repo's `design/` directory when you file the
> matching PRD.

## What you're building

A **one-time-token URL** — e.g. `https://exchange.tiro.health/redeem?otp=<opaque>`
— that a caller (internal service, email link, QR code, whatever the flow
requires) presents to redeem for a **scoped Supabase session**. The session's
access token carries custom claims (`grant_id`, `scope`, and a synthetic
`role`) that scope its authority.

The user identity behind the session must already exist in `auth.users` — this
is a delegation primitive, not a signup path.

At a high level: your exchange service issues a signed OIDC ID token per
redemption, POSTs it to GoTrue's `id_token` grant, GoTrue mints a session,
and the access-token hook promotes the allowlisted claims into the JWT.

## Why this shape (context you shouldn't re-derive)

- **Not a GoTrue fork.** See the feasibility report — three prior upstream
  asks for per-request hook context were declined. We're not going to be the
  fourth. The design must live entirely in our services + configuration.
- **Not the `scoped_grant_pending` workaround.** That table shipped as Slice 0
  and works, but it costs one extra Postgres round-trip per exchange and
  couples the exchange endpoint to a table the hook reads out-of-band. This
  design retires it.
- **Not a full OIDC IdP.** GoTrue accepts a pre-signed ID token via
  `POST /token?grant_type=id_token` — no browser, no `/authorize` redirect,
  no `/token` endpoint on our side. We only need to be a valid *issuer*: a
  discovery document, a JWKS, and a signing key.

Relevant GoTrue code:

- `internal/api/custom_oauth_admin.go:139` — `adminCustomOAuthProviderCreate`,
  the endpoint we register with once.
- `internal/api/token_oidc.go:126-161` — the `custom:` branch of the id_token
  grant. This is the path our token takes.
- `internal/api/token_oidc.go:254` — signature verification against the
  provider's JWKS (fetched via discovery, cached in `a.oidcCache`).
- `internal/api/token_oidc.go:278-292` — audience check. `aud` in the ID
  token must include the provider's `client_id`.
- `internal/api/provider/oidc.go:354` — claim parsing; where
  `custom_claims_allowlist` is applied (verify this end-to-end — see Open
  questions).
- `internal/tokens/service.go:657-746` — session issuance and hook fire.

## Architecture

Three components, all under our control:

1. **OTP store.** A Postgres table keyed on `otp_hash`, holding
   `(user_id, grant_id, scope, expires_at, consumed_at)`. Owned by the
   exchange service.
2. **Exchange service** (`exchange.tiro.health`, single Cloud Run service).
   Doubles as the OIDC issuer:
   - `GET /.well-known/openid-configuration` — static-ish JSON.
   - `GET /.well-known/jwks.json` — public half of the ID-token signing key.
   - `POST /grant` (or similar) — issue an OTP for a `(user_id, grant_id,
     scope)` triple; called by internal services with a service-role bearer.
   - `POST /redeem?otp=…` — the one that runs on OTP redemption. Validates,
     mints ID token, calls GoTrue, returns session.
3. **GoTrue** — self-hosted, unmodified. Configured once (in Terraform,
   via a bootstrap script that calls `POST /admin/oauth/providers`) to know
   about our issuer.

The private signing key lives in Google Secret Manager, injected at boot.
Rotation is a separate design concern (see Open questions).

## Flow, step by step

### Setup (once per environment)

1. **Generate an RS256 keypair.** Store the private key in Secret Manager
   (or the equivalent). Publish the public key as a JWK at
   `/.well-known/jwks.json`. Give the JWK a `kid`.
2. **Register the provider with GoTrue** via `POST /admin/oauth/providers`
   using the service-role key. Body shape (see
   `AdminCustomOAuthProviderParams` at `custom_oauth_admin.go:44`):
   ```json
   {
     "provider_type": "oidc",
     "identifier": "custom:tiro-scoped-exchange",
     "name": "Tiro Scoped Exchange",
     "issuer": "https://exchange.tiro.health",
     "client_id": "gotrue-scoped-client",
     "client_secret": "<32B random; ignored on id_token grant but required by schema>",
     "scopes": ["openid"],
     "custom_claims_allowlist": ["grant_id", "scope"],
     "skip_nonce_check": true,
     "email_optional": true,
     "attribute_mapping": { "provider_id": "sub" }
   }
   ```
   GoTrue fetches your discovery document at registration time and rejects
   the config if it's malformed (`custom_oauth_admin.go:217-223`). Fail-fast
   is on your side.
3. **Decide the identity-linkage strategy** (see Open questions). Two
   options:
   - **Pre-provision** an `auth.identities` row per user, with
     `provider="custom:tiro-scoped-exchange"` and `provider_id=<user_id>`.
     Then use `sub=user_id` in the ID token.
   - **Email match**: skip identities; include the user's email in the ID
     token; let GoTrue match on first use. Requires every scoped-session
     user to have a verified email.
4. **Update `custom_access_token_hook`** to promote the allowlisted claims:
   ```sql
   create or replace function public.custom_access_token_hook(event jsonb)
   returns jsonb language plpgsql as $$
   declare
     claims jsonb := event->'claims';
     custom jsonb := coalesce(claims->'user_metadata'->'custom_claims', '{}'::jsonb);
   begin
     if custom ? 'grant_id' then
       claims := claims || jsonb_build_object(
         'grant_id', custom->'grant_id',
         'scope',    custom->'scope',
         'role',     'scoped_agent'
       );
     end if;
     return jsonb_build_object('claims', claims);
   end $$;
   ```
   Follow the pattern in
   `supabase/migrations/20260708090000_mfa_has_verified_claim.sql` — a new
   migration that supersedes the previous version of the function, keeping
   the MFA-verified-claim extension intact.

### Runtime — issuing an OTP URL

Internal service calls `POST /grant` on the exchange service with
`{ user_id, grant_id, scope, ttl_seconds }`. The exchange service:

1. Generates a 32-byte random `otp` (base64url).
2. Hashes it: `otp_hash = sha256(otp)`.
3. `INSERT INTO scoped_grant (otp_hash, user_id, grant_id, scope, expires_at)
   VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))` — with a
   unique index on `otp_hash`.
4. Returns `https://exchange.tiro.health/redeem?otp=<otp>` to the caller.

Never store the raw OTP. Log only its hash prefix.

### Runtime — redeeming an OTP URL

`POST /redeem?otp=<otp>` (or GET, if the URL is meant to be visited by a
browser; see Non-goals). Steps:

1. **Consume atomically:**
   ```sql
   UPDATE scoped_grant
   SET consumed_at = now()
   WHERE otp_hash = sha256($1::bytea)
     AND consumed_at IS NULL
     AND expires_at > now()
   RETURNING user_id, grant_id, scope;
   ```
   Zero rows → 401. Exactly one row → proceed with the returned tuple.
2. **Mint the ID token.** Sign with the exchange service's private key:
   ```
   {
     "iss": "https://exchange.tiro.health",
     "aud": "gotrue-scoped-client",
     "sub": "<user_id>",
     "iat": <now>,
     "exp": <now + 60>,
     "grant_id": "<grant_id>",
     "scope": "<scope>"
   }
   ```
   Header: `{"alg": "RS256", "kid": "<key id>"}`. If using email-match
   identity, also include `"email": "<user email>"` and
   `"email_verified": true`.
3. **Exchange with GoTrue:**
   ```
   POST https://<gotrue>/token?grant_type=id_token
   Content-Type: application/json

   { "id_token": "<jwt>", "provider": "custom:tiro-scoped-exchange" }
   ```
4. **Return the response to the caller.** The response body is a normal
   `AccessTokenResponse` — `access_token`, `refresh_token`, `expires_in`,
   `user`. Either return it as JSON or redirect (browser flow) with the
   session in the URL fragment.

Failure modes to surface distinctly (each with its own HTTP status):

- OTP not found / consumed / expired → 401.
- Signing key unavailable → 503.
- GoTrue rejects the token → 502, log the GoTrue error body.
- User not found (identity linkage failed) → 500 in the pre-provision model
  (means we forgot to seed); a 401 in the email-match model.

## What to build — concrete list

Ordered so you can spike-verify before committing to the full build.

1. **Spike (do this first, ~2h).** Register a provider on a dev GoTrue,
   sign an ID token with `grant_id: "spike"` and `sub: "<real user id>"`,
   POST to `/token?grant_type=id_token`, inspect the resulting access
   token. Confirm `grant_id` lands in `user_metadata.custom_claims` and
   that the hook (with the SQL above) promotes it to a top-level claim.
   If this doesn't work, STOP and update the report — the assumption
   under this whole handover is wrong.
2. **OTP store migration.** `scoped_grant` table + unique index +
   `consumed_at`/`expires_at` sweep job (delete rows where
   `expires_at < now() - interval '1 day'`).
3. **Exchange service scaffolding.** Whatever language matches the existing
   scripts (Node/TypeScript looks likely from `scripts/unenroll-mfa.ts`) —
   a single-container Cloud Run service with three endpoints:
   `/grant`, `/redeem`, `/.well-known/*`. Auth on `/grant` is a service-role
   bearer.
4. **Signing key management.** Generate the RS256 keypair; publish JWK;
   inject private key from Secret Manager. Note: the exchange service's
   signing key is **different** from GoTrue's session-signing key. Don't
   confuse them.
5. **Provider registration bootstrap.** A `terraform apply`-time or
   deploy-time script that calls `POST /admin/oauth/providers` if the
   provider isn't already registered (idempotent — check first with
   `GET /admin/oauth/providers/custom:tiro-scoped-exchange`).
6. **Identity seeding.** If you chose pre-provisioning: a migration + a
   trigger on `auth.users` insert that creates the identity row.
7. **Hook migration.** Extend `custom_access_token_hook` as shown. Ship
   in the migration that removes `scoped_grant_pending` reads (do them in
   one PR — never leave the hook reading both mechanisms).
8. **Remove `scoped_grant_pending`.** Drop the table and its writes from
   the old exchange path in the same migration.
9. **End-to-end tests.** Cover happy path, expired OTP, consumed OTP,
   tampered OTP, wrong signature, refresh-token behavior (does the
   scoped session refresh cleanly? — see Open questions).

## Verify BEFORE committing

These are the load-bearing assumptions. If any fails, this design changes
shape.

1. **`custom_claims_allowlist` fires on the `id_token` grant path.**
   Verified statically only. `provider/oidc.go:354` parses claims via
   `token.Claims(&data.Metadata.CustomClaims)`, and the allowlist filter
   in `custom_oauth.go` should apply. Spike test (item 1 above) confirms
   or refutes.
2. **`email_optional: true` really lets GoTrue mint a session with no
   email claim.** Set on the provider (`custom_oauth_admin.go:60`); traced
   into `createAccountFromExternalIdentity` but not verified end-to-end.
   Same spike answers it.
3. **`client_id` need not match a real OAuth client.** For the `id_token`
   grant path, the `client_id` on the provider registration is only used
   to check the ID token's `aud` claim (`token_oidc.go:278-292`). No
   handshake with our /token endpoint happens. Confirm by inspecting the
   spike's GoTrue debug log.
4. **Signature verification uses your JWKS.** GoTrue's OIDC cache
   (`a.oidcCache`) fetches from `discovery.jwks_uri`. Verify it hits our
   `/.well-known/jwks.json` — check the exchange service's access log
   during the spike.

## Open questions

1. **Identity strategy: pre-provision or email-match?** Pre-provisioning
   is safer (grants can't work for a user we haven't authorized) but
   requires a migration + trigger, and every new user needs a row. Email
   match is simpler but couples every scoped session to email presence
   and correctness. Needs a human decision informed by whether all
   scoped-session users are guaranteed to have verified emails.
2. **Signing-key rotation cadence.** RSA-2048 with `kid` supports zero-
   downtime rotation: publish the new key in JWKS first, wait for
   GoTrue's OIDC cache TTL (need to find or measure this — the cache is
   at `internal/api/provider/oidc_cache.go`), then start signing with the
   new key. Retire the old key's JWK after another cache TTL. Automate or
   manual? For infra scale, quarterly manual is probably fine; document it.
3. **Refresh-token behavior for scoped sessions.** GoTrue's refresh path
   re-runs the access-token hook. Does it re-read `user_metadata.custom_claims`,
   or does it use the original claims from session creation? If it re-reads,
   the grant_id survives refresh naturally. If it uses cached session
   claims, we need to think about whether we WANT refresh (and if not,
   how to disable it for scoped sessions specifically). Trace
   `internal/api/token_refresh.go` end-to-end during the spike.
4. **Revocation.** Standard GoTrue admin `signOut` and refresh-token
   revocation apply. Is that enough? Do we need a separate "revoke this
   grant_id across all sessions" primitive? Depends on Slice 0-4 flows.
5. **Concurrency.** OTP consumption is atomic (SQL `UPDATE ... WHERE
   consumed_at IS NULL ... RETURNING`). Concurrent redemption attempts
   for the same OTP will see exactly one winner. But what about
   concurrent grants for the same `(user_id, grant_id)` — is that
   meaningful, or should the OTP store enforce a uniqueness constraint
   on `(user_id, grant_id)` too?
6. **Rate limiting.** GoTrue's built-in limiter
   (`internal/api/apilimiter`) is bypassed here because we're using
   service-role admin calls internally. What limits do we want on
   `/grant` and `/redeem` at the exchange service layer? Consider CVE
   scenarios: does a compromised issuer key let an attacker mint arbitrary
   grants for any user? (Yes. Protect the key accordingly.)

## Non-goals

- **Don't build `/authorize` or `/token` endpoints on the exchange service.**
  We only issue ID tokens, never redeem OAuth codes. The whole point of
  this design is that we skip the browser-based OAuth dance.
- **Don't stand up a full IdP framework** (ory/fosite, zitadel/oidc,
  etc.). Two static endpoints + a signing function is enough. If you
  find yourself wanting a framework, re-read the flow — you probably
  don't.
- **Don't try to make `scoped_grant_pending` and this new path
  coexist.** Fully replace, in a single PR that migrates the hook and
  drops the table.
- **Don't add MFA gating on the OTP redemption path.** The OTP itself is
  the auth factor; the user has already been verified by whatever issued
  it. If the design later needs MFA on top, that's a separate PRD.
- **Don't upstream anything.** The whole design lives outside GoTrue.
  This is by choice — see the feasibility report.

## Success criteria

- Redemption path: OTP → session in a single Cloud Run request, one
  GoTrue call, no side tables read by the hook.
- The access token has top-level `grant_id`, `scope`, and `role`
  claims — verified with `jwt.io` or equivalent.
- `scoped_grant_pending` table is gone. The old exchange endpoint code
  path is gone.
- All four flows from `design/scoped-sessions.md` (Slice 0 + follow-ups)
  work under the new mechanism.
- Refresh, revocation, and audit behave the same as any other GoTrue
  session, or the differences are explicitly documented.

## Budget

- Spike (verify assumptions): ~2 hours.
- If spike passes: full build + migration + tests ≈ 1–2 engineer-days.
- If spike surfaces an assumption failure: STOP and file findings; do
  not paper over. The design's whole value is that it's clean; a hacked
  version is worse than the current workaround.

## Starting points

Local (in-tree, this GoTrue fork — reference only; don't modify):

- `internal/api/token_oidc.go` — the id_token grant handler. Lines
  126-161 for the `custom:` branch.
- `internal/api/custom_oauth_admin.go` — provider CRUD. Lines 44-72 for
  the request schema, 139-249 for the create handler.
- `internal/api/provider/oidc.go` — claim parsing.
- `internal/api/provider/oidc_cache.go` — OIDC discovery cache.
- `migrations/20240427152123_add_one_time_tokens_table.up.sql` — pattern
  reference for the OTP table migration.

External:

- Sibling design doc: `design/scoped-sessions.md`.
- Feasibility context: `design/scoped-sessions-gotrue-patch-feasibility-report.md`
  (specifically Q4 and Q6d).
- GoTrue docs on custom OAuth: <https://supabase.com/docs/guides/auth/social-login>
  (patchy on server-to-server id_token; source is the truth).
- OIDC Discovery 1.0 spec: <https://openid.net/specs/openid-connect-discovery-1_0.html>
  (`/.well-known/openid-configuration` shape).
- JWKS spec: <https://datatracker.ietf.org/doc/html/rfc7517>.

Ping back with:
- The spike result (item 1 in "What to build").
- The identity-strategy decision.
- A one-paragraph go/no-go on the full build.
