-- Add token endpoint client authentication settings to custom_oauth_providers.
-- token_endpoint_auth_method: null keeps the historical behaviour (auto-detect
-- client_secret_basic, then client_secret_post). private_key_jwt (RFC 7523)
-- authenticates with a JWT signed by client_signing_key instead of a secret.
-- client_signing_key holds a PEM private key, encrypted at application level.
/* auth_migration: 20260923120000 */
alter table {{ index .Options "Namespace" }}.custom_oauth_providers
    add column if not exists token_endpoint_auth_method text null
        check (token_endpoint_auth_method in ('client_secret_basic', 'client_secret_post', 'private_key_jwt')),
    add column if not exists client_signing_key text null,
    add column if not exists client_signing_key_id text null;
