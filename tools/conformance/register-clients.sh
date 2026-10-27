#!/usr/bin/env bash
# Registers the two conformance clients in the local development database (issue #20). There is no admin API yet
# (#32), so this writes the rows directly. The secrets go to .local/conformance/, never to the terminal.
#
# Usage: tools/conformance/register-clients.sh [with-backchannel|without-backchannel]
# The RP-initiated logout plan serves no back-channel endpoint, so run it "without-backchannel".
set -euo pipefail
mode="${1:-with-backchannel}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/.local/conformance"
mkdir -p "$out"
tenant="$(podman exec heimdall-postgres psql -U heimdall -d heimdall -tAc "select id from tenants where host = 'acme.localhost'")"
base="https://localhost.emobix.co.uk:8443/test/a/heimdall"
backchannel="'$base/backchannel_logout'"
[ "$mode" = "without-backchannel" ] && backchannel="NULL"

for n in 1 2; do
  if [ ! -f "$out/secret$n.txt" ]; then
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$out/secret$n.txt"
  fi
  hash="$(tr -d '\n' < "$out/secret$n.txt" | sha256sum | cut -d' ' -f1)"
  podman exec heimdall-postgres psql -U heimdall -d heimdall -v ON_ERROR_STOP=1 -q -c "
    SELECT set_config('app.tenant_id', '$tenant', false);
    INSERT INTO clients (id, tenant_id, client_id, name, type, token_endpoint_auth_method, allowed_grant_types, allowed_scopes,
                         redirect_uris, allowed_audiences, require_consent, status, created_at, require_dpop,
                         backchannel_logout_uri, post_logout_redirect_uris, resource_audiences, require_pushed_authorization_requests)
    VALUES (gen_random_uuid(), '$tenant', 'conformance-$n', 'OpenID conformance suite $n', 'confidential', 'client_secret_basic',
            ARRAY['authorization_code','refresh_token'], ARRAY['openid','profile','email','address','phone','offline_access'],
            ARRAY['$base/callback'], ARRAY[]::text[], false, 'active', now(), false,
            $backchannel, ARRAY['$base/post_logout_redirect'], ARRAY[]::text[], false)
    ON CONFLICT (tenant_id, client_id) DO UPDATE SET backchannel_logout_uri = EXCLUDED.backchannel_logout_uri;
    DELETE FROM client_secrets WHERE client_pk = (SELECT id FROM clients WHERE tenant_id = '$tenant' AND client_id = 'conformance-$n');
    INSERT INTO client_secrets (id, tenant_id, client_pk, secret_hash, created_at)
    SELECT gen_random_uuid(), '$tenant', id, decode('$hash', 'hex'), now() FROM clients WHERE tenant_id = '$tenant' AND client_id = 'conformance-$n';
    DELETE FROM backchannel_logouts WHERE tenant_id = '$tenant';" > /dev/null
done

# The plan configuration that run-plan.mjs reads. It holds the secrets, so it stays in .local/.
cat > "$out/config.json" <<JSON
{
  "alias": "heimdall",
  "description": "Heimdall local",
  "server": { "discoveryUrl": "https://acme.localhost:7200/.well-known/openid-configuration" },
  "client": { "client_id": "conformance-1", "client_secret": "$(cat "$out/secret1.txt")" },
  "client2": { "client_id": "conformance-2", "client_secret": "$(cat "$out/secret2.txt")" },
  "browser": []
}
JSON
echo "Registered conformance-1 and conformance-2 ($mode). Restart Heimdall: it caches clients."
