#!/usr/bin/env bash
# Registers the two conformance clients in the local development database (issue #20). There is no admin API yet
# (#32), so this writes the rows directly. The secrets go to .local/conformance/, never to the terminal.
#
# Usage: tools/conformance/register-clients.sh [with-backchannel|without-backchannel|private-key-jwt]
# The RP-initiated logout plan serves no back-channel endpoint, so run it "without-backchannel".
# "private-key-jwt" first registers the clients with back-channel logout, then moves both to private_key_jwt (D45)
# with one new ES256 key. The private key goes to .local/conformance/config-pkjwt.json for the suite only.
set -euo pipefail
mode="${1:-with-backchannel}"
keys="no"
if [ "$mode" = "private-key-jwt" ]; then mode="with-backchannel"; keys="yes"; fi
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
    ON CONFLICT (tenant_id, client_id) DO UPDATE SET backchannel_logout_uri = EXCLUDED.backchannel_logout_uri,
      token_endpoint_auth_method = 'client_secret_basic', jwks = NULL;
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

if [ "$keys" = "yes" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$out/pkjwt.pem"
  python3 - "$out" <<'PY'
import base64, json, subprocess, sys
out = sys.argv[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
der = subprocess.run(["openssl", "ec", "-in", f"{out}/pkjwt.pem", "-outform", "DER"], capture_output=True, check=True).stdout
d = der[der.index(b"\x04\x20") + 2:][:32]
point = der[der.rindex(b"\x03\x42\x00\x04") + 4:]
public = {"kty": "EC", "crv": "P-256", "kid": "conformance-1", "use": "sig", "alg": "ES256", "x": b64(point[:32]), "y": b64(point[32:64])}
json.dump({"keys": [public]}, open(f"{out}/pkjwt-public.json", "w"))
config = json.load(open(f"{out}/config.json"))
private = {"keys": [dict(public, d=b64(d))]}
config["client"] = {"client_id": "conformance-1", "jwks": private}
config["client2"] = {"client_id": "conformance-2", "jwks": private}
json.dump(config, open(f"{out}/config-pkjwt.json", "w"))
PY
  jwks="$(cat "$out/pkjwt-public.json")"
  podman exec heimdall-postgres psql -U heimdall -d heimdall -v ON_ERROR_STOP=1 -q -c "
    SELECT set_config('app.tenant_id', '$tenant', false);
    UPDATE clients SET token_endpoint_auth_method = 'private_key_jwt', jwks = '$jwks'
    WHERE tenant_id = '$tenant' AND client_id IN ('conformance-1', 'conformance-2');" > /dev/null
  echo "Moved both clients to private_key_jwt. The suite config is $out/config-pkjwt.json."
fi
