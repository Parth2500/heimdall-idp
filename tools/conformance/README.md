# OpenID conformance suite (local)

These files run the OpenID Foundation conformance suite against a local Heimdall (issue #20). The results are in [docs/conformance.md](../../docs/conformance.md).

The suite runs locally, because the hosted suite cannot reach a development server. Heimdall requires PKCE `S256` from every client (D2). The suite's OpenID Connect modules send no PKCE, so this setup patches the suite to send it. Because of the patch, a result here is not an official OpenID certification.

## Files

| File | Purpose |
|---|---|
| `heimdall-pkce.patch` | Adds PKCE `S256` to every authorization request of the suite's OpenID Connect server modules. |
| `compose.override.yml` | Runs the patched suite image, maps `acme.localhost` to the host, and gives nginx a certificate for its host name. |
| `register-clients.sh` | Registers `conformance-1` and `conformance-2` in the development database. It writes the secrets and the plan configuration to `.local/conformance/`. |
| `run-plan.mjs` | Runs one plan. Playwright plays the user: it signs in, allows consent, confirms a sign-out, and uploads a screenshot for a review step. |

## Steps

All paths are relative to the repository root. Podman runs rootless (see the README).

1. Clone the suite at the tested commit, apply the patch, and build it:
```
git clone https://gitlab.com/openid/conformance-suite.git .local/conformance-suite
cd .local/conformance-suite
git checkout 23353b36957d6466010de767c812d2c91ed37638
git apply ../../tools/conformance/heimdall-pkce.patch
podman run --rm -v ../m2:/root/.m2:Z -v .:/usr/src/mymaven:Z -w /usr/src/mymaven docker.io/library/maven:3-eclipse-temurin-21 mvn -B -q clean package -DskipTests=true
sed 's|^FROM eclipse-temurin:21|FROM docker.io/library/eclipse-temurin:21|' Dockerfile > Dockerfile.local
podman build -f Dockerfile.local -t localhost/conformance-suite-heimdall:pkce .
```
2. Make a certificate for the suite's host name, and a trust bundle for Heimdall:
```
mkdir -p .local/conformance && cd .local/conformance
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout suite.key -out suite.crt -subj "/CN=localhost.emobix.co.uk" -addext "subjectAltName=DNS:localhost.emobix.co.uk"
cat /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem suite.crt > bundle.crt
```
3. Start the suite (`https://localhost.emobix.co.uk:8443`; the public DNS name resolves to `127.0.0.1`):
```
cd .local/conformance-suite
podman compose -f docker-compose-prebuilt.yml -f ../../tools/conformance/compose.override.yml up -d
```
4. Register the clients, then start Heimdall on all interfaces, trusting the suite's certificate. The `SSL_CERT_FILE` bundle keeps every TLS check on. The suite signs in many times from one address, so raise the login rate limit for this local run only (the default is 5 each minute for each IP):
```
tools/conformance/register-clients.sh with-backchannel
SSL_CERT_FILE=.local/conformance/bundle.crt Heimdall__RateLimits__Login__PermitLimit=1000 dotnet run --project src/Heimdall.Api --launch-profile https -- --urls "https://0.0.0.0:7200"
```
5. Run a plan. The user must exist in the tenant:
```
cd tools/conformance && npm install --ignore-scripts
export HEIMDALL_CONFORMANCE_EMAIL=... HEIMDALL_CONFORMANCE_PASSWORD=... NODE_EXTRA_CA_CERTS=../../.local/conformance/suite.crt
# Optional: a Chromium that is already installed, when the Playwright version wants another browser build.
export CHROMIUM_PATH=~/.cache/ms-playwright/chromium_headless_shell-<build>/chrome-headless-shell-linux64/chrome-headless-shell
node run-plan.mjs oidcc-basic-certification-test-plan '{"server_metadata":"discovery","client_registration":"static_client"}' ../../.local/conformance/config.json
node run-plan.mjs oidcc-config-certification-test-plan '{}' ../../.local/conformance/config.json
node run-plan.mjs oidcc-backchannel-rp-initiated-logout-certification-test-plan '{"client_registration":"static_client","response_type":"code"}' ../../.local/conformance/config.json
```
The RP-initiated logout plan serves no back-channel endpoint. Run `register-clients.sh without-backchannel` and restart Heimdall first:
```
node run-plan.mjs oidcc-rp-initiated-logout-certification-test-plan '{"client_registration":"static_client","response_type":"code"}' ../../.local/conformance/config.json
```

Each run writes `results-<plan>.json`. A module in `REVIEW` waits for a person to check its screenshot in the suite's web page.
