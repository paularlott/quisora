# OpenID conformance harness

Runs the OpenID Foundation conformance suite against a local Quisora node. The latest results, the warnings that are
expected and why, and what was fixed because of the runs are in [docs/conformance.md](../docs/conformance.md).

| File | Purpose |
|---|---|
| `seed/` | Prepares a **stopped** node's store: the primary organization, an organization `acme` with the fake sign-in provider, the user it signs in (`user@acme.test`) and eight first-party confidential clients with Require PKCE off (two each of `client_secret_basic`, `client_secret_post` and `private_key_jwt` with a generated ES256 key, and two `client_secret_basic` with a back-channel logout URI for the back-channel plan), plus four with the FAPI 2.0 Security Profile for the FAPI plan (two with ES256 keys, two with PS256 keys; PKCE on, as the profile requires) and two more for its client credentials variant (SCIM provisioning on, `scim` scope only). Client ids, secrets and keys are generated, so it writes the suite configurations from the templates in `config/` into `.run/config/`, a super admin API token (admin scope) into `.run/admin-token`, and the super admin's sign-in (a generated password and authenticator secret) into `.run/admin-login.json`: `run-plan.py` signs in with it, as rotating signing keys takes a re-authenticated console session, not a token. |
| `fakeidp/` | A sign-in provider with no UI, over HTTPS with its own self-signed certificate (written to `.run/fakeidp.pem`; Quisora trusts it through `--extra-ca-file`). `/authorize` redirects straight back with a code; `/token` issues an ES256 ID token for `user@acme.test` with a verified address, which Quisora links to the seeded user. It also relays Quisora's back-channel logout posts to the suite's own self-signed endpoint. |
| `config/` | Suite configuration templates (`@CLIENT1_ID@` … filled in by `seed`): `basic.json`, `backchannel.json`, `post.json` (client_secret_post), `jwt.json` (private_key_jwt), and `fapi2.json` and `fapi2-ps256.json` (the FAPI 2.0 plan with ES256 or PS256 client keys; the protected resource is userinfo), and `fapi2-cc.json` (its client credentials variant; the protected resource is the `acme` organization's SCIM users). The browser steps click the provider button on `/o/<org>/login` (a plain link, so no JavaScript is needed) and the sign-out page's form button, and wait for the error, sign-in and signed-out pages the "review" steps screenshot. |
| `suite.patch` | One local change to the suite: it listens on port 8453 instead of 8443 (so it does not collide with `task run-server`). The tests themselves are unmodified; the seeded clients have Require PKCE turned off because the suite's OIDC client sends no PKCE. |
| `node.sh` | Starts, stops and seeds the node under test (`https://host.docker.internal:8090`) and the fake provider. State goes in `.run/` (ignored). |
| `run.sh`, `runall.sh` | Run one plan, or the four certification plans (config, basic, RP-initiated logout, back-channel logout). |
| `run-plan.py` | What `run.sh` runs: the suite's own `run-test-plan.py`, unmodified, with a real signing key rotation where `oidcc-server-rotate-keys` needs one (between the module's set-up and its start, which the runner alone cannot do). Before that module starts it waits until no other module of the plan is in flight, then signs in as the seeded super admin (password, then TOTP) and calls `POST /api/keys/rotate` with that session. The rotation is part of the plan run, so the plan's export has the module's real result. |
| `summ.py` | Each module's result from a run log, with the failure and warning messages, through the suite's API. |

Development machines only: the node listens on all interfaces with a self-signed certificate, the fake provider
signs anyone in, and client secrets end up in `.run/config`.

## Prerequisites

- Docker with Compose. The suite is a Java application built and run in containers (several GB).
- Python 3 for the suite's runner (`run-test-plan.py`).
- The suite's container reaches this machine as `host.docker.internal` (Docker Desktop; on Linux add
  `extra_hosts: ["host.docker.internal:host-gateway"]` to the suite's `server` service). The suite's own address,
  `localhost.emobix.co.uk`, is a public name that resolves to 127.0.0.1.

## Run

Build Quisora and the harness tools:

```bash
task build conformance-tools
```

Get the suite (once), apply the local changes, build it and start it:

```bash
git clone --depth 1 https://gitlab.com/openid/conformance-suite.git conformance/.run/suite
```

```bash
git -C conformance/.run/suite apply ../../suite.patch
```

```bash
cd conformance/.run/suite && mkdir -p ../m2 && MAVEN_CACHE=$PWD/../m2 docker compose -f builder-compose.yml run --rm builder && docker compose up -d
```

```bash
python3 -m venv conformance/.run/venv && conformance/.run/venv/bin/pip install -r conformance/.run/suite/scripts/requirements.txt
```

Start the fake provider, seed a fresh store and start the node:

```bash
conformance/node.sh idp-start && conformance/node.sh seed && conformance/node.sh start
```

Run the four plans and print one line per module (about two minutes):

```bash
conformance/runall.sh r1
```

The comprehensive plan with other client authentication methods (each run rotates Quisora's signing key once, for
`oidcc-server-rotate-keys`):

```bash
CONFIG=post.json conformance/run.sh "oidcc-test-plan[client_auth_type=client_secret_post][response_type=code][response_mode=default][client_registration=static_client]" comp-post
```

```bash
CONFIG=jwt.json conformance/run.sh "oidcc-test-plan[client_auth_type=private_key_jwt][response_type=code][response_mode=default][client_registration=static_client]" comp-jwt
```

The FAPI 2.0 Security Profile plan (private_key_jwt, DPoP), with ES256 and then PS256 client keys (about three
minutes each):

```bash
CONFIG=fapi2.json conformance/run.sh "fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]" fapi2
```

```bash
CONFIG=fapi2-ps256.json conformance/run.sh "fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]" fapi2-ps256
```

Its client credentials variant (no browser, about a minute):

```bash
CONFIG=fapi2-cc.json conformance/run.sh "fapi2-security-profile-final-test-plan[openid=plain_oauth][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=fapi_client_credentials_grant]" fapi2-cc
```

One module on its own: append `:<module>` to the plan, for example the key rotation module:

```bash
CONFIG=post.json conformance/run.sh "oidcc-test-plan[client_auth_type=client_secret_post][response_type=code][response_mode=default][client_registration=static_client]:oidcc-server-rotate-keys" rotate
```

The suite tests the `acme` organization's own issuer, `https://host.docker.internal:8090/o/<acme's id>` (its discovery
document, endpoints and sign-in pages are all under it); the configurations `seed` writes name it.

Details of a plan's modules: `python3 conformance/summ.py conformance/.run/logs/basic-r1.log`. The suite's UI at
https://localhost.emobix.co.uk:8453 shows each run, with the screenshots the "review" results wait on.

Stop everything:

```bash
conformance/node.sh stop && conformance/node.sh idp-stop && (cd conformance/.run/suite && docker compose down)
```
