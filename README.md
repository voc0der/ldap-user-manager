# LDAP User Manager — hardened fork

A fork of **wheelybird/ldap-user-manager** with reverse‑proxy auth header support, **mTLS self‑serve certificate delivery**, **Apprise notifications**, a **host stager + tmpfs** for race‑free downloads via SWAG (nginx), and a **Lease IP** feature to temporarily allow client IPs in SWAG. Base features and most env vars remain compatible with upstream.

---

## What’s new in this fork

- **Reverse‑proxy auth headers (Authelia/SSO):** trusts `Remote-User`, `Remote-Email`, and `Remote-Groups` from your proxy. Sessions are bound to those headers.
- **mTLS self‑serve:** users in group **`mtls`** can request a one‑time email code, verify, and download their personal client certificate via a **single‑use, 5‑minute token**.
- **Race‑free delivery (SWAG + tmpfs):** PHP marks the token **used** then hands off to nginx (`X-Accel-Redirect`). A tiny **host stager** copies the correct `.pfx/.p12` into a per‑token directory on **tmpfs** that SWAG serves read‑only, then cleans up.
- **Apprise notifications:** code sent, token issued, and download events are pushed to your Apprise endpoint (e.g., Matrix) with tags.
- **Consistent mail “From” name:** mTLS emails use the same display style as the app (e.g., `BBQ User Manager <sysop@example.com>`).
- **Lease IP:** a small UI/API pair that lets users/admins add/remove client IPs to SWAG’s `ip-lease.conf` (with static entries, prune, etc.).
- **Hardening:** per‑user rate limiting, CSRF, session‑bound tokens, explicit permissions, and internal nginx delivery path.


TBD: OIDC
---

## Reverse‑proxy auth headers

Place an auth proxy (e.g., **Authelia**) in front of the app and inject these headers:

- `Remote-User` → username
- `Remote-Email` → email
- `Remote-Groups` → delimited list (`; ,` or whitespace). Users must have `mtls` to access the mTLS page.

The app trusts these headers and binds the session to them.

---

## mTLS self‑serve — how it works

1. **Send code** → user in group `mtls` requests an email OTP.
2. **Verify** → backend mints a **single‑use token** (5‑min TTL) and shows **Download**.
3. **Download** → PHP marks the token **used** and responds with `X-Accel-Redirect` to an **internal** path:  
   `/_protected_mtls/<token-hash>/client.p12`  
   SWAG serves the staged file from tmpfs.
4. **Host stager** (systemd) sees the token JSON and stages the user’s `.pfx/.p12` from the host cert store into tmpfs with SWAG’s uid/gid; a short **grace** keeps it long enough for nginx to serve, then removes it.

### Host paths (example)

- **Cert store (host):** `/docker_3000/certificates/bindable-internal/user_<uid>/user_<uid>.pfx`
- **Tmpfs stage (host):** `/docker_3000/mtls_stage` → mounted **read‑only** into SWAG at `/mtls_stage`
- **Token JSONs (host ⟷ app):**
  - `/docker_3000/appdata/ldap-user-manager/mtls-tokens` → `/opt/ldap_user_manager/data/mtls/tokens`
  - `/docker_3000/appdata/ldap-user-manager/mtls-codes`  → `/opt/ldap_user_manager/data/mtls/codes`
  - `/docker_3000/appdata/ldap-user-manager/mtls-logs`   → `/opt/ldap_user_manager/data/mtls/logs`

### SWAG (nginx) config

```nginx
# inside SWAG (nginx)
# tmpfs is bind-mounted read-only to /mtls_stage
location /_protected_mtls/ {
    internal;
    alias /mtls_stage/;  # serves /_protected_mtls/<token-hash>/client.p12
}
```

### Expiry display (best‑effort)

If present, the app will try to compute days until expiry from either:

- `MTLS_CERT_BASE/<uid>/client.crt` (PEM) **or**
- `MTLS_CERT_BASE/<uid>/client.p12` (requires `MTLS_P12_PASS`).

This is purely informational; **downloads always come from SWAG’s tmpfs** stage, not from `MTLS_CERT_BASE`.

---

## Apprise notifications

Set your Apprise endpoint and (optionally) a tag. Events sent:

- **🔑 mTLS Code Sent**
- **🪪 mTLS Token Issued**
- **📥 mTLS Certificate Downloaded**

**Env (LUM container):**

- `APPRISE_URL` — e.g. `https://notify.example.com/notify/apprise`
- `APPRISE_TAG` — e.g. `matrix_group_system_alerts` (optional)

**Test from inside container:**

```bash
curl -s -X POST \
  -F 'body=🧪 <b>mTLS Test</b>: hello from ldap-user-manager' \
  -F 'tag=matrix_group_system_alerts' \
  "$APPRISE_URL"
```

---

## Lease IP (SWAG + LUM)

A tiny UI inside **ldap-user-manager** that lets users temporarily “lease” their current IP into SWAG’s nginx `ip-lease.conf`. SWAG’s auto‑reload picks up changes immediately—useful for low‑traffic admin access without over‑engineering.

### How it works

- **File (SWAG‑owned):** `/config/nginx/http.d/ip-lease.conf`
- **Entry format:**
  ```nginx
  # LUM alice
  # 2025-09-30 11:26:00
  # static: yes      # optional; prune skips when present
  allow 203.0.113.7;
  ```
- **Flow:** LUM UI → LUM proxy (`/lease_ip/api.php`) → SWAG endpoint (`/endpoints/ip_lease.php`)

  LUM sets headers:
  - `X-IP-Lease-Label: LUM <username>`
  - `X-IP-Lease-Static: yes|no` (only when admin toggles “Static”)

SWAG writes the file **atomically**; its auto‑reload handles the rest.

### User experience

- **Users:** Add my IP / Remove my IP
- **Admins:** List leases; manual add; set/unset Static; delete; Clear all; Prune older than *N* hours (Static entries are skipped).

### SWAG endpoint contract (strict)

Send exactly **one** GET parameter per request:

- `?list=1`
- `?clear=1`
- `?add=IP`
- `?delete=IP`
- `?prune=HOURS`

Optional headers:

- `X-IP-Lease-Label: <string>`
- `X-IP-Lease-Static: yes|no`

**Examples**

```bash
# List
curl "https://swag.example.com/endpoints/ip_lease.php?list=1"

# Add (static)
curl -H "X-IP-Lease-Label: LUM alice" \
     -H "X-IP-Lease-Static: yes" \
     "https://swag.example.com/endpoints/ip_lease.php?add=203.0.113.7"

# Toggle static on existing
curl -H "X-IP-Lease-Label: LUM alice" \
     -H "X-IP-Lease-Static: no" \
     "https://swag.example.com/endpoints/ip_lease.php?add=203.0.113.7"

# Delete
curl "https://swag.example.com/endpoints/ip_lease.php?delete=203.0.113.7"

# Prune entries older than 24h (static entries are skipped)
curl "https://swag.example.com/endpoints/ip_lease.php?prune=24"

# Clear all
curl "https://swag.example.com/endpoints/ip_lease.php?clear=1"
```

### Nginx integration

Add the lease file where it matters (e.g., a protected `location`/server):

```nginx
# additional allow-list (combine with your existing mTLS/auth logic)
include /config/nginx/http.d/ip-lease.conf;
```

### LUM environment variables (Lease IP)

- `LEASE_API_BASE` — path or URL to SWAG endpoint (`/endpoints/ip_lease.php`)
- `LEASE_API_ORIGIN` — origin to force when `LEASE_API_BASE` is a path (e.g., `https://swag.example.com`)
- `EMAIL_DOMAIN` / `DOMAIN_NAME` — for building Matrix/Apprise URL when `APPRISE_URL` is not set
- `APPRISE_URL`, `APPRISE_TAG` — optional overrides for notifications

### Security notes (Lease IP)

- SWAG endpoint owns the file; LUM only calls the endpoint.
- LUM proxy enforces: authenticated users; non‑admins can only add/remove **their own** detected IP; admin‑only actions for list/clear/prune/manual add/static toggle.
- All writes are **atomic**; Static entries are **skipped by prune** but deletable.

---

## Volumes & permissions (containers)

Bind just the three mTLS subdirs to avoid exposing unrelated state:

```yaml
# ldap-user-manager container
volumes:
  - /docker_3000/appdata/ldap-user-manager/mtls-tokens:/opt/ldap_user_manager/data/mtls/tokens
  - /docker_3000/appdata/ldap-user-manager/mtls-codes:/opt/ldap_user_manager/data/mtls/codes
  - /docker_3000/appdata/ldap-user-manager/mtls-logs:/opt/ldap_user_manager/data/mtls/logs
```

Ensure those host dirs are **writable by the LUM container’s runtime uid:gid** (e.g., `300027:1337`). Avoid `0777`; use `0775` on dirs. Files are created with strict modes by the app.

**SWAG** must mount tmpfs read‑only:

```yaml
# swag (nginx) container
volumes:
  - /docker_3000/mtls_stage:/mtls_stage:ro
```

---

## Host tmpfs & stager

**tmpfs (host `/etc/fstab`):**

```
tmpfs /docker_3000/mtls_stage tmpfs rw,nosuid,nodev,noexec,relatime,size=64m,mode=0750,uid=<SWAG_UID>,gid=<SWAG_GID> 0 0
```

**Stager script (host):** `mtls_stager.py`

- Watches `/docker_3000/appdata/ldap-user-manager/mtls-tokens/*.json`
- Stages `/docker_3000/certificates/bindable-internal/user_<uid>/user_<uid>.pfx`
  → `/docker_3000/mtls_stage/<token-hash>/client.p12` (mode `0400`, owner = SWAG uid/gid)
- Cleans used/expired after a small **grace**

**systemd units (host):**

- `mtls-stager.path` — inotify trigger on token dir
- `mtls-stager.timer` — periodic sweep (e.g., every 5s)
- `mtls-stager.service` — runs the script

---

## Environment variables (summary)

**General**

- `REMOTE_HTTP_HEADERS_LOGIN=true` — rely on proxy headers
- `SITE_NAME`, `ORGANISATION_NAME` — used to render “From” name in emails
- SMTP: `SMTP_HOSTNAME`, `SMTP_HOST_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD[_FILE]`, `SMTP_USE_TLS`, `EMAIL_FROM_ADDRESS`, etc.

**mTLS**

- `MTLS_P12_PASS` — needed only to parse `.p12` to show expiry days
- `MTLS_CERT_BASE` — optional read‑path for expiry display (PEM/PKCS12)
- (Download always comes from SWAG tmpfs staging, not here.)

**Apprise**

- `APPRISE_URL` — e.g. `https://notify.example.com/notify/apprise`
- `APPRISE_TAG` — e.g. `matrix_group_system_alerts`

**Lease IP**

- `LEASE_API_BASE`, `LEASE_API_ORIGIN`
- `EMAIL_DOMAIN` / `DOMAIN_NAME` or `APPRISE_URL`, `APPRISE_TAG`

---

## Security notes

- OTP **rate-limit**: 3 sends/hour/user (sliding window)
- **CSRF** on API posts; **session‑bound** tokens
- Single‑use tokens (5‑min TTL); token marked **used** before nginx handoff
- SWAG serves from **tmpfs (RO)** with `internal` location
- Stager keeps a short **grace** to tolerate client/proxy timing, then deletes

---

## Troubleshooting

- **HTML 404 instead of `.p12`** → SWAG couldn’t see `/mtls_stage/<hash>/client.p12` yet. Ensure stager is running, tmpfs is mounted/owned by SWAG uid/gid, and give the UI’s 1‑second guard a moment.
- **“Certificate not found for user”** → no `user_<uid>/user_<uid>.pfx` in host store, or username mapping mismatch.
- **“Too many code requests”** → wait for the 3/hour/user window or clear rate file in `mtls-logs`.
- **No Apprise notifications** → test with the curl snippet above from inside the container.

---

## Quick setup checklist

1. Put auth proxy (Authelia) in front; inject `Remote-User/Email/Groups`.
2. Mount mTLS subdirs (tokens/codes/logs) into the LUM container with correct uid:gid.
3. Create host **tmpfs** at `/docker_3000/mtls_stage` owned by SWAG’s uid:gid; mount it **read‑only** in SWAG as `/mtls_stage`.
4. Add SWAG nginx `location /_protected_mtls/ { internal; alias /mtls_stage/; }`.
5. Install stager + systemd units on host; enable the path unit and timer.
6. Set `APPRISE_URL` (and `APPRISE_TAG`) for notifications; test via curl.
7. (Optional) Set `MTLS_CERT_BASE` / `MTLS_P12_PASS` for expiry display.
8. (Optional) Deploy Lease IP endpoint in SWAG, set `LEASE_API_BASE` in LUM, and include `/config/nginx/http.d/ip-lease.conf` where needed.

---

## Credits

Based on **wheelybird/ldap-user-manager**. This fork adds SSO header support, mTLS self‑serve with SWAG tmpfs staging, Apprise notifications, Lease IP, and security hardening.
