# mTLS Certificate module

This module adds a secure, single-use, short-lived download flow for per-user mTLS client certificates behind Authelia.

## Requirements

- Authelia in front of this path, providing headers:
  - `Remote-User` (uid), `Remote-Email` (optional), `Remote-Groups` containing `mtls`
- Nginx with `X-Accel-Redirect` mapping for an **internal** path.
- A per-user certificate artifact present on an internal filesystem (default: `/mnt/mtls-certs/<uid>/client.p12`).

## Environment variables

- `APPRISE_URL`   : Apprise endpoint (used via `curl -X POST --form-string 'body=...'`)
- `MTLS_MAIL_FROM`: From address for the email one-time code (PHP `mail()`)
- `MTLS_CERT_BASE`: Base directory for per-user certs (defaults to `/mnt/mtls-certs`)

## Nginx example

```
# Public app location (proxied to PHP app)
location /mtls_certificate/ {
    # ... your usual proxy_* and Authelia auth here ...
    proxy_set_header Remote-User   $upstream_http_remote_user;
    proxy_set_header Remote-Email  $upstream_http_remote_email;
    proxy_set_header Remote-Groups $upstream_http_remote_groups;
}

# Internal protected files (never directly exposed)
location /_protected_mtls/ {
    internal;
    # Map opaque to real path with alias/resolver or a Lua map.
    # Simple alias example (requires deterministic file names):
    # alias /mnt/mtls-certs/;
    # More secure approach: use a small Lua or subrequest to translate sha1 to path.
}
```

## Notes

- The email code is hashed (password_hash) and expires in 5 minutes.
- Download token is single-use, session-bound, and expires in 5 minutes.
- All user/path resolution is server-side based on the authenticated uid.
