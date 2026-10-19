# restic-pcloud-server

A small [restic](https://restic.net/) REST-protocol server backed by [pCloud](https://www.pcloud.com/)
via [rclone](https://rclone.org/), with **verify-after-write**: every object restic saves is
independently re-checked against what pCloud actually stored, and retried fresh (delete +
re-upload) on any mismatch, instead of trusting rclone/pCloud's own "success" response.

> **Why this exists:** pCloud's storage API has proven unreliable enough for large,
> automated uploads - reporting success on writes that then come back wrong-sized or
> missing - that backing up to it with restic wasn't trustworthy without something in
> between catching and correcting that. This project is that something.
>
> **On support:** this was built with AI assistance (Claude) to solve a personal backup
> problem, and is shared here as-is in case it's useful to someone else with the same one.
> It isn't actively maintained, and I won't be taking feature requests or providing support -
> see [Support](#support) below. Fork it and adapt it to your own needs.

## How the pieces fit together

restic normally talks straight to a storage backend (S3, a local path, SFTP...) and trusts
whatever that backend tells it. pCloud doesn't have a restic-native backend, so the usual
route is `restic` -> `rclone` (as an `rclone serve restic` bridge, or via `rclone mount`) ->
pCloud. That works, but in real-world use pCloud's API has been observed reporting a
successful upload for an object that then comes back wrong-sized or missing entirely on the
very next read - restic and rclone both assume a backend's "success" response is trustworthy,
so neither one catches this on its own.

This project replaces that bridge with its own small REST server, so the chain becomes:

```
restic  --(restic REST protocol, HTTP/S)-->  restic-pcloud-server  --(rclone)-->  pCloud
```

Every write from restic goes through this server, which writes it via `rclone`, then
independently re-reads pCloud's own listing to confirm both the byte count and the content
hash (which pCloud reports in its file metadata) actually match what was sent - and if
either doesn't, deletes the bad object and retries the write from scratch, up to a
configurable number of times, before ever telling restic the write succeeded. restic only
ever sees a clean success or a clean failure for each object; the retrying against pCloud's
flakiness is entirely this server's job, invisible to restic.

Concretely: you run this server once (as a Docker container, e.g. on a home server or NAS),
point it at an rclone config with your pCloud remote authenticated, and then point restic's
`RESTIC_REPOSITORY` at this server instead of at pCloud directly. `rclone` only needs to exist
where this server runs (it's bundled in the container) - the machine actually running
`restic backup` needs nothing but restic itself and network access to this server. Everything
below covers setting that up.

By default the server drives rclone as a single long-lived daemon (`-transport=rcd`): it
starts `rclone rcd` as a child process and talks to it over its RC API on a loopback address,
so the per-operation costs of the original design (one rclone process per object, each paying
config load, DNS resolution and TLS setup) are paid once. If the daemon dies, the server
exits with it, so a supervisor restarts the pair together. The RC API is unauthenticated, so
its address is loopback-only and never published. `-transport=exec` restores the original
one-process-per-operation behaviour as a fallback.

## 1. Setup

```bash
cp .env.example .env
```

Edit `.env`:
- `RCLONE_CONF_PATH` - path on the Docker host to an rclone config file with your pCloud
  remote already authenticated (`rclone config` if you haven't set one up yet).
- `PCLOUD_REMOTE_ROOT` - `remotename:path`, matching a `[remotename]` section in that
  rclone.conf, e.g. `pcloud:Backups/restic`. This is a fixed root the server never lets clients
  escape - each restic repo gets its own subfolder under it, named by the client via the
  repository URL (see below), not by anything set server-side.
- `AUTH_USER` / `AUTH_PASS` - pick a real username and a long random password. **Required**
  once this is reachable from anywhere other than a fully trusted private network - restic's
  REST protocol has no auth of its own, so without this, anyone who can reach the hostname can
  read, write, or delete the whole repository.
- `REPAIR_HOSTNAME`, `TRAEFIK_CERTRESOLVER`, `TRAEFIK_NETWORK` - only needed if you use the
  bundled Traefik labels in `docker-compose.yml` for TLS termination. If you front this with
  something else (nginx, Caddy, a cloud load balancer), delete the `labels:`/`networks:`
  sections and publish the port directly instead.

  You can also skip a reverse proxy entirely and reach the server directly over plain HTTP -
  useful on a trusted LAN, or just to get something working before adding TLS. In
  `docker-compose.yml`, drop the `labels:`/`networks:` blocks and add:
  ```yaml
  ports:
    - "8080:8080"
  ```
  Then point restic at `rest:http://user:pass@host:8080/reponame/` (`http`, not `https`).
  The tradeoff: HTTP Basic Auth sends `AUTH_USER`/`AUTH_PASS` in the clear, and restic's own
  metadata (though not your file contents, which restic encrypts client-side) travels
  unencrypted too. Fine on a network you trust; don't expose it to the internet like this.

Bring it up:

```bash
docker compose up -d --build
docker compose logs -f restic-pcloud-server   # confirm it started
```

You should see a line like:
```
restic-pcloud-server <version> listening on 0.0.0.0:8080, remote root pcloud:Backups/restic (max-retries=3, debug=false)
```

## 2. Run a backup through it

Each restic repo is a subfolder under `PCLOUD_REMOTE_ROOT`, picked by the trailing path
segment in `RESTIC_REPOSITORY` - not by anything set server-side. Use a distinct name per
machine or dataset, e.g. `laptop-documents`, `server-archive`.

From wherever restic runs (anywhere that can reach `REPAIR_HOSTNAME` over HTTPS):

```bash
export RESTIC_REPOSITORY="rest:https://${AUTH_USER}:${AUTH_PASS}@${REPAIR_HOSTNAME}/laptop-documents/"
export RESTIC_PASSWORD="pick-your-own-restic-encryption-password"   # different from AUTH_PASS - this one encrypts the repo, never sent to the server in the clear

restic init
restic backup /path/to/your/data
restic check --read-data
```

`restic check --read-data` is the important one - it's the only way to actually confirm nothing
came back corrupted, not just that the backup command exited 0. Run it periodically even after
initial setup; the per-write verify this server does catches wrong-size and content-mismatched
objects at write time, but nothing at write time can catch corruption that happens later, at
rest, which is what the periodic check is for.

## 3. Troubleshooting

At startup the server performs one real verified write of a small probe object against the
remote root and logs the result as a `PROBE` line: the hash algorithm verification will use and
the full set of hashes the remote reports for the object (sha256 in pCloud's EU region, sha1/md5
in the US). If verification cannot work (for example the remote reports no hashes while
`-require-hash=true`), the probe logs that as a warning instead of leaving it to the first
backup to discover; the probe object is deleted again immediately and the server starts either
way.

Routine successful saves are not logged individually - at repository scale that is one line per
object for no signal. What is logged: any save that needed a retry (including its eventual
verified OK), every verification mismatch or failure, successful deletes, and failed
authentication attempts.

Run with `-debug=true` (or `DEBUG=true` in `.env`) to log per-request timing, concurrency, and
every verify/retry decision to stdout:

```bash
docker compose logs restic-pcloud-server > server-debug.log
```

## Configuration flags

| Flag | Default | Meaning |
|---|---|---|
| `-remote-root` | `pcloud:Backups/restic` | fixed rclone `remote:path` root; each restic repo is a subfolder under this |
| `-rclone-config` | (required) | path to `rclone.conf` |
| `-transport` | `rcd` | how rclone is driven: `rcd` keeps one rclone daemon alive and uses its RC API; `exec` spawns one rclone process per operation |
| `-rc-addr` | `127.0.0.1:5572` | listen address of the rclone daemon when `-transport=rcd` (loopback only: the RC API is unauthenticated) |
| `-ca-cert` | (unset) | CA bundle for rclone's TLS verification, only needed in unusual environments |
| `-max-retries` | `3` | fresh re-upload retries after a failed verify (so the initial write plus this many retries is the total number of tries) |
| `-require-hash` | `true` | fail verification when pCloud reports no content hash for a saved object, leaving size as the only check; pCloud reports at least one of sha256/sha1/md5 in both regions, so turn this off only for a remote that cannot report hashes at all |
| `-listen` | `127.0.0.1:8080` | address to listen on |
| `-debug` | `false` | log per-request/per-stage timing and concurrency, not just errors |
| `-auth-user` / `-auth-pass` | (unset) | HTTP Basic Auth; set both to require it (or `RESTIC_PCLOUD_AUTH_USER`/`RESTIC_PCLOUD_AUTH_PASS` env vars) |
| `-version` | - | print the build version and exit |

## Notes

- Each restic repo lives at its own `<remote-root>/<repo-name>/` subfolder on pCloud - the
  server enforces this by construction (the repo-name segment can only ever be letters,
  digits, `-`, `_`), so one server instance can safely serve multiple independent repos.

## Support

This is shared as-is, no support provided and none implied - use it, fork it, modify it,
do whatever you want with it under the license below, but please don't open issues asking
for features or fixes. Pull requests that fix an actual bug are welcome, but there's no
commitment to review or merge them on any timeline.

## License

MIT - see [LICENSE](LICENSE). Provided as-is, with no warranty (see the license text for the
full legal wording).
