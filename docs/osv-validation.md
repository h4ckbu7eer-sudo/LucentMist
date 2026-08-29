# OSV Query Validation

Validated on 2026-08-30 for the post-0.9.4 development branch.

## Decision

LucentMist does not send a service banner version as a Debian package version or as a
synthetic `GIT` package/tag query. A normal banner such as `OpenSSH_9.8p1` lacks both a
distribution package coordinate and a Git commit, so OSV is skipped and no OSV
`versionStatus=verified` claim is produced.

OSV is queried only when the collected evidence explicitly contains a 40-character
Git commit. The request then uses the documented top-level shape:

```json
{"commit":"6879efc2c1596d11a6a6ad296f80063b558d5e0f"}
```

## Why the tag query was removed

Two OSV-owned sources conflict:

- The current [POST `/v1/query` documentation](https://google.github.io/osv.dev/post-v1-query/)
  shows an uppercase `GIT` ecosystem with a repository URL and tag in `version`.
- OSV maintainers state in [discussion 2040](https://github.com/google/osv.dev/discussions/2040)
  that `GIT` is a synthetic ecosystem, package/tag queries return
  `{"code":3,"message":"Invalid ecosystem."}`, and the supported workflow is a
  top-level commit query. [Issue 2576](https://github.com/google/osv.dev/issues/2576)
  records the same deployed-API behavior.

Because a security result must not depend on an unresolved documentation/deployment
contradiction, LucentMist uses only the commit contract that both the API documentation
and maintainers identify as supported.

## Live-query attempts

No successful local OSV response is claimed. Three independent attempts failed before
an HTTP response was received:

1. Windows PowerShell/curl failed during Schannel credential acquisition
   (`SEC_E_NO_CREDENTIALS`).
2. WSL curl timed out connecting to `api.osv.dev:443` after 30 seconds.
3. A fresh `curlimages/curl:8.10.1` container could not connect to port 443; the
   in-app browser network path returned `ERR_BLOCKED_BY_CLIENT`.

These are local network/TLS limitations, not evidence of a particular OSV response.
The regression tests therefore verify two honest invariants without fabricating a
positive hit: banner-only input makes no HTTP call, and explicit commit evidence emits
only the official top-level `commit` request shape. A real OSV integration test remains
environment-dependent and must not be reported as passed until the API is reachable.
