# LucentMist 0.9.5 Release Notes

Release date: 2026-08-30

LucentMist 0.9.5 is a cumulative correctness and performance release after 0.9.4. Operators on 0.9.4 should upgrade to receive the OSV evidence correction, SSL and UDP result fixes, CVE version-status visibility, and bounded report/worker concurrency.

## User-facing changes

- **Honest CVE evidence:** OSV is queried only when input contains a real 40-character Git commit. A service banner such as OpenSSH `9.8p1` is not converted into a Debian package version or Git revision, and other external-source findings remain visibly version-unverified.
- **SSL correctness:** leaf and chain certificate times are evaluated in UTC. Reports expose trust-chain failures, hostname mismatch, and expired intermediate certificates instead of presenting every completed handshake as trusted.
- **UDP result honesty:** NTP and SSDP use protocol-valid probes. A response is `open`, an unreachable/refused socket error is inferred as `closed`, and silence is `open|filtered` rather than a false closed result.
- **CVE status in every output:** interactive CLI, HTML, Markdown, and CSV distinguish version-verified and version-unverified candidates.
- **Bounded report concurrency:** per-device report work is concurrent with a fixed upper bound, reducing multi-host report time without creating an unbounded number of connections.
- **Bounded scan-worker concurrency:** a slow range scan no longer monopolizes the only worker; concurrency remains capped to protect host and network resources.
- **Monitoring clarity:** task failure, monitoring failure, and monitoring timeout are separate user-visible states.

## Known limits

- Normal service banners do not contain an OSV-compatible package coordinate or Git commit. Banner-only OpenSSH observations therefore do not trigger OSV; this is an explicit evidence boundary, not an empty successful lookup.
- UDP `closed` is inferred from platform socket errors. A firewall-generated reset can still look closed; use a protocol-aware follow-up before treating it as absolute proof.
- If a platform exposes X.509 `NotAfter` as `DateTimeKind.Unspecified`, LucentMist interprets the wall-clock value in the scanner host's local time zone because the source time-zone ID is not recoverable. Keep the scanner clock and time zone correct.
- SMBv3.1.1 and representative OpenSSH versions were tested against real authorized services. SMBv1 positive detection still has simulator coverage rather than a real vulnerable target; CVE findings remain candidates unless stronger evidence is available.

## Deployment requirements

Do not expose an unconfigured deployment to the public Internet. Production deployments must explicitly set strong, shared values for:

```text
LMIST_API_TOKEN=<at least 32 random bytes>
LMIST_WEB_USER=<non-default administrator name>
LMIST_WEB_PASSWORD=<strong random password>
```

Automatically generated credentials are printed to logs and are only suitable for isolated local demonstrations. Store production secrets outside the repository, preferably in a secret manager.

## Local release gate

The following commands were run from a worktree that already contained one preserved, unrelated `tests/LucentMist.Tools.Tests/packages.lock.json` modification and untracked `.codex/` data. Neither is part of the release commit.

```text
dotnet build LucentMist.slnx -c Release --no-restore --verbosity minimal
Build succeeded. 0 Warning(s), 0 Error(s).

dotnet test LucentMist.slnx -c Release --no-build --no-restore --verbosity minimal
LucentMist.Scanning.Tests: 26 passed
LucentMist.API.Tests: 25 passed
LucentMist.Agent.Tests: 50 passed
LucentMist.Tools.Tests: 235 passed
Total: 336 passed, 0 failed, 0 skipped

dotnet format LucentMist.slnx --no-restore --verify-no-changes
exit code 0

docker compose config --quiet
exit code 0

git diff --check
exit code 0
```

The full 336-test command passed twice consecutively: once before the version change and once after it. These results are local evidence only. They do not establish that the tag was pushed, CI passed, or the GHCR artifact exists.

## Remote release evidence

The release commit and annotated tag are remotely visible:

```text
git ls-remote --tags origin 'v0.9.5' 'v0.9.5^{}'
52c1355a091acc96274e57c83bad830955a802f7  refs/tags/v0.9.5
9b67bdbeeba46f51d40a88a90f52f023c6472d2d  refs/tags/v0.9.5^{}
```

`gh run view 33277190463` independently reports the tag workflow as successful:

```text
✓ v0.9.5 CI · 33277190463
JOBS
✓ Build & Test (windows-latest) in 4m25s (ID 99165863954)
✓ Build & Test (ubuntu-latest) in 1m9s (ID 99165864003)
✓ Build & Push GHCR in 1m35s (ID 99166338839)
```

The full run is [GitHub Actions run 33277190463](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33277190463). GitHub emitted Node.js 20 deprecation annotations for current third-party action versions; these are maintenance warnings, not failed jobs.

Both versioned GHCR artifacts remain readable. `docker manifest inspect` returned schema-v2 manifests for both tags, and immutable-digest inspection returned:

```text
docker buildx imagetools inspect ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5
Name:      ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5
MediaType: application/vnd.docker.distribution.manifest.v2+json
Digest:    sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698

docker buildx imagetools inspect ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4
Name:      ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4
MediaType: application/vnd.docker.distribution.manifest.v2+json
Digest:    sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af
```

The 0.9.5 image config digest reported by `docker manifest inspect` is `sha256:1a02d5daca3b0819ad9970954e3f7d237d240ceb6bc42952d789d5596b1354dd`. The manifest digest above, not the config digest, is the immutable reference used for deployment verification.

The existing release-verification workflow was dispatched with the 0.9.5 tag and expected manifest digest. [Run 33277480928](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33277480928) completed every step in 19 seconds:

```text
✓ Log in to GHCR
✓ Pull published image
✓ Record immutable digest
✓ Start published API image
✓ Wait for health endpoint
✓ Show container logs
✓ Remove verification container

Pulled image: ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698
Health response: {"status":"healthy","version":"0.9.5","uptime":"0h 0m"}
```

This proves the published artifact can be pulled by immutable digest, starts successfully, and answers its API health endpoint with version 0.9.5. It does not by itself prove Web login, persistence, a full scan, or product demand.

## Upgrade and rollback

Upgrade from 0.9.4 by pulling `ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698`. Both version tags remain available. Exact rollback to 0.9.4 uses `ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af`; do not rely only on a mutable version tag. The historical verification output remains in [RELEASE_0.9.4.md](RELEASE_0.9.4.md).
