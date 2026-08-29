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

Pending. This section will be replaced with the actual `git ls-remote`, `gh run view`, `docker manifest inspect`, and release-verification workflow outputs after the tag has been published. Until then, 0.9.5 is not claimed as remotely verified.

## Upgrade and rollback

Upgrade from 0.9.4 by pulling `ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.5` after the remote evidence above is complete. Both version tags are expected to remain available. Exact rollback must use the immutable manifest digest recorded for the chosen release, not only a mutable version tag. The historical 0.9.4 digest and verification output remain in [RELEASE_0.9.4.md](RELEASE_0.9.4.md).
