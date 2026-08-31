# Known Issues

Current status as of the verified 0.9.5 release.

## Release Status

- The local 0.9.5 release gate passed with 336/336 tests, a Release build with zero warnings and zero errors, formatting verification, Compose configuration validation, and `git diff --check`.
- The [v0.9.5 tag workflow](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33277190463) completed Windows, Ubuntu, and GHCR jobs successfully. The GHCR manifest digest is `sha256:48271745e38a425340004bf5852e84f8fc08e2cc03a7795d5bf4feb89c9bb698`.
- Independent [release verification run 33277480928](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33277480928) matched that digest, started the published API image, and received `{"status":"healthy","version":"0.9.5","uptime":"0h 0m"}`.
- 0.9.5 adds the OSV evidence boundary, visible CVE version status, SSL/UDP correctness fixes, and bounded report/worker concurrency. 0.9.4 operators should upgrade.

### Historical 0.9.4 evidence

- `v0.9.4` is published from commit `d56e4f0e`. Its [tag workflow](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244573226) completed Windows, Ubuntu, and GHCR jobs successfully.
- `ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4` has a readable Docker manifest; the inspected image config digest is `sha256:66397206f4c24956b4b1b9278e379032fb90b6361d944a5e39e421f5a1d93278`.
- The image manifest digest is `sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af`. Independent [release verification run 33257054498](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33257054498) pulled that exact digest from GHCR, started the published API image, and received `{"status":"healthy","version":"0.9.4","uptime":"0h 0m"}`.
- The first simultaneous main workflow exposed a timer-sensitive Windows test. The assertion guard was fixed without changing the production monitoring timeout, and the follow-up [main workflow](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244948229) completed all three jobs successfully.

## Product Limitations

- Current main validation and exact matching/source boundaries are recorded in
  [agent-real-validation.md](agent-real-validation.md) and [cve-matching-sources.md](cve-matching-sources.md).
  Real DeepSeek CLI, redirected-input REPL and browser Web dialogues were exercised on 2026-08-31.
  Raw contract compliance was 73/74 overall, and 54/54 after JSON mode; this is not semantic accuracy.
  Final CLI/Web runs included DNS/TLS evidence and all discovered 53/80/443 ports, with bounded correction of premature or contradictory conclusions.
  Web verification used isolated loopback ports 15050/15051 because user processes occupied 5050/5051; it does not validate the existing hosts or a newly published image.
  Models can still infer unsupported device purpose or call a vendor-issued certificate self-signed. Check raw certificate/scan evidence; the Agent remains experimental.
  DNS probes can disagree, and no public reachability or unrestricted recursive-resolver claim was verified.
  The earlier Hourly Self-Check failed a live Baidu certificate SAN assertion. The eight external SSL tests have now been replaced by generated loopback certificates; main CI and hourly both run the full suite without an External filter.
  SAN values are parsed from DER rather than localized OS display text. See [testing-strategy.md](testing-strategy.md) for coverage limits and [final-validation-and-push.md](final-validation-and-push.md) for final-commit revalidation and current push evidence.
  Protocol-only cloud candidates are shown separately and do not count as target vulnerabilities.
  Offline rules now total 18; MySQL/MongoDB unauthenticated data access checks are still not implemented.

- Current main defaults to free cloud CVE lookups; set `LMIST_CVE_EXTERNAL=false` for offline use.
  Only normalized service keywords/product CPEs (or explicit OSV commits) leave the scanner, not target IPs/raw banners.
  Providers see the request's egress IP. Shodan CVEDB is free for **non-commercial** use, not unrestricted commercial use.
  Source timeouts, HTTP failures and local NVD throttling are reported; capped responses are not an exhaustive CVE inventory.
  Keyword/CPE results remain version-unverified candidates and can be irrelevant to the target.
  Built-in matching always runs, and locally provable version mismatches are removed.

- Built-in CVE database is small and heuristic. It is not equivalent to Nmap/Nessus fingerprinting.
- SMB 3.1.1 dialect negotiation alone cannot reveal the Windows build or installed patch level.
  The built-in matcher therefore shows SMBGhost only as an unverified protocol assessment.
  Default cloud lookups can additionally return `CVE-2020-0796` as a version-unverified candidate;
  that is metadata to review, not proof of a missing patch. SMBv1 is not SMBGhost's dialect.
- Service version detection depends on banner format; many real-world banners will not produce exact versions.
- UDP `closed` is an inference from an unreachable/refused socket error or a connection
  reset. Some firewalls synthesize reset-style errors, so a reset can be reported as
  `closed` even when the service is filtered or otherwise not directly observable.
  Timeout remains `open|filtered`; use a protocol-aware follow-up before treating
  `closed` as absolute proof.
- When a platform certificate provider exposes `NotAfter` with `DateTimeKind.Unspecified`,
  LucentMist interprets that wall-clock value in the scanner host's local time zone.
  X.509 validity timestamps do not carry a separately recoverable source time-zone ID;
  operators should keep the scanner host's time zone and clock correctly configured.
- Standard service banners do not provide an OSV-compatible package coordinate or Git
  commit. LucentMist therefore does not query OSV or claim OSV version verification for
  an OpenSSH string such as `9.8p1`; only explicit 40-character commit evidence enables
  OSV's top-level commit query. Debian/Ubuntu package versions are not fabricated from
  banners. See [osv-validation.md](osv-validation.md) for the contract evidence and the
  unsuccessful local live-query attempts. Other external sources remain explicitly
  version-unverified.
- SMB2-first dialect detection was validated against an authorized real Windows
  SMBv3.1.1 service at `192.168.99.9:445`: it negotiated SMBv3.1.1, did not report
  EternalBlue, and reported SMBGhost only as a candidate. The captured command
  output and environment facts are recorded in
  [product-validation.md](product-validation.md#real-windows-smb-target). A follow-up
  reachability check on 2026-08-29 found that endpoint unavailable, so the real-target
  scan could not be repeated in this session.
- A real SMBv1 positive target is still needed. The positive path currently uses a
  local TCP test server for SMB2-first/reconnect behavior and byte offset 37; this is
  simulator coverage, not real-target proof.
- Real OpenSSH services were validated using authorized local Docker containers bound
  to `192.168.99.9:22`. Ubuntu 22.04 exposed a real OpenSSH 8.9p1 service (banner
  `OpenSSH_8.9p1 Ubuntu-3ubuntu0.16`) and produced a CVE-2023-38408 **candidate**;
  Ubuntu 24.04 exposed `OpenSSH_9.6p1 Ubuntu-3ubuntu13.18` and did not produce that
  candidate. This proves
  real SSH banner capture and version matching on both sides of the threshold. It does
  not prove exploitability: distribution packages may backport security fixes without
  changing the upstream banner version, and a server banner alone cannot establish the
  affected runtime path. Exact `9.3p1`/`9.3p2` adjacency remains pinned by banner tests.
  Full evidence is recorded in
  [product-validation.md](product-validation.md#real-openssh-services-in-local-containers).
- The bundled verifier currently reports SMBv1 exposure only as a candidate. It does
  not confirm EternalBlue patch state or exploitability; the verifier interface is an
  extension point for future evidence-backed checks.
- Web live monitoring stops after its configured time budget (10 minutes by default,
  configurable with `LMIST_POLL_TIMEOUT_MINUTES`). The UI explicitly says that the
  result could not be confirmed and directs the user to scan history; the underlying
  scan may still complete later, so this state is not reported as a task failure.
- New scan databases enforce allowed status values with a table `CHECK`. Existing
  databases receive equivalent insert/update triggers because SQLite cannot add that
  table constraint in place without rebuilding the table. A future schema rebuild may
  consolidate the legacy trigger defense into the table definition.

## Agent

- Agent analysis is experimental.
- Agent network tools do not use an interactive authorization prompt. Public IPs, CIDRs and
  domains must be explicitly included in `LMIST_ALLOWED_TARGETS`; otherwise the tool call is
  rejected before network access. RFC1918 and loopback targets remain allowed by default.
  The user remains responsible for having legal authorization for every configured target.
- Default local model qwen2.5:7b scored 0/10 in real LLM evaluation.
- Claude validation is pending.
- Contract violations now produce a visible degradation warning.
- The development Web UI labels Agent as experimental and keeps the chat controls
  closed until the user explicitly accepts the limitation. Non-experts are directed
  to deterministic scan and report paths instead.

## Testing

- CI runs `--filter "Category!=External"`. The filtered count changes as tests are added; do not treat a single number as a frozen contract.
- Local full runs include external SSL tests and may show a different count.
- Test counts in docs are being reconciled to this two-track statement.

## Deployment

- The historical `0.9.4` entrypoint can independently generate API tokens in the API
  and Web containers when `LMIST_API_TOKEN` is blank. Because both containers share
  the token file but keep their own process environment, this can leave Web unable to
  authenticate to API. `0.9.4` operators must explicitly set the same strong
  `LMIST_API_TOKEN` for both services, plus `LMIST_WEB_USER` and
  `LMIST_WEB_PASSWORD`, before startup.
- The `0.9.5` entrypoint fixes that coordination defect by reusing the existing
  non-empty shared token file and generates Web credentials only for the Web process.
  Current `main` persists generated local-demo credentials in the protected data volume
  and logs only their file locations, never their values. The published 0.9.5 image
  predates that hardening and still prints generated demo credentials; production
  deployments must override all credentials through an uncommitted `.env` or a proper
  secret manager.
- Scan results, Agent sessions, audit records and generated credential files are not
  application-layer encrypted. Self-use deployments should protect the host with
  full-disk encryption and restrict filesystem access. See
  [data-security-and-recovery.md](data-security-and-recovery.md).
- The GHCR package currently requires authenticated access. Deployers need a classic personal access token with `read:packages`; credentials must be supplied through `docker login --password-stdin`, not committed to configuration.
- The `0.9.4` GHCR tag is not claimed to be immutable. Exact rollback uses `ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af`.
- There is no GitHub Release object for `v0.9.4`, and repository ruleset visibility was unavailable to the verification credential (`403`), so Git tag immutability is not claimed. Enable GitHub immutable Releases before publishing the next version; that protects the Git tag and release assets, while the container still needs digest pinning.
- The local Windows route to GHCR blobs was unusually slow (about 26.8 KB/s in a 60-second sample), so the local full pull exceeded its 10-minute verification budget. The independent GitHub-hosted pull-and-run succeeded; this local network condition is not presented as a successful deployment test.
