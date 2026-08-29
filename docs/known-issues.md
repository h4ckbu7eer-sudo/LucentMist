# Known Issues

Current status as of 0.9.4.

## Release Status

- `v0.9.4` is published from commit `d56e4f0e`. Its [tag workflow](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244573226) completed Windows, Ubuntu, and GHCR jobs successfully.
- `ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4` has a readable Docker manifest; the inspected image config digest is `sha256:66397206f4c24956b4b1b9278e379032fb90b6361d944a5e39e421f5a1d93278`.
- The first simultaneous main workflow exposed a timer-sensitive Windows test. The assertion guard was fixed without changing the production monitoring timeout, and the follow-up [main workflow](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244948229) completed all three jobs successfully.

## Product Limitations

- Built-in CVE database is small and heuristic. It is not equivalent to Nmap/Nessus fingerprinting.
- Service version detection depends on banner format; many real-world banners will not produce exact versions.
- SMB2-first dialect detection was validated against an authorized real Windows
  SMBv3.1.1 service at `192.168.2.9:445`: it negotiated SMBv3.1.1, did not report
  EternalBlue, and reported SMBGhost only as a candidate. The captured command
  output and environment facts are recorded in
  [product-validation.md](product-validation.md#real-windows-smb-target). A follow-up
  reachability check on 2026-08-29 found that endpoint unavailable, so the real-target
  scan could not be repeated in this session.
- A real SMBv1 positive target is still needed. The positive path currently uses a
  local TCP test server for SMB2-first/reconnect behavior and byte offset 37; this is
  simulator coverage, not real-target proof.
- Real OpenSSH services were validated using authorized local Docker containers bound
  to `192.168.2.9:22`. Ubuntu 22.04 exposed a real OpenSSH 8.9p1 service (banner
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
- Default local model qwen2.5:7b scored 0/10 in real LLM evaluation.
- Claude validation is pending.
- Contract violations now produce a visible degradation warning.

## Testing

- CI runs `--filter "Category!=External"`. The filtered count changes as tests are added; do not treat a single number as a frozen contract.
- Local full runs include external SSL tests and may show a different count.
- Test counts in docs are being reconciled to this two-track statement.

## Deployment

- Docker compose auto-generates random credentials and prints them to container logs.
- Production deployments must override credentials through `.env`.
