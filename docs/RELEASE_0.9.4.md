# LucentMist 0.9.4 Release Notes

Release date: 2026-08-29

LucentMist 0.9.4 is a reliability and security-detection release. It turns the accumulated scanner fixes into a versioned, auditable delivery without changing the public product direction.

## What changed for users

### Vulnerability detection

- SMB negotiation is SMB2-first with SMB1 fallback, and both paths use one dialect parser. SMB1 reads the dialect index from byte offset 37; SMB2/3 reads the dialect revision from byte offset 72.
- Modern SMBv3 services are no longer incorrectly treated as SMB1/EternalBlue candidates. SMBGhost remains a candidate when SMBv3.1.1 is observed because dialect alone does not prove patch state.
- OpenSSH CVE-2023-38408 matching now uses the upstream 9.3p2 fix boundary. Versions through 9.3p1 match; 9.3p2 and later do not.
- CVEs that cannot be concluded from the collected banner are marked as not banner-matchable instead of being silently presented as automatically checked.

### Reports for non-experts

- HTML, Markdown and CSV reports list the actual open ports and service names rather than only a count.
- The report command collects SSL information for eligible HTTPS services, and HTML renders the result.
- Findings excluded by report scoping are genuinely excluded from summary, urgency and detail sections.
- Only warnings that affect exposure or vulnerability completeness downgrade a report to `partial`; informational gaps remain visible as notes.

### Monitoring and lifecycle reliability

- Web monitoring has a bounded timeout and distinguishes “scan failed” from “result could not be confirmed.”
- Monitoring errors and rejected scan requests are visible on Home, Scan and Devices pages.
- Completed and failed scan states cannot be reversed by late cancellation or duplicate worker updates; the database also constrains allowed status values.
- Polling failures are isolated, cancellation is propagated, and queue/back-pressure behavior avoids unbounded work.

## Validation evidence

- Local full suite: 299/299 tests passed before release.
- SMB parsing and reconnect regression tests cover both byte offsets 37 and 72.
- An authorized real Windows SMB service negotiated SMBv3.1.1. LucentMist did not report EternalBlue and reported SMBGhost only as a candidate.
- Authorized local Docker containers exposed real OpenSSH 8.9p1 and 9.6p1 services. LucentMist reported CVE-2023-38408 as a candidate for 8.9p1 and did not report it for 9.6p1.
- Exact OpenSSH 9.3p1/9.3p2 adjacency remains deterministic banner-test evidence, not a pair of separately compiled real daemons.

Full evidence and limitations are recorded in [product-validation.md](product-validation.md) and [known-issues.md](known-issues.md).

## Published artifacts

- Tag: `v0.9.4` at commit `d56e4f0e`
- Tag CI: [run 39](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244573226), with Windows, Ubuntu and GHCR jobs successful
- Follow-up main CI after stabilizing a timer-sensitive test guard: [run 41](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244948229), with all three jobs successful
- Container: `ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4`
- Immutable image manifest digest: `sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af`
- Image config digest: `sha256:66397206f4c24956b4b1b9278e379032fb90b6361d944a5e39e421f5a1d93278`

## Reproducible post-release verification

Independent read-only checks on 2026-08-29 confirmed:

```text
refs/heads/main       826ae6f25898cb3ba6f73b4ec614e8cc31449980
refs/tags/v0.9.4      7e8b2df52dad6a81c59989d31348e2c4d69b3573
refs/tags/v0.9.4^{}   d56e4f0e43d5752a28e0e77db17998eb5b1f07bd

run 33244573226: completed / success
  Build & Test (ubuntu-latest): success
  Build & Test (windows-latest): success
  Build & Push GHCR: success

run 33244948229: completed / success
  Build & Test (ubuntu-latest): success
  Build & Test (windows-latest): success
  Build & Push GHCR: success
```

The repository now contains an on-demand [release image verification workflow](../.github/workflows/release-verification.yml). Its first [run 33257054498](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33257054498) pulled the published image from GHCR, rejected any manifest other than the expected release digest, started the API container, and recorded:

```text
Pulled image: ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af
Health response: {"status":"healthy","version":"0.9.4","uptime":"0h 0m"}
```

The local Windows host could read the manifest, but its route to the GHCR blob store transferred a sampled 29.8 MB layer at only about 26.8 KB/s and did not complete a full pull within the 10-minute local budget. That local attempt is not reported as successful; the successful pull-and-run evidence above comes from the independent GitHub-hosted runner.

GHCR version tags are treated as mutable references. Reproducible rollback therefore pins the manifest digest, not only the `0.9.4` tag:

```text
ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af
```

The repository currently has no GitHub Release object for `v0.9.4`, and the available API credential could not inspect repository rulesets (`403`), so no tag-protection claim is made. GitHub release immutability protects Git tags and release assets for newly published Releases; it does not make a GHCR tag immutable. For the next release, enable immutable Releases before publication and continue recording the container manifest digest separately.

## Known limitations

- A real SMBv1 positive target has not been available. The SMBv1 positive path is proven with a local TCP protocol simulator, not a real vulnerable host.
- SMBGhost and EternalBlue results derived from dialect exposure are candidates, not proof of patch state or exploitability.
- Distribution vendors can backport OpenSSH fixes without changing the upstream version in the SSH banner. Banner matches therefore remain candidates.
- If Web monitoring exceeds its configured time budget, the UI reports that the result cannot be confirmed and directs the user to scan history; it does not claim the underlying scan failed.
- The built-in CVE catalog and service fingerprinting are intentionally small and heuristic. LucentMist is not a replacement for a full authenticated enterprise scanner.
- Agent analysis remains experimental.

## Deployment requirements

> **Important:** do not start the published `0.9.4` API/Web compose stack with blank
> credential variables. Each container can generate a different API token, so Web
> authentication to API is not reliable in that configuration. Set the same explicit
> `LMIST_API_TOKEN`, plus strong `LMIST_WEB_USER` and `LMIST_WEB_PASSWORD`, before
> startup. This is both a security requirement and a functional requirement.

The versioned container is:

```text
ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4
```

For an exact rollback, use the manifest-pinned reference shown above. The package currently requires authenticated GHCR access; use a classic personal access token with `read:packages` and pass it through `docker login --password-stdin`. Do not place the token in shell history or deployment files.

Production deployments must explicitly set strong values for:

- `LMIST_API_TOKEN`
- `LMIST_WEB_USER`
- `LMIST_WEB_PASSWORD`

The published startup helper can generate credentials and prints them to container
logs, but its two-container blank-token behavior is not a supported deployment path.
Development after `0.9.4` reuses a shared generated token for isolated local demos;
neither behavior replaces explicit production secret management.

## Next product step

The report path is now suitable for structured usability testing. The next milestone is not another broad code sweep: it is interviewing non-expert users with the protocols in [product-validation-protocols.md](product-validation-protocols.md) to determine whether they understand what is exposed and what to fix first.

Development after this release uses version `0.9.5-dev` on `main`. The `0.9.4` tag and digest remain fixed rollback references; fixes after the tag belong to a new `0.9.5` release rather than overwriting `0.9.4`.
