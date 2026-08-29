# Product Validation

Date: 2026-08-28

Target: `127.0.0.1`, controlled local loopback only.

## 1. Real End-to-End Run

### CLI scan

`lmist scan 127.0.0.1`:

- Ping: 1/1 alive
- TCP subset `22,80,443,3389,8080`: 0 open

### Vuln scan

`lmist vuln-scan 127.0.0.1`:

- Open ports: 135, 445, 902, 912
- Service guesses: RPC, SMB, VMware
- CVE findings: 0

### Report

`lmist report --target 127.0.0.1 --format html`:

- Generated `docs/validation-report.html`
- 7355 characters
- No external reviewer evaluation performed yet

### API

`POST /api/v1/scan` with `tcp` and ports `135,445,902,912`:

- Status: completed
- Open ports: 135, 445, 902, 912
- Duration: 0.07s

## 2. Nmap Comparison

Nmap is not installed in this environment. No comparison was performed.

## 3. Honest Conclusion

This is the first limited product validation, not a proof of product value:

- LucentMist can complete real scans and produce a report.
- Service identification is heuristic and did not identify versions for SMB or VMware.
- The vulnerability database returned zero findings, so no security analysis value was demonstrated.
- No evidence yet shows LucentMist provides value over Nmap/Nessus.
- Agent analysis remains experimental and has not been proven with a capable model.

The product value question remains open until a real Nmap comparison and an external report usability review are performed.

The validation protocols and their pass/fail criteria are defined in [product-validation-protocols.md](product-validation-protocols.md).

## 4. Core Vulnerability Detection Follow-up

Date: 2026-08-29

### Real Windows SMB target

The local Windows host was used as an authorized real SMB target at `192.168.99.9:445`.
This was the Windows `LanmanServer` service, not a TCP response simulator.

Read-only environment checks reported:

- Windows build: `22631`
- `EnableSMB1Protocol`: `False`
- `EnableSMB2Protocol`: `True`
- Port `445`: listening

`lmist vuln-scan 192.168.99.9` produced:

- Port `445` service: `SMB`
- Negotiated version: `SMBv3.1.1`
- EternalBlue (`CVE-2017-0144`): not reported
- SMBGhost (`CVE-2020-0796`): reported as a **candidate**, not a verified finding

This confirms the SMB2-first negotiation path works against a real modern Windows
server and that an SMBv3 target is not misclassified as EternalBlue. The SMBGhost
result must remain a candidate because a dialect banner alone does not prove the
Windows patch level.

### Validation still pending

- No real SMBv1 target was available. The positive SMBv1 path is covered by a local
  TCP test server that verifies the SMB2-first attempt, reconnect fallback, and the
  SMB1 dialect index at byte offset 37. It must not be described as real-target proof.
- No real OpenSSH `9.0`-`9.3p1` or `9.3p2+` target was available. The local `sshd`
  service was stopped and no Docker daemon was running. Banner regression tests pin
  `9.0p1`, `9.1`, `9.2p1`, and `9.3p1` as candidates, and `9.3p2` and `9.4` as not
  matching `CVE-2023-38408`; real-service validation remains pending.

### Follow-up availability check

On 2026-08-29, a read-only reachability check found `192.168.99.9:445` unavailable,
so the previously recorded real Windows SMB run above could not be repeated. Local
port `22` was also closed and no Docker service was available; consequently no real
OpenSSH boundary target was substituted or claimed. The focused SMB/OpenSSH regression
suite was rerun instead: 28 tests passed, including offsets 37/72, SMB2-first with
SMB1 reconnect fallback, OpenSSH `9.0p1` through `9.3p1` matching, and `9.3p2`/`9.4`
not matching. Those tests establish parser and matching behavior only, not real-service
validation.

### Real OpenSSH services in local containers

Later on 2026-08-29, Docker Desktop became available. Two temporary, authorized
containers were run one at a time on the local Windows host and published only for
this validation at `192.168.99.9:22`:

| Container base | Installed package | Observed real SSH banner | LucentMist result |
|---|---|---|---|
| Ubuntu 22.04 | `1:8.9p1-3ubuntu0.16` | `OpenSSH_8.9p1 Ubuntu-3ubuntu0.16` | CVE-2023-38408 reported as a candidate |
| Ubuntu 24.04 | `1:9.6p1-3ubuntu13.18` | `OpenSSH_9.6p1 Ubuntu-3ubuntu13.18` | CVE-2023-38408 not reported |

For the 8.9p1 service, an independent OpenSSH client completed a real SSH handshake
and logged the remote software version before LucentMist was run. `lmist vuln-scan
192.168.99.9 --all` then identified port 22 as SSH version `8.9p1`, CPE
`cpe:2.3:a:openbsd:openssh:8.9p1`, and reported CVE-2023-38408 with CVSS 7.5 as an
unconfirmed candidate. The same full command against the 9.6p1 service identified
version `9.6p1` and did not report CVE-2023-38408.

This is real-service validation, not a TCP banner simulator. It establishes that the
network connection, SSH banner parser, product-version extraction, and CVE threshold
work end to end for representative versions below and above the fix threshold. It
does **not** establish that the Ubuntu 8.9p1 package is exploitable: Ubuntu may backport
security fixes while retaining the upstream version in its banner, and an SSH server
banner cannot prove the affected runtime path. The finding must therefore remain a
candidate. Exact `9.3p1` and `9.3p2` adjacency is still covered by deterministic banner
tests rather than separately compiled real daemons.

Both temporary containers were removed after validation, the host port was released,
and the WSL Ubuntu distribution was returned to its original stopped state.

## 5. Version 0.9.4 Release Verification

Date: 2026-08-29

Version `v0.9.4` was published from commit `d56e4f0e`. The release contains the
real Windows SMB and real containerized OpenSSH validation paths documented above.

Remote evidence:

- The [v0.9.4 tag workflow (run 39)](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244573226)
  completed Windows build-and-test, Ubuntu build-and-test, and GHCR publishing with
  `success`.
- `docker manifest inspect ghcr.io/h4ckbu7eer-sudo/lucentmist:0.9.4` returned a valid
  schema-v2 manifest. Its config digest was
  `sha256:66397206f4c24956b4b1b9278e379032fb90b6361d944a5e39e421f5a1d93278`.
- The simultaneous first main workflow (run 40) was not called green: its Windows job
  failed because a 2-second assertion guard expired while a 25-millisecond test timer
  was delayed on the shared runner. The same commit's tag Windows job passed. The test
  retained a short injected product timeout but received a longer deadlock guard, and
  the [follow-up main workflow (run 41)](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33244948229)
  completed Windows, Ubuntu, and GHCR jobs with `success`.

This release evidence does not widen the vulnerability claims: the real Windows target
proved SMBv3.1.1 negotiation and absence of an EternalBlue misclassification, not a
real SMBv1 positive; the real OpenSSH services proved end-to-end banner capture and
matching on representative versions, not exploitability or separately compiled
9.3p1/9.3p2 daemons.

With the report path now deliverable, the next product step is the non-expert user
interview protocol in [product-validation-protocols.md](product-validation-protocols.md),
not another unbounded code sweep.

### Independent published-image run

An on-demand GitHub Actions workflow independently pulled the published GHCR image in
[run 33257054498](https://github.com/h4ckbu7eer-sudo/LucentMist/actions/runs/33257054498).
The job completed every step successfully: GHCR login, pull, manifest-digest
comparison, container startup, health request, log capture, and cleanup.

The pulled reference resolved to:

```text
ghcr.io/h4ckbu7eer-sudo/lucentmist@sha256:11b2bdcd909697e1509370231daf06f1bd56c25beb38d251774bc3f96d41d2af
```

The running published container returned:

```json
{"status":"healthy","version":"0.9.4","uptime":"0h 0m"}
```

This proves the GHCR artifact can be pulled and the API process in that artifact can
start and answer its health endpoint. It does not prove Web login, persistence, or a
full scan from the published container; those were outside this focused release-image
check.

The local Windows Docker path was also attempted but did not complete: a direct
60-second sample downloaded 1,626,944 of 29,752,807 bytes from one layer, averaging
26,829 bytes/second. The local result is recorded as a network timeout, not a product
success. The GitHub-hosted run above is the successful deployment evidence.

## 6. First Direction A Execution Material

Date: 2026-08-29

The first prerequisite for the report-usability protocol was executed against an
isolated Docker `/29` using the published `0.9.4` CLI image. Three real services were
started temporarily and removed after the run:

| Target | Observed service | Report result |
|---|---|---|
| `172.30.0.9:22` | Ubuntu 22.04 OpenSSH 8.9p1 | CVE-2023-38408 candidate; upgrade/verification guidance |
| `172.30.0.10:80` | nginx HTTP | Open HTTP exposure with plain-protocol guidance |
| `172.30.0.11:443` | nginx TLS, seven-day self-signed certificate | TLS subject/issuer and six-day expiry warning |

LucentMist completed the report run with `3/6` online devices, three open ports, and
one vulnerability candidate. The rendered artifact is
[validation-report.html](validation-report.html); reproducible target definitions are
under [validation-kit/controlled-targets](validation-kit/controlled-targets/README.md).
The scanner image lacked a `ping` executable, so discovery recorded ICMP warnings and
used TCP fallback to find the three intended targets. The final report remained
`completed`; this controlled run is evidence about report content, not a claim that
all discovery environments are equivalent.

The facilitator-ready [interview script](validation-kit/interview-script.md) and
[report review rubric](validation-kit/report-review-rubric.md) are now available.
No non-contributor has yet been interviewed or observed using the report. Direction A
demand and non-expert usability therefore remain **pending recruitment**; this kit is
execution material, not fabricated user evidence.

### Recruitment outcome

The first requested human execution on 2026-08-29 could not start recruitment of a
real non-contributor. No participant list, authorized outreach channel, incentive, or
consent/data-handling workflow was available, so no invitation was sent and no human
response was collected. The empty evidence records are preserved in
[results/interview.md](validation-kit/results/interview.md) and
[results/report-review.md](validation-kit/results/report-review.md).

This is recorded as `0/3`, **sample insufficient / not passed**. It is not evidence
that Direction A failed, and it is not evidence that Direction A works. Need, payment
intent, alternatives, and report decision support all remain unknown.
