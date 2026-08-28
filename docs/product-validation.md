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

The local Windows host was used as an authorized real SMB target at `192.168.2.9:445`.
This was the Windows `LanmanServer` service, not a TCP response simulator.

Read-only environment checks reported:

- Windows build: `22631`
- `EnableSMB1Protocol`: `False`
- `EnableSMB2Protocol`: `True`
- Port `445`: listening

`lmist vuln-scan 192.168.2.9` produced:

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
