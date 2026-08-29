# Direction A Validation Kit

This directory turns the protocols in
[product-validation-protocols.md](../product-validation-protocols.md) into material
that a non-contributor can use without project coaching.

## Current evidence status

| Item | Status | Evidence |
|---|---|---|
| Controlled report with findings | Complete | [validation-report.html](../validation-report.html) |
| Interview script | Ready; recruitment blocked at 0/3 | [interview-script.md](interview-script.md) |
| Report review rubric | Ready; recruitment blocked at 0/3 | [report-review-rubric.md](report-review-rubric.md) |
| Interview result | **Sample insufficient / not passed** | [results/interview.md](results/interview.md) |
| Report review result | **Sample insufficient / not passed** | [results/report-review.md](results/report-review.md) |
| User demand validated | **No** | No real participant was recruited or interviewed |

The report was generated from three real services in isolated Docker containers:
OpenSSH 8.9p1 on port 22, nginx HTTP on port 80, and nginx TLS with a seven-day
self-signed certificate on port 443. It contains one OpenSSH
CVE-2023-38408 **candidate**, not an exploitability claim.

The reproducible target definitions and commands are in
[controlled-targets/README.md](controlled-targets/README.md). Do not expose this
isolated validation network to the public Internet.

## Suggested first session

1. Recruit one person who has not contributed to LucentMist.
2. Run the interview using [interview-script.md](interview-script.md).
3. Give the same person [validation-report.html](../validation-report.html) and five
   minutes without coaching.
4. Score the result with [report-review-rubric.md](report-review-rubric.md).
5. Store dated, anonymized results separately. Do not turn polite interest into a
   pass unless the protocol criteria are met.
