# Non-Expert Report Review Rubric

Status: **ready to execute; reviewers are still to be recruited**. No usability pass
is claimed yet.

Artifact: [validation-report.html](../validation-report.html)

Recruit at least three people who have not contributed to LucentMist: ideally one
technical non-security user, one business user, and one management lead. Give each
person the HTML file and five minutes. Do not explain CVEs, ports, “candidate,” or TLS
status before the timer ends.

## Participant task (read aloud)

> Imagine this report describes a network you are responsible for. In five minutes,
> decide whether there is a problem, what should be handled first, and what you would
> tell the person responsible for fixing it. Think aloud if you are comfortable doing
> so. The report may contain uncertainty; point out anything you do not trust or
> understand.

## Questions after five minutes

1. Does this network have a problem? What evidence in the report led you there?
2. What is the highest-priority risk, and why is it higher priority than the others?
3. What is the first concrete action you would ask someone to take?
4. In one minute, how would you explain this result to a manager or client?
5. What was confusing or could cause a wrong decision?
6. What do “candidate” and the TLS warning mean to you? What do they **not** prove?

Do not correct the participant until all answers are recorded. Afterwards, explain
that the OpenSSH item is a version/banner candidate rather than proof of
exploitability, and that a self-signed or expiring certificate needs context.

## 1-5 scoring anchors

Score every dimension; do not average away a dangerous misunderstanding.

| Dimension | 1 | 3 | 5 |
|---|---|---|---|
| Risk recognition | Says the network is safe or cannot locate evidence | Sees a problem but misses important evidence | Identifies the OpenSSH candidate and TLS warning from the report |
| Prioritization | Cannot select a risk or chooses by guesswork | Selects a risk with incomplete reasoning | Selects the high-risk candidate first and explains uncertainty |
| Actionability | Gives no action or a dangerous action | Gives a vague “investigate/update” action | Names a safe next step: confirm package/patch state, then restrict or update |
| Explainability | Cannot summarize for another person | Gives a technical list without a decision | States exposure, priority, next action, and uncertainty in plain language |
| Honesty comprehension | Treats candidate as confirmed compromise/exploitability | Notices caveats only after prompting | Independently explains what the report knows and does not know |

Use scores 2 and 4 when performance falls between the written anchors.

## Review record

```text
Review ID / date:
Participant profile (no identifying details):
Time to first decision:

Network has a problem? Answer and evidence:
Highest priority and reason:
First requested action:
One-minute explanation:
Confusing or misleading areas:
Meaning of “candidate”:
Meaning of TLS warning:

Scores (1-5):
- Risk recognition:
- Prioritization:
- Actionability:
- Explainability:
- Honesty comprehension:

Could identify risks and first priority without coaching: yes / no
Could name a safe next action without coaching: yes / no
Potentially dangerous misunderstanding observed:
Facilitator notes after task:
```

## Decision rule

The report usability protocol passes only if at least two of three reviewers can,
without coaching, identify the main risks, select what to handle first, and name a
safe next action. Any repeated misunderstanding that could cause an unsafe change is
a redesign signal even if the numeric average looks acceptable.
