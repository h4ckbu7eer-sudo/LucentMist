# Direction A User Interview Script

Status: **ready to execute; participants are still to be recruited**. This is an
execution script, not evidence that any interview has happened.

Target participant: a small-company solo IT operator, independent developer, or
entry-level security practitioner who has not contributed to LucentMist.

Duration: 20-25 minutes. Record only with explicit permission. Remove names,
employers, IP addresses, credentials, and other identifying details from shared
notes.

## Opening (read aloud)

> Thank you for helping us understand how people check network exposure. We are
> testing the problem and the report, not testing you. LucentMist is an experimental
> self-check tool, not a guarantee of security. There are no right answers. Please
> describe what you actually do rather than what sounds ideal. I will not sell you
> anything during this interview.

Ask permission to take notes. If recording is desired, ask separately and record the
answer here: `notes only / audio permitted / declined`.

## Five questions

Ask the numbered question first. Use the prompts only when needed; do not lead the
participant toward LucentMist.

1. **Tell me about the last time you needed to find which network ports or services
   were exposed. What triggered it, and what did you actually do?**
   - When was this?
   - What was difficult or uncertain?
   - What happened if you did nothing?

2. **What tools or people do you use today? Have you tried Nmap?**
   - If not: was the barrier installation, command line usage, English terminology,
     interpreting results, or something else?
   - If yes: what do you still have to do manually after it finishes?

3. **Imagine a tool produces a prioritized network exposure report in about five
   minutes. In what concrete situation would you use it, and who would act on the
   result?**
   - What would make you distrust or abandon it?
   - What evidence would you need before changing a firewall or service?

4. **Which alternatives do you know or use, including Shodan, Qualys, online
   scanners, cloud-provider tools, a consultant, or doing nothing? Why did you choose
   or reject them?**
   - Capture one concrete alternative and its advantage, cost, or blocker.

5. **If this solved the situation you described, would you pay US$5 per month? Why or
   why not? At what monthly price would it clearly be worth paying, and at what price
   would you not bother?**
   - Ask for a number even if it is `$0`.
   - Do not count “maybe” as willingness to pay.

## Interview record

```text
Interview ID / date:
Participant profile (no identifying details):
Interviewer:
Notes/recording permission:

Last real exposure-check event:
Current pain and consequence:
Current tool/person/alternative:
Nmap experience and blocker:
Concrete use case for a 5-minute report:
Evidence needed before acting:
US$5/month answer and reason:
Clearly worthwhile price:
Would-not-bother price:

Short verbatim phrases (with permission):
-

Observed behavior, not interpretation:
-

Interviewer interpretation (keep separate):
-
```

## Outcome classification

Mark each independently:

- `real current pain: yes / no / unclear`
- `concrete current or rejected alternative: yes / no`
- `concrete price point: yes / no`
- `would use in a named situation: yes / no`

The Direction A interview protocol passes only after at least half of all recruited
participants report a real current pain and at least half give both a concrete price
and a concrete alternative. Courtesy, enthusiasm, or “sounds useful” alone is not a
pass.
