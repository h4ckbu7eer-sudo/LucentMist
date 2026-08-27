# Direction A Validation Protocols

Direction A: a lightweight exposure self-check tool for non-security experts.

The value proposition to validate:

> LucentMist can give a non-security expert a 5-minute exposure check and help them decide which exposure should be handled first.

## Order

1. User interviews: cheapest, highest information, confirms demand exists.
2. Report usability review: confirms the core deliverable enables decisions.
3. Controlled subnet scan + Nmap comparison: confirms the scanner foundation.

## Protocol 1: User Interview

Participants:

- 3-5 target users: one-person IT in a small company, personal developer, entry-level security.

Questions:

1. How do you currently check which ports/services your network exposes?
2. Have you used Nmap? If not, what blocked you: barrier, English, CLI?
3. Would a 5-minute tool that tells you "these exposures exist, this one is most urgent" be useful? Would you pay?
4. Have you tried an online exposure/security SaaS? What stopped you or what did you dislike?
5. At what monthly price would this be worth paying? At what price would you not bother?

Pass:

- At least half report a real current pain point, not "sounds nice".
- At least half state a concrete price point and a concrete alternative they currently use or reject.

Fail:

- Users say they would outsource it, use an online tool, or do not care.

## Protocol 2: Report Usability Review

Participants:

- At least 3 non-security people: technical-but-not-security, business, management lead.
- No project contributors.

Task:

- Use a report generated against a controlled target with known findings (for example a deliberately vulnerable test VM), not the empty 127.0.0.1 report.
- Enable CVE data for the validation run so the report is not artificially "safe".
- Give each participant the report with findings.
- Ask:
  1. Does this report tell you whether the network has a problem? Is severity ordered?
  2. Can you decide whether and what to handle first?
  3. What is unclear or could cause a wrong decision?

Pass:

- At least 2/3 can answer "what risks exist and which should be handled first".

Fail:

- The report reads as a port/CVE list and non-experts cannot prioritize.

## Protocol 3: Controlled Subnet Scan + Nmap Comparison

Environment:

- VM or isolated subnet, at least 3 machines:
  - Linux SSH + HTTP
  - Windows SMB + RDP
  - Router or firewall
- Install Nmap locally.

Execution:

- LucentMist: CLI + API + Web across the full /29.
- Nmap: `nmap -sV` against the same subnet.

Record:

- Port discovery comparison.
- Service identification comparison, especially version detection.
- Time and stability for each tool.

Pass:

- LucentMist identifies common service versions, such as OpenSSH or nginx.

Important:

- LucentMist may use Nmap itself through NmapEnhancer. The comparison must split:
  - Built-in heuristic identification without Nmap.
  - Nmap-backed identification.
  Otherwise the comparison is Nmap versus Nmap.

Fail:

- Version detection remains broken. Direction A must then decide whether the report can work with service category plus common-risk hints instead of exact versions.

## Decision

- All three pass: Direction A stands; report redesign and guided interaction become the next engineering phase.
- Any critical validation fails: stop or pivot to Direction B.

## Core Value Measurement

Direction A is "5-minute self-check". The protocols above only measure correctness. Add a task-level measurement:

- Install to first report: measure how long a non-expert takes from install to reading a prioritized report.
- Understanding: ask the participant to state the top risk and the recommended next action.
- Pass: a non-expert can complete install, scan, and decision in about 5 minutes without contributor help.
