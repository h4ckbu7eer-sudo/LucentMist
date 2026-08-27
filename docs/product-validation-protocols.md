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

Pass:

- At least half report a real current pain point, not "sounds nice".

Fail:

- Users say they would outsource it, use an online tool, or do not care.

## Protocol 2: Report Usability Review

Participants:

- At least 3 non-security people: technical-but-not-security, business, management lead.
- No project contributors.

Task:

- Give each participant `docs/validation-report.html`.
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

Fail:

- Version detection remains broken. Direction A must then decide whether the report can work with service category plus common-risk hints instead of exact versions.

## Decision

- All three pass: Direction A stands; report redesign and guided interaction become the next engineering phase.
- Any critical validation fails: stop or pivot to Direction B.
