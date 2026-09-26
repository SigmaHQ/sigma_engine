# Security Policy

## Supported versions

This project has no tagged release yet. Security fixes are made on the `main` branch.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: **Security → Advisories → "Report a vulnerability"** on this repository (<https://github.com/SigmaHQ/sigma_engine/security/advisories/new>).
If you cannot use GitHub, open a public issue that says only that you have a security report and asks for a private contact. Do not include any details in that issue.

Please include:

- the crate version or commit, and a minimal rule and event that reproduce the problem;
- the impact you see (see the scope below) and, if you have one, a proposed fix.

## What we treat as a vulnerability

sigma_engine parses Sigma detection and correlation rules and matches them against log events. Both rules and events may come from untrusted sources. The following are in scope:

- **Denial of service:** crafted rules or events that cause panics, unbounded memory growth, excessive CPU (for example pathological regular expressions, wildcard or encoding expansion), or deadlocks in the multithreaded matching pipeline.
- **Memory safety:** any undefined behaviour reachable from rule or event input, including through `unsafe` code or dependencies.
- **Evasion by construction:** event input that can make the engine skip evaluation of other events or rules (for example by crashing a worker or poisoning shared state), as opposed to a single rule simply not matching.
- **Correlation state abuse:** events that exhaust or corrupt correlation state across rules or time windows.

**Out of scope (report publicly as bugs):**

- A rule matching more or fewer events than the Sigma specification requires, without the effects above. These are handled as normal issues and pull requests so fixes reach users quickly.
- A systemic and severe detection gap may be reported privately; the maintainers decide whether it becomes an advisory.

## Our process

| Step                                                                          | Target                                        |
| ----------------------------------------------------------------------------- | --------------------------------------------- |
| Acknowledge the report                                                        | within 5 working days                         |
| Initial assessment and severity (CVSS 3.1)                                    | within 14 days                                |
| Fix developed in the advisory's temporary private fork                        | as soon as practical, normally within 90 days |
| Coordinated release, then GitHub Security Advisory published (CVE via GitHub) | at the fix release                            |

- We credit reporters in the advisory unless they ask not to be credited.
- When a fix affects other SigmaHQ projects, we may coordinate their releases.
- We ask reporters to keep details private until the advisory is published or 90 days have passed, whichever comes first, unless agreed otherwise.
