# Security Policy

## Scope

NovaGate-AIShield is a **heuristic, transparent filter**. It is meant to be read,
audited and extended -- not to be the only thing between your users and a model.
It has no training data and no model weights; it matches phrases and measures
structure.

That design is deliberate. A model-based classifier will beat it on novel
payloads, and it is bypassable by anything clever enough. What it gives you is
a first layer that is auditable in five minutes, has no data-governance
footprint, and cannot be persuaded by the attacker's prompt. If you need more,
put a model classifier behind it and treat NovaGate as the cheap, transparent
tier in front.

Please do not report "I bypassed it with a novel payload" as a vulnerability in
the coordinated-disclosure sense. It is the documented design, and the right
response is a rule in `signatures.py`. Report it anyway -- the corpus gets
better -- but expect it to be handled as an enhancement.

## What *is* in scope

Please report these:

- A vulnerability in **NovaGate itself**: unauthenticated access to the
  dashboard, audit log or `/api/v1/stats`; the bind-safety check being
  bypassable; a way to forge or corrupt audit entries; the dashboard executing
  attacker-supplied script (XSS); a remote-code-execution or path-traversal
  issue; an unauthenticated bypass of the API key.
- A **documented guarantee that is false** -- for example the README claiming a
  behaviour the code does not have.
- A **dependency vulnerability** reachable from the default configuration.
- **DoS with a trivially small request**: a payload that makes one request cost
  disproportionate CPU or memory.

## What is out of scope

- Novel prompt-injection payloads that reach the detector's scoring function.
- False positives, unless the benign corpus in `tests/corpus/benign.json` is
  blocked.
- Running without an API key on a public interface. That is refused at startup
  by design; finding a way around the refusal is in scope, configuring around it
  is not.
- Absence of authentication on `localhost` with default settings.
- Anything requiring an already-compromised host.

## Supported versions

`main` only. The project has no release tags yet; install from `main` or use the
Docker image.

| Version | Supported |
| --- | --- |
| `main` | yes |
| anything older | no |

## Reporting

**Do not open a public issue.**

Email the maintainer via the address on the GitHub profile, or use GitHub's
private vulnerability reporting on the Security tab of the repository if it is
enabled.

Please include:

- what the issue is, in one sentence
- the request or payload that demonstrates it
- the version or commit
- what you expected and what happened
- whether it needs authentication

Expect an acknowledgement within 72 hours and an assessment within 7 days. If
we accept it we will agree a disclosure date with you, and credit you in the
advisory unless you prefer otherwise.

Please give us a reasonable window to ship a fix before public disclosure. We
will not withhold a fix indefinitely; if we cannot reach you after 90 days we
will disclose.

## Hardening checklist for deployment

Before putting this in front of a real model:

- [ ] Set `NOVAGATE_API_KEY`. Binding a non-loopback address without one is
      refused, but that guard is the only thing standing between you and an
      open dashboard.
- [ ] Terminate TLS in front of it. NovaGate speaks plain HTTP.
- [ ] Set `NOVAGATE_EXPOSE_DOCS=false` (the default) so `/docs` and
      `/openapi.json` are not published.
- [ ] Set `NOVAGATE_TRUST_FORWARDED_FOR=true` **only** if there is a proxy you
      control. Otherwise every client shares one rate-limit bucket, and if you
      enable it without a proxy, any client can mint a fresh bucket per request.
- [ ] Ship the audit log somewhere durable and ship it off-host. It is JSON
      lines and rotates, but it stays on local disk unless you move it.
- [ ] Set `NOVAGATE_CONSOLE_TELEMETRY=false` outside development.
- [ ] Treat `REVIEW` verdicts as work, not noise. They exist so a human looks.
- [ ] Add a second tier. See the Limitations section of the README.

## What the audit log does and does not record

It records a SHA-256 of the normalised prompt, a short redacted preview, the risk
index, matched categories, the client address and a request ID. It redacts
credential-shaped strings and truncates previews.

It does **not** record your prompts in full. That is intentional, but it does
mean the log is not enough to reconstruct an incident. If you need that, you
need a separate, deliberately configured, access-controlled capture path -- not
this file.
