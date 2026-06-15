# Evidence Hygiene (skill)

This skill is the human-facing reference for the 5-step capture order,
ranked redaction methods, and post-submission credential rotation.
It is rendered by ``/evidence`` and lives in source form at
``prometheus/skills/evidence-hygiene.md``.

The implementation lives in :mod:`prometheus.skills.evidence_hygiene`
and exposes:

- ``render_evidence_hygiene()`` — the markdown body printed by
  ``/evidence``.
- ``scan_text_for_secrets(text)`` — substring scan for cookie /
  token names.
- ``scan_image_for_secrets(path)`` — best-effort EXIF + OCR scan
  for an image file.

## Why this is a first-class skill

Bounty submissions fail when a screenshot contains a live session
cookie or an API key. The 7-Question Gate's Q6 (actual victim data)
*requires* the evidence to show exfil — but it must not leak the
attacker's own credentials in the process.

## When to invoke

- After any tool call that returns a `screenshot://` URL.
- Before any tool call to `create_vulnerability_report` (the report
  should reference only redacted evidence).
- Any time the agent sees a `session=`, `bearer `, or `api_key=`
  substring in tool output.
