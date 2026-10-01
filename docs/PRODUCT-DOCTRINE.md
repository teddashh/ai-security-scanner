# Product doctrine: ai-security-scanner

**Locked:** 2026-09-13 (America/New_York), Ted Huang  
**Audience:** future Codex / Claude / human sessions on this repo

This note is durable product stance. Prefer it over improvising UX for “power users.”

## Core optimization

The whole product optimizes **time-to-first-scan** for beginners.

## Augustus 14-rule preflight

- Finish the Augustus **14-rule preflight evidence ladder** as **engine-side fail-closed** proofs.
- Continue Rules **8→14** as **pure-data evidence** only.
- Still **no** launcher / network / credentials / push unless Ted explicitly says so.

## Product surface (hard no)

- **Do NOT** build a complex advanced Augustus settings UI / 14 knobs.
- Ted: if someone is that professional, they should use **upstream Augustus** themselves.
- Product surface = **one simple path**:
  - starter defaults that already satisfy gates;
  - on reject, show **short human one-liners** (not rule essays).

## Contracts

- Still refuse incomplete exports.
- Do **not** loosen contracts for green builds or “ease.”
- Convenience = defaults that pass gates, **not** removing gates.

## Pointers

- Current engineering status: [`development-status.md`](development-status.md)
- Product behavior source of truth: [`product-spec.md`](product-spec.md)
