# Vendor Risk Screener

A local-first, buyer-side vendor contract risk reviewer. Paste an MSA, DPA, SaaS subscription terms, or vendor SOW → get a **0-100 buyer-friendliness score**, **40+ clause risk flags across 6 axes**, and **negotiation language** you can paste into a redline.

## Why this exists

Most contract review tools are written for the *vendor* — they help freelancers push harder on payment terms or scope. That's a real need, but it ignores the much larger group: **the people who are paying the vendor.**

If you're a procurement lead, IT security, head of legal ops, finance lead, or just the person who got handed "please review this SaaS contract" — you're reviewing for a different reason. You're looking for:

- Will our data end up somewhere we didn't approve?
- Can we exit cleanly if this vendor disappoints?
- Is the liability cap enough to actually recover from a breach?
- Are we locked in via auto-renewal / proprietary format / undocumented APIs?
- Is the SLA real, or is "commercially reasonable" the only commitment?

Vendor Risk Screener flips the lens. **It reviews from the buyer's side.**

## What it does

For any vendor contract (MSA, DPA, SaaS terms, vendor SOW, master services agreement with attached order form):

1. **Detects ~40 clause types** — DPA, breach notification, sub-processors, encryption, audit rights, price increase caps, SLA, IP infringement indemnity, liability cap, insurance, IP ownership, audit rights, SLA credits, auto-renewal, termination for convenience, transition assistance, data portability, confidentiality survival, force majeure carveouts, and more.
2. **Scores each clause's quality** for the buyer:
   - **buyer-friendly** — language that actually protects the buyer
   - **buyer-hostile** — language that looks like the clause is there but is written against the buyer
   - **present-but-ambiguous** — clause exists but language is vague or contradictory
   - **missing** — clause is silently absent
3. **6-axis scoring** with weights rebalanced by vendor type and contract value:
   - **Data governance** — DPA, breach notification, sub-processors, encryption, data residency, audit, return on termination (heavier for SaaS / data vendors)
   - **Commercial** — auto-renewal, price caps, payment terms, SLA, volume pricing
   - **Liability** — indemnification scope, liability cap, consequential-damages carveouts, insurance, IP infringement warranty, IP assignment (heavier for $1M+ contracts)
   - **Operational** — support response, change of control, service change notice, disaster recovery, acceptance criteria
   - **Exit** — termination for convenience, cure periods, transition assistance, data portability
   - **Governance** — warranties, compliance attestations, governing law, confidentiality, anti-bribery, non-solicit, background checks, force majeure
4. **0-100 overall score** with 5 verdict bands:
   - `ship_ready` ≥85 — sign it
   - `mostly_ready` ≥70 — light edits
   - `needs_polish` ≥55 — moderate redline
   - `tight_but_usable` ≥40 — heavy redline, walk-away risk
   - `needs_rework` <40 — don't sign as-is
5. **Per-clause negotiation language** — for every high/medium finding, you get a concrete redline phrase ready to paste back to the vendor.
6. **Top 3 negotiation asks** — the highest-leverage redlines surfaced first.
7. **Session history** with self-rating (1-5) and free-form notes — track how each contract actually went after the negotiation.
8. **Markdown + JSON export** for sharing with counsel or saving to your deal file.

## Tech stack

- **Backend:** Python 3 + Flask + SQLite (no external dependencies beyond Flask)
- **No API keys.** No LLM. Everything runs locally.
- **Frontend:** Vanilla HTML / CSS / JavaScript, dark UI

## How to run

```bash
# from inside the project directory
python3 -m venv .venv
source .venv/bin/activate
pip install flask

python3 app.py
# → http://127.0.0.1:5007
```

Then click **"Load buyer-hostile sample"** to see what a typical vendor MSA looks like when scanned.

## Endpoints

- `GET /` — UI
- `GET /api/health` — health check
- `GET /api/sample` — load a sample buyer-hostile contract for demo
- `POST /api/analyze` — analyze a contract (body: `contract_text`, `vendor_type`, `contract_value_band`, `brief`, optional `save`)
- `GET /api/sessions` — list recent sessions
- `GET /api/sessions/<id>` — get one session
- `PATCH /api/sessions/<id>` — update `self_rating` (1-5) or `notes`
- `GET /api/export/<id>?fmt=md|json` — export a session

## Different from existing tools

- `sow-forge` is the **freelancer reviewing a SOW they received** — vendor-side lens.
- `offer-letter-forge` is **employment offer review** (the candidate reviewing their own offer).
- `lease-decode` / `lease-renewal-comparator` / `closing-cost-cipher` are **residential lease review** — different contract shape entirely.

There was no buyer-side vendor / SaaS contract redliner. Vendor Risk Screener fills that gap: the procurement lead or IT security person reviewing a third-party MSA / DPA / SaaS subscription terms before signing.

## Limitations

- This is a triage tool, not a substitute for qualified legal review. The clause patterns and redline language are starting points — your counsel should still review any contract over $50K or with significant data exposure.
- Vendor contract language varies wildly. We catch the common patterns but won't catch every novel clause. Use the **buyer-hostile** and **missing** flags as a to-do list, not a final answer.
- No international-jurisdiction-specific clause coverage (e.g. UK-only deed execution, German commercial register requirements). US-leaning defaults.