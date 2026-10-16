"""
Vendor Risk Screener — local-first vendor / SaaS / supplier contract risk reviewer.

Paste a vendor agreement (MSA, DPA, SaaS subscription terms, vendor SOW) and get a
0-100 buyer-friendliness score, risk flags across ~40 clause types, missing-clause
detection, and negotiation language — but from the BUYER perspective (the
company engaging the vendor) rather than the freelancer / vendor side.

Flask + SQLite + vanilla JS, no API keys, no LLM.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "vendor_risk.db"

app = Flask(__name__, template_folder="templates", static_folder="static")


# ------------------------------------------------------------------ #
# Database
# ------------------------------------------------------------------ #
def get_db() -> sqlite3.Connection:
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
    return db


@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brief TEXT NOT NULL,
                contract_text TEXT NOT NULL,
                vendor_type TEXT,
                contract_value_band TEXT,
                analysis_json TEXT NOT NULL,
                overall_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                self_rating INTEGER,
                notes TEXT,
                created_at TEXT NOT NULL
            );
            """
        )


# ------------------------------------------------------------------ #
# Clause pattern library — 40+ clause types from the BUYER perspective
# ------------------------------------------------------------------ #
# Each clause has:
#   id, axis (one of 6 axes), severity_if_missing (default high),
#   patterns (regex list — if any matches, clause is PRESENT),
#   bad_phrases (regex list — present but unfavorable to buyer),
#   good_phrases (regex list — present and favorable to buyer),
#   description, fix (negotiation language), evidence_hint
#
# Axes: data_governance, commercial, liability, operational, exit, governance
#
# "good_phrases" outweighs "bad_phrases" if both present; if neither is found,
# the clause is flagged as MISSING.

CLAUSE_LIBRARY = [
    # ────────── DATA GOVERNANCE (data_handling, breach, sub-processors) ──────────
    {
        "id": "data_processing_addendum",
        "axis": "data_governance",
        "label": "Data Processing Addendum (DPA)",
        "severity": "high",
        "patterns": [
            r"\bdata processing addendum\b",
            r"\bDPA\b",
            r"\bdata processing agreement\b",
            r"\bGDPR Art\.?\s*28\b",
            r"\bCCPA\b",
        ],
        "bad_phrases": [r"\bvendor processes data as (a |an )?(independent )?controller\b"],
        "good_phrases": [
            r"\bprocessor (will|shall) process .* (only )?(on|for) (the )?(customer's|client's|company's) (documented )?instructions\b",
            r"\bstandard contractual clauses\b",
            r"\bDPA incorporated (by reference|herein)\b",
            r"\bGDPR Article 28\b",
        ],
        "description": "A DPA specifies how the vendor processes personal data on the buyer's behalf. Missing DPA means data roles (controller vs processor) and sub-processor approval flow are unclear.",
        "fix": "Attach a signed DPA referencing GDPR Art. 28 / CCPA service-provider language. Require the vendor to process only on your documented instructions and to flow down Art. 28 obligations to sub-processors.",
        "evidence_hint": "data processing",
    },
    {
        "id": "breach_notification_window",
        "axis": "data_governance",
        "label": "Security breach notification window",
        "severity": "high",
        "patterns": [r"\bbreach notification\b", r"\bsecurity incident\b", r"\bdata (incident|breach)\b"],
        "bad_phrases": [
            r"\b(unduly|without undue delay)\b",
            r"\bno later than \d{2,3} (business )?days\b",
        ],
        "good_phrases": [
            r"\bwithin (24|48|72) hours?\b",
            r"\bwithout undue delay and in any event within (24|48|72) hours\b",
            r"\bimmediately (and in any event within \d+ hours)\b",
        ],
        "description": "Vendors commonly commit to \"without undue delay\" (≥7 days) which is too slow for GDPR's 72-hour clock. Push for ≤72 hours and clear severity tiering.",
        "fix": "Tighten to 'within 72 hours of discovery, with an initial status update within 24 hours for confirmed Category 1 incidents.' Add definition of 'discovery' that includes the vendor's sub-processors.",
        "evidence_hint": "breach",
    },
    {
        "id": "sub_processor_approval",
        "axis": "data_governance",
        "label": "Sub-processor approval & list",
        "severity": "high",
        "patterns": [r"\bsub-?processor\b", r"\bsubcontractor.* (data|process)"],
        "bad_phrases": [
            r"\bvendor (may|reserves the right to) (engage|use) .*sub-?processors?\b",
            r"\blist (will be|of) (made )?available (upon|on) request\b",
        ],
        "good_phrases": [
            r"\b(list of |current )sub-?processors? (is |will be )(published|posted) (at|on)\b",
            r"\b(customer|client) (may |shall have the right to )?(object|approve) (to )?new sub-?processors?\b",
            r"\b(15|30|45) days? (prior |advance )?notice (for|of) new sub-?processors?\b",
        ],
        "description": "Without prior-notice + right-to-object on sub-processors, the vendor can quietly shift data to weaker jurisdictions or cheaper providers.",
        "fix": "Require (a) a published sub-processor list URL, (b) ≥30 days prior notice for new sub-processors, (c) right to object with termination-for-convenience trigger if objection unresolved.",
        "evidence_hint": "sub-processor",
    },
    {
        "id": "data_location_restriction",
        "axis": "data_governance",
        "label": "Data residency / location restriction",
        "severity": "medium",
        "patterns": [r"\bdata (residency|location|sovereignty)\b", r"\bdata (will|shall) (be )?stored .* in\b"],
        "bad_phrases": [
            r"\bworldwide\b",
            r"\bglobally\b",
            r"\bany (region|country|jurisdiction) vendor (selects|chooses)\b",
        ],
        "good_phrases": [
            r"\bdata (will|shall) (be )?(stored|processed|hosted) (only )?in (the )?(United States|EU|EEA|US|UK)\b",
            r"\bregion (selection|lock|opt) (at|in)\b",
            r"\bcustomer (may |can )?select (the )?(data )?(region|geography)\b",
        ],
        "description": "If the contract is silent on data location, the vendor can move data to a weaker jurisdiction overnight. Pin the region and add a change-of-region notice trigger.",
        "fix": "Pin data residency to a specific region (e.g. 'US, EU, or customer-selected region'). Require 90-day prior notice + right to terminate for any cross-region transfer.",
        "evidence_hint": "data residency",
    },
    {
        "id": "data_return_on_termination",
        "axis": "data_governance",
        "label": "Data return / deletion on termination",
        "severity": "high",
        "patterns": [
            r"\bdata (return|deletion|deletion|portability)\b",
            r"\b(end of|upon) termination\b.*\b(data|deletion)\b",
        ],
        "bad_phrases": [
            r"\bafter (90|180|365) days?\b",
            r"\bvendor (may|reserves the right to) retain .* (data|backups?) indefinitely\b",
        ],
        "good_phrases": [
            r"\bwithin (30|60|90) days? (of|after) termination\b.*\b(delete|return|destroy)\b",
            r"\bcustomer's (sole )?(discretion|option) .* (return|deletion)\b",
            r"\bmachine-?readable (format|export)\b",
        ],
        "description": "Many vendors bury deletion windows in their terms (often 'as required by law') — leaving your data on their backups for years.",
        "fix": "Require: (a) export in machine-readable format (JSON/CSV/Parquet) within 30 days of termination, (b) deletion within 60 days of termination, (c) written certification of deletion upon request.",
        "evidence_hint": "data return",
    },
    {
        "id": "encryption_at_rest_in_transit",
        "axis": "data_governance",
        "label": "Encryption at rest & in transit",
        "severity": "high",
        "patterns": [
            r"\bencryption (at rest|in transit)\b",
            r"\bTLS 1\.\d\b",
            r"\bAES-?\d{2,3}\b",
        ],
        "bad_phrases": [r"\bvendor (may|reserves the right to) (use|select) .* encryption (at its|of its) (sole )?discretion\b"],
        "good_phrases": [
            r"\bAES-256\b.*\bat rest\b",
            r"\bTLS 1\.[23]\b.*\bin transit\b",
            r"\bFIPS 140-?2\b",
            r"\bcustomer-?managed (encryption )?keys?\b",
            r"\bBYOK\b",
        ],
        "description": "Vague 'industry-standard encryption' language lets vendors downgrade to weaker ciphers. Pin the cipher suite and key custody.",
        "fix": "Pin 'AES-256 at rest, TLS 1.2+ in transit, FIPS 140-2 validated modules.' Add 'customer-managed keys' or 'BYOK' for any regulated data.",
        "evidence_hint": "encryption",
    },
    {
        "id": "audit_rights",
        "axis": "data_governance",
        "label": "Audit rights (SOC 2 / ISO / on-site)",
        "severity": "medium",
        "patterns": [r"\baudit (rights?|reports?)\b", r"\bSOC 2\b", r"\bISO 27001\b"],
        "bad_phrases": [
            r"\bonly (upon|with) (prior )?(written )?request .* (30|45|60) days?\b",
            r"\bvendor's (sole )?discretion\b.*\baudit\b",
        ],
        "good_phrases": [
            r"\bSOC 2 Type II\b.*\bannually\b",
            r"\bright to (audit|inspect) (on (reasonable )?notice|with \d+ days? notice)\b",
            r"\bpenetration test (summary|results) (annually|on request)\b",
        ],
        "description": "Many contracts bury audit rights behind 'upon reasonable request' plus 30+ day notice, or only allow review of 'current' SOC 2 summaries.",
        "fix": "Require: (a) annual SOC 2 Type II report delivery on request, (b) on-site audit right with ≤14 days notice (≤1× per year), (c) prompt remediation of any material exceptions.",
        "evidence_hint": "audit",
    },

    # ────────── COMMERCIAL (pricing, payment, renewals, price changes) ──────────
    {
        "id": "auto_renewal_terms",
        "axis": "commercial",
        "label": "Auto-renewal & notice-to-cancel",
        "severity": "high",
        "patterns": [
            r"\bauto(matic)?-?renew(al)?\b",
            r"\brenew(s|ed|al)? automatically\b",
            r"\bautomatically (renewed?|extended?|continued?)\b",
        ],
        "bad_phrases": [
            r"\bauto(matic)?-?renew.* (30|45|60|90) days? (prior |advance )?(written )?notice\b",
            r"\bterm (will|shall) (be )?(automatically )?renewed\b.*\bunless (either|written) notice\b",
            r"\bautomatically (renewed?|extended?)\b.*\b(30|45|60|90) days? (prior |advance )?(written )?notice\b",
            r"\bautomatically renew(ed)?\b.*\b\d+ days? (prior |advance )?(written )?notice\b",
        ],
        "good_phrases": [
            r"\b(opt (in|out) of|election to (renew|terminate))? .* (60|90) days?\b",
            r"\bno auto(matic)?-?renew(al)?\b",
            r"\brenew(s|al)? (only|requires) .* (mutual|written) (consent|agreement)\b",
            r"\bshall not auto(matic)?ally renew\b",
            r"\b(renewal|renew) (requires?|only with) (mutual|written|affirmative) (consent|consent|agreement)\b",
        ],
        "description": "Auto-renewal clauses with 30-60 day notice windows silently extend contracts for 12+ months. Many teams miss the deadline and get locked in for another year.",
        "fix": "Either remove auto-renewal entirely or extend the notice window to ≥90 days AND require affirmative opt-in for renewal. Add a calendar reminder for the notice deadline.",
        "evidence_hint": "auto-renewal",
    },
    {
        "id": "price_increase_cap",
        "axis": "commercial",
        "label": "Annual price increase cap",
        "severity": "medium",
        "patterns": [r"\bprice (increase|escalat|adjust|chang)\b", r"\b(increase|adjust) (prices?|fees)\b", r"\bCPI\b", r"\bannual (price )?adjustment\b"],
        "bad_phrases": [
            r"\bvendor (may|reserves the right to) (increase|adjust) (prices|fees) (at any time|from time to time)\b",
            r"\b(sole|absolute) discretion .* price(s| change)?\b",
        ],
        "good_phrases": [
            r"\b(capped? at|limited to|not to exceed) (the lesser of .* )?(CPI|3%|5%|7%)\b",
            r"\bno (more than|increase (greater than)) \d+%\b",
            r"\bprice (increase|escalation) .* (90|120|180) days? (prior |advance )?notice\b",
            r"\b(capped at|limited to) .* (CPI|3%|5%|7%)\b",
            r"\b(increase|adjust) .* (capped at|limited to) .* (CPI|3%|5%|7%)\b",
            r"\b(upon|with) (90|120|180) days? notice\b.*\b(capped|increase)\b",
        ],
        "description": "Open-ended price-change rights mean your SaaS bill can jump 20-40% at renewal. Pin the cap and require lead time.",
        "fix": "Cap annual increases at the lesser of CPI or 5%, with ≥90 days prior written notice. Lock pricing for any committed-spend or multi-year term.",
        "evidence_hint": "price increase",
    },
    {
        "id": "payment_terms_buyer",
        "axis": "commercial",
        "label": "Payment terms (Net-30 / Net-60 / Net-90)",
        "severity": "medium",
        "patterns": [r"\b(net|due) (15|30|45|60|90)\b", r"\bpayment (terms|due)\b"],
        "bad_phrases": [
            r"\bdue (on|upon) (receipt|delivery|invoice)\b",
            r"\bnet 7\b",
            r"\badvance (payment|prepay)\b",
        ],
        "good_phrases": [
            r"\bnet (30|45|60)\b",
            r"\bdue (within|net) (30|45|60) days? (of|after) (invoice|receipt)\b",
            r"\b2%\s*/\s*\d+ (net \d+)?\b",
        ],
        "description": "Net-7 or 'due on receipt' is buyer-hostile. Net-30 is standard; Net-60 is typical for enterprise procurement.",
        "fix": "Negotiate Net-45 minimum. Add a '2/10 Net-30' discount if cash flow permits. Push back on 'due on receipt' — it's an AP nightmare.",
        "evidence_hint": "payment terms",
    },
    {
        "id": "sla_credits",
        "axis": "commercial",
        "label": "SLA credits & service levels",
        "severity": "high",
        "patterns": [
            r"\bSLA\b",
            r"\bservice level (agreement|commitment|objective)\b",
            r"\buptime (guarantee|commitment)\b",
        ],
        "bad_phrases": [
            r"\bSLA (credits|remedies?) (are|is) (your |customer's )?(sole|exclusive) remedy\b",
            r"\b(best efforts|commercially reasonable efforts) .* uptime\b",
            r"\bno (warranty|guarantee) (of|as to) uptime\b",
        ],
        "good_phrases": [
            r"\b(99\.[5-9]|99\.9)% (uptime|availability)\b",
            r"\b(service credits?|SLA credits?) (of|equal to) \d+%\b",
            r"\bright to (terminate|withdraw) .* (sustained|repeated) (SLA |uptime )?(breach|failure)\b",
        ],
        "description": "Vague SLA language ('commercially reasonable uptime') with 'sole remedy' clauses means the vendor gets paid even when the service is down.",
        "fix": "Require: (a) ≥99.9% uptime with measurable definition, (b) tiered credits (10-30% of monthly fee), (c) right to terminate for cause after sustained breach (e.g. <99% over 2 months).",
        "evidence_hint": "SLA",
    },
    {
        "id": "expense_pass_through",
        "axis": "commercial",
        "label": "Expense / pass-through cost controls",
        "severity": "low",
        "patterns": [
            r"\bexpenses?\b.*\b(reimburs|pass.?through|invoic)\b",
            r"\b(out.?of.?pocket|pass.?through) (costs?|expenses?)\b",
        ],
        "bad_phrases": [
            r"\ball (reasonable|necessary) (out.?of.?pocket|pass.?through) (costs?|expenses?) (will be|invoiced|reimbursed)\b",
            r"\bvendor (may|reserves the right to) (incur|take on) .* expenses\b",
        ],
        "good_phrases": [
            r"\bexpenses? (capped?|limited to|not to exceed) (\\$|USD|EUR)?\s?\d{1,3}(,\d{3})*\b",
            r"\bprior (written )?(approval|consent) .* (any |each )?expense\b",
            r"\b(invoice|reimburs(e|ement)) .* (with|and) (itemized|receipts)\b",
        ],
        "description": "Open-ended expense pass-throughs turn a fixed-fee engagement into a blank check. Require caps, prior approval, and itemized receipts.",
        "fix": "Cap expenses at a fixed dollar amount or a percentage of fees. Require itemized receipts and prior written approval for any expense over a small threshold (e.g. $250).",
        "evidence_hint": "expenses",
    },
    {
        "id": "volume_discount_buyer",
        "axis": "commercial",
        "label": "Volume / multi-year discount",
        "severity": "low",
        "patterns": [r"\bvolume (discount|tier)\b", r"\bmulti.?year (discount|commitment)\b"],
        "bad_phrases": [
            r"\bno (discount|preferential) (pricing|rates?)\b",
            r"\b(as reflected|set forth) (in|on) (the )?(then-?current )?price (list|book)\b",
        ],
        "good_phrases": [
            r"\b(\d+%|tiered|step) discount (on|for) .* (volume|committed spend|annual)\b",
            r"\b(free|complimentary) (seat|user|license) (above|over|after) \d+\b",
        ],
        "description": "Lock in tiered discounts up front — the vendor is unlikely to volunteer them at renewal time once you're a captive customer.",
        "fix": "Negotiate tiered volume discounts (e.g. 5% over $50K, 10% over $100K). For multi-year commits, demand 15-25% off list AND price protection across the term.",
        "evidence_hint": "volume discount",
    },

    # ────────── LIABILITY (indemnification, limitation, insurance, IP) ──────────
    {
        "id": "indemnification_scope",
        "axis": "liability",
        "label": "Indemnification scope (IP / data / bodily)",
        "severity": "high",
        "patterns": [
            r"\bindemnif(y|ication|ies)\b",
            r"\bdefend,? indemnify,? (and )?hold harmless\b",
        ],
        "bad_phrases": [
            r"\bvendor (will|shall) indemnify (only |solely )(to the extent|arising from)\b",
            r"\bcapped at .* (liability cap|aggregate)\b.*\bindemnif(y|ies)\b",
        ],
        "good_phrases": [
            r"\bindemnif(y|ication) .* (third-?party (claim|IP infringement)|(data|security) breach|breach of (confidentiality|warranty))\b",
            r"\bdefend against .* (IP|intellectual property) (infringement|claims?)\b",
            r"\b(indemnification|indemnity) (is |shall not be )?(subject to |limited by )?liability cap\b",
        ],
        "description": "A weak indemnity only covers direct damages from vendor negligence and is capped at the contract value. Strong indemnities cover IP infringement, data breach, and bodily injury uncapped.",
        "fix": "Require broad indemnity (IP / data breach / confidentiality / bodily injury / property damage) WITHOUT being subject to the liability cap. Add control-of-defense and settlement-consent clauses.",
        "evidence_hint": "indemnify",
    },
    {
        "id": "liability_cap",
        "axis": "liability",
        "label": "Limitation of liability cap",
        "severity": "high",
        "patterns": [
            r"\blimitation of liability\b",
            r"\bliabilit(y|ies) (cap|capped|limited)\b",
            r"\baggregate liabilit(y|ies)\b",
        ],
        "bad_phrases": [
            r"\baggregate liabilit(y|ies) (will not|shall not) exceed (the )?(fees? paid|last (3|6|12) months)\b",
            r"\b(in no event|aggregate) .* (exceed|greater than) (\\$|USD)?\s?\d{1,3}(,\d{3})?\b",
        ],
        "good_phrases": [
            r"\b(2x|3x|2\.0x|3\.0x) (annual |aggregate )?fees\b",
            r"\bno (cap|limit) (on|for) .* (data breach|IP infringement|confidentiality|indemnification)\b",
            r"\b(super-?cap|additional cap) (of|equal to) \d+x (annual )?fees\b",
            r"\b(2|3|4|5)x (annual )?fees\b.*\b(data breach|IP infringement|confidentiality|indemnification)\b",
        ],
        "description": "A 12-months-of-fees liability cap leaves you exposed for catastrophic vendor failures. Negotiate a super-cap (2-3x) for data breach / IP / indemnity claims.",
        "fix": "Cap general liability at 2x annual fees; create a super-cap of 3-5x annual fees (uncapped for IP infringement, data breach, confidentiality breach, and gross negligence). Carve out fraud from any cap.",
        "evidence_hint": "liability cap",
    },
    {
        "id": "consequential_damages_waiver",
        "axis": "liability",
        "label": "Consequential damages waiver carveouts",
        "severity": "medium",
        "patterns": [
            r"\bconsequential damages?\b",
            r"\b(indirect|incidental|special|punitive) damages?\b",
        ],
        "bad_phrases": [
            r"\b(neither party .* liable for|waives?) .* consequential damages?\b",
            r"\bin no event .* (any |all )?(indirect|consequential|special|punitive) damages\b",
        ],
        "good_phrases": [
            r"\b(carve.?out|exception (to|for)) .* (breach of confidentiality|data breach|IP infringement|indemnification)\b",
            r"\bnotwithstanding .* (consequential damages|waiver),? .* (breach of confidentiality|data breach)\b",
        ],
        "description": "Mutual consequential-damages waivers without carveouts for data breach / IP infringement leave the buyer with no recovery for the actual harm (lost customers, IP loss).",
        "fix": "Add carveouts so the consequential-damages waiver does NOT apply to: breach of confidentiality, data breach, IP infringement, indemnification obligations, and gross negligence / willful misconduct.",
        "evidence_hint": "consequential damages",
    },
    {
        "id": "insurance_coverage",
        "axis": "liability",
        "label": "Insurance (cyber, E&O, GL, workers' comp)",
        "severity": "high",
        "patterns": [
            r"\binsurance\b",
            r"\bcyber (liability|insurance)\b",
            r"\bE&O\b|\berrors? .* omissions?\b",
        ],
        "bad_phrases": [
            r"\b(commercially reasonable|appropriate) (insurance|coverage)\b",
            r"\binsurance (amounts?|coverage) .* (sole|absolute) discretion\b",
        ],
        "good_phrases": [
            r"\bcyber (liability )?(insurance|coverage) (of|not less than) (\\$|USD)?\s?[1-9]\d{6,}\b",
            r"\b(commercial general liability|CGL|workers\\'\'? comp(ensation)?|E&O)\b.*\d{1,3}(,\d{3}){2,}\b",
            r"\bcustomer (named|listed) as (an )?(additional )?insured\b",
            r"\bcertificate of insurance (provided|furnished) (annually|on request)\b",
        ],
        "description": "Vague 'commercially reasonable insurance' means $1M of cyber coverage — useless for a $10M breach. Pin the minimums by line of coverage.",
        "fix": "Pin minimums: Cyber ≥$5M, E&O ≥$5M, CGL ≥$2M, Workers' Comp at statutory minimums. Require customer as additional insured and annual COI delivery.",
        "evidence_hint": "insurance",
    },
    {
        "id": "ip_infringement_warranty",
        "axis": "liability",
        "label": "IP infringement warranty & remedy",
        "severity": "high",
        "patterns": [r"\bIP (infringement|indemnification|warranty)\b", r"\bintellectual property (infringement|warranty)\b"],
        "bad_phrases": [
            r"\bvendor (does not|warrants? that it does not) infringe (third-?party )?IP\b.*\bsolely to the extent\b",
            r"\bremed(y|ies) (for IP|for infringement) (is|are) (limited to|capped at)\b",
        ],
        "good_phrases": [
            r"\bvendor (will|shall) (defend|indemnify) .* (against|for|from) .* (third-?party )?IP (claims?|infringement)\b",
            r"\b(defend|indemnify) .* (third-?party )?IP (claims?|infringement)\b",
            r"\b(procure |obtain )?right for (customer|client) to (continue )?(use|access)\b.*\binfringe(ment)?\b",
            r"\breplace .* (with |non-?infringing )?functional equivalent\b",
            r"\bdefend,? indemnify,? .* (third-?party )?IP (claims?|infringement)\b",
        ],
        "description": "A 'we don't knowingly infringe' warranty is buyer-hostile. Demand defense + indemnity + a clear remedy ladder (procure license → modify → refund).",
        "fix": "Require: (a) defense of any third-party IP claim, (b) procurement of a license, modification to non-infringing, OR refund of prepaid fees + termination right. Carve from liability cap.",
        "evidence_hint": "IP infringement",
    },
    {
        "id": "ip_assignment_to_buyer",
        "axis": "liability",
        "label": "IP ownership / work product assignment",
        "severity": "high",
        "patterns": [
            r"\b(intellectual property|IP)\b.*\b(ownership|assignment)\b",
            r"\bwork (made |performed )?for hire\b",
            r"\bwork product\b",
            r"\bdeliverables?\b.*\b(ownership|property|assignment)\b",
        ],
        "bad_phrases": [
            r"\bvendor (retains|owns) .* (all )?(IP|intellectual property|right,? title)\b",
            r"\bcustomer (receives|is granted) (a |an )?(non-?exclusive|revocable) license\b",
            r"\bbackground IP\b.*\bvendor (owns|retains)\b",
            r"\bnon-?exclusive\b.*\b(license|right) .* (work product|deliverables?|use)\b",
        ],
        "good_phrases": [
            r"\b(sole|exclusive) property of (customer|client)\b",
            r"\b(assignment|transfer) of (all |any )?IP (rights?|title|interest)\b.*\b(customer|client)\b",
            r"\bfull assignment of .* (work product|deliverables?|IP)\b",
            r"\bassigns? (all )?(IP|right,? title|work product|deliverables?) (to|hereunder)\b",
            r"\b(customer|client) (shall own|owns) (all|the) (right,? title|work product|deliverables?)\b",
        ],
        "description": "Many vendor contracts leave IP ownership ambiguous or only grant a license — meaning the buyer cannot freely modify, port, or hand off the work.",
        "fix": "Require full assignment of all work product / deliverables to the buyer. Carve out pre-existing 'background IP' but require a perpetual license back to buyer. Add moral-rights waiver.",
        "evidence_hint": "IP ownership",
    },

    # ────────── OPERATIONAL (service levels, support, change control) ──────────
    {
        "id": "support_response",
        "axis": "operational",
        "label": "Support response / resolution times",
        "severity": "medium",
        "patterns": [
            r"\bsupport (response|resolution) (time|sla)\b",
            r"\b(response|resolution) time\b",
            r"\bSeverity (1|one|two|2|three|3|four|4)\b",
        ],
        "bad_phrases": [
            r"\b(best efforts|commercially reasonable) .* (response|support)\b",
            r"\bvendor (will|shall) respond (within )?(a |reasonable )?(timeframe|period)\b",
        ],
        "good_phrases": [
            r"\bSeverity 1\b.*\bwithin (1|2|4) (hour|hours|business hour)\b",
            r"\b(24/7|twenty.?four.?seven) (support|coverage)\b.*\b(response|critical)\b",
            r"\b(initial response|acknowledgment) within \d+ (minutes?|hours?)\b",
        ],
        "description": "Vague 'reasonable support response' means the vendor triages at the lowest priority. Pin response and resolution times by severity tier.",
        "fix": "Pin by severity: Sev1 = 1-hour response / 4-hour resolution, Sev2 = 4-hour response / 1-day resolution, Sev3 = 1-business-day response / 5-day resolution. Include 24/7 coverage for Sev1.",
        "evidence_hint": "support response",
    },
    {
        "id": "change_of_control",
        "axis": "operational",
        "label": "Change of control / assignment notice",
        "severity": "medium",
        "patterns": [
            r"\bchange of control\b",
            r"\b(assignment|transfer) (of (this )?(agreement|contract))\b",
            r"\b(merger|acquisition|sale of (substantially all ))\b",
        ],
        "bad_phrases": [
            r"\b(either party may) assign (or transfer) (this )?agreement (without consent|freely)\b",
            r"\bno (notice|consent) (required )?for (assignment|change of control)\b",
        ],
        "good_phrases": [
            r"\b(notice|consent) (required|of (customer|client)) .* (assignment|change of control|merger|acquisition)\b",
            r"\bright to (terminate|withdraw) .* (assignment|change of control) (to a competitor)?\b",
            r"\bprior (written )?(notice|consent) (of|for) .* assignment\b",
        ],
        "description": "Silent assignment clauses mean the vendor can sell to a competitor or to a firm in a sanctioned country with zero notice. Lock assignment rights.",
        "fix": "Require prior written notice (≥30 days) of any change of control or assignment. Reserve right to terminate if the acquirer is a direct competitor or sanctioned entity.",
        "evidence_hint": "change of control",
    },
    {
        "id": "service_change_notice",
        "axis": "operational",
        "label": "Service-change / deprecation notice",
        "severity": "medium",
        "patterns": [r"\b(change|deprecat|end of life|EOL) (notice|notification)\b", r"\bsubstantial (change|modification) (to (the )?service)"],
        "bad_phrases": [
            r"\bvendor (may|reserves the right to) (modify|change) .* (service|features) (at any time|from time to time)\b",
            r"\b(discontinue|deprecate) .* (sole|absolute) discretion\b",
        ],
        "good_phrases": [
            r"\b(90|120|180) days? (prior |advance )?(written )?notice .* (change|deprecation|discontinu)\b",
            r"\bsubstantive (changes?|modifications) (to (the )?service) (require|with) \d+ days? notice\b",
            r"\bright to (terminate|withdraw) (without penalty) .* (substantial|material) (change|deprecation)\b",
        ],
        "description": "Vendors can quietly sunset features or change APIs with 30-day notice. Push the notice window to 90-180 days for substantive changes.",
        "fix": "Require ≥180 days notice for any substantive change (especially API breaks, feature removal, infrastructure migration). Right to terminate without penalty if changes are material.",
        "evidence_hint": "service change",
    },
    {
        "id": "disaster_recovery",
        "axis": "operational",
        "label": "Disaster recovery / business continuity",
        "severity": "medium",
        "patterns": [
            r"\bdisaster recovery\b",
            r"\bbusiness continuity\b",
            r"\bDR (plan|test)\b",
            r"\bRTO\b|\bRPO\b",
        ],
        "bad_phrases": [
            r"\b(commercially reasonable|industry standard) .* (DR|disaster recovery|business continuity)\b",
            r"\bno (specific|defined) (RTO|RPO|recovery (time|point) (objective|target))\b",
        ],
        "good_phrases": [
            r"\bRTO (of|≤|less than or equal to) \d+ (hours?|days?)\b",
            r"\bRPO (of|≤|less than or equal to) \d+ (minutes?|hours?)\b",
            r"\bannual (DR|business continuity) (test|exercise) (results?|report)\b",
        ],
        "description": "Vague 'industry-standard DR' can mean days of downtime. Pin Recovery Time / Recovery Point Objective numbers and require annual DR test reports.",
        "fix": "Pin RTO ≤4 hours, RPO ≤1 hour for production workloads. Require annual DR test results and prompt notification of any RTO/RPO misses.",
        "evidence_hint": "disaster recovery",
    },
    {
        "id": "performance_benchmark",
        "axis": "operational",
        "label": "Performance benchmarks / acceptance",
        "severity": "medium",
        "patterns": [
            r"\bperformance (benchmark|metric|criteria)\b",
            r"\bacceptance (criteria|test|period)\b",
        ],
        "bad_phrases": [
            r"\b(acceptance|sign.?off) .* (sole|absolute) discretion\b",
            r"\bno (acceptance|review) (period|criteria)\b",
        ],
        "good_phrases": [
            r"\bacceptance (period|criteria|window) of \d+ (business )?days?\b",
            r"\b(written )?(acceptance|sign-?off) (deemed|considered) .* \d+ days? (after|of) (delivery|completion)\b",
            r"\bright to (withhold|reduce) (payment|fee) .* (non-conforming|deliverable)\b",
        ],
        "description": "Without a defined acceptance window, you can be deemed to have accepted deliverables by silence — and lose leverage to require rework.",
        "fix": "Define acceptance criteria in writing. Specify a 10-15 business day acceptance window with explicit pass/fail criteria. Deemed acceptance ONLY after written confirmation.",
        "evidence_hint": "acceptance",
    },

    # ────────── EXIT (termination, transition, data return) ──────────
    {
        "id": "termination_for_convenience",
        "axis": "exit",
        "label": "Termination for convenience",
        "severity": "high",
        "patterns": [
            r"\btermination for convenience\b",
            r"\bterminate (this )?agreement (at any time|for any reason)\b",
        ],
        "bad_phrases": [
            r"\bno termination for convenience\b",
            r"\btermination for convenience .* (full )?(remaining|unpaid) (fees?|balance)\b",
            r"\bterminate (this )?agreement only (for cause|upon material breach)\b",
        ],
        "good_phrases": [
            r"\b(customer|client) may terminate (this )?agreement (at any time|for convenience|without cause) (upon |with )\d+ days? (written )?notice\b",
            r"\btermination (fee|cost) (limited to|capped at|of) \d+ (months?|%) of (annual )?fees\b",
            r"\bfor (convenience|any reason|any or no reason)\b.*\b\d+ days? (written )?notice\b",
            r"\bmay terminate (this )?agreement (at any time|for (convenience|any reason))\b",
        ],
        "description": "If termination for convenience is missing or punitive (full remaining fees), you cannot exit a failing vendor without litigation. Negotiate for a clean exit.",
        "fix": "Add a termination-for-convenience right with ≤90 days notice. Cap any termination fee at ≤3 months of fees (or a fixed dollar amount). Pair with transition obligations.",
        "evidence_hint": "termination for convenience",
    },
    {
        "id": "termination_for_cause_buyer",
        "axis": "exit",
        "label": "Termination for cause + cure period",
        "severity": "high",
        "patterns": [
            r"\btermination for (cause|material breach)\b",
            r"\bmaterial breach\b.*\b(terminate|cure)\b",
            r"\bcure period\b",
        ],
        "bad_phrases": [
            r"\b(cure period|right to cure) .* (sole|absolute) discretion\b",
            r"\b(sole|absolute) discretion .* (deem|determine) (material breach)\b",
        ],
        "good_phrases": [
            r"\b(cure period|right to cure) of \d+ (days?|business days?) (after|following) (notice|breach)\b",
            r"\b(customer|client) (may|shall have the right to) terminate .* (without )?(further )?notice .* (uncured|material breach)\b",
            r"\b(supersede|overrides?) (any|the) cure period .* (data|security|breach)\b",
        ],
        "description": "Vague cure-period language lets the vendor drag out remediation. Pin cure days and allow no-cure termination for security breaches / willful misconduct.",
        "fix": "Standard cure period: 30 days for general breach, 15 days for payment breach, ZERO days (no cure) for security breach, confidentiality breach, willful misconduct, or insolvency.",
        "evidence_hint": "termination for cause",
    },
    {
        "id": "transition_assistance",
        "axis": "exit",
        "label": "Transition assistance (off-boarding / migration)",
        "severity": "high",
        "patterns": [
            r"\btransition (assistance|period|support)\b",
            r"\boff-?boarding\b",
            r"\bmigration (assistance|support)\b",
        ],
        "bad_phrases": [
            r"\bno (further |additional )(assistance|support) (after|post|following) termination\b",
            r"\b(discretionary|sole discretion) .* (transition|migration) (assistance|support)\b",
        ],
        "good_phrases": [
            r"\b\d+ (to \d+ )?(days?|months?) (of )?transition (assistance|support) (included|in the (fees|price))\b",
            r"\b(at|then-?current) (rates?|fees) .* (transition|migration|off.?boarding) (services?|assistance)\b",
            r"\bknowledge transfer (plan|sessions?) (within|at end of) transition period\b",
        ],
        "description": "Without a transition-assistance clause, the vendor can refuse to help you migrate off their platform — a classic lock-in tactic.",
        "fix": "Require ≥90 days of transition assistance included in fees (with optional extension at then-current rates). Include knowledge transfer, documentation handover, and export tooling.",
        "evidence_hint": "transition",
    },
    {
        "id": "no_vendor_lockin",
        "axis": "exit",
        "label": "No-vendor-lock-in / data portability",
        "severity": "high",
        "patterns": [
            r"\b(no vendor lock-?in|interoperability|data portability|open formats)\b",
            r"\bstandard (format|protocol|API)\b",
        ],
        "bad_phrases": [
            r"\b(proprietary|format) (exclusively|only) .* available .* vendor\b",
            r"\b(no|not) .* (data |information )?portability\b",
        ],
        "good_phrases": [
            r"\b(open|standard|machine-?readable) (formats?|protocols?|APIs?)\b",
            r"\bdata export (in|using) (CSV|JSON|XML|Parquet|standard)\b",
            r"\b(publicly )?documented (API|interfaces?) (for |to enable )?(data )?(export|portability)\b",
        ],
        "description": "Proprietary formats / undocumented APIs trap the buyer. Lock in open formats and documented export paths.",
        "fix": "Require export in open formats (CSV / JSON / Parquet) via documented APIs. Prohibit 'unreasonable' restrictions on bulk export. Add format-conversion support during transition.",
        "evidence_hint": "vendor lock-in",
    },

    # ────────── GOVERNANCE (warranty, compliance, dispute) ──────────
    {
        "id": "warranty_disclaimer",
        "axis": "governance",
        "label": "Warranty (fitness / merchantability / conformance)",
        "severity": "medium",
        "patterns": [
            r"\bwarrant(y|ies)\b",
            r"\b(disclaim(s|er)|as-?is|as is)\b.*\b(warrant(y|ies)|fitness|merchantability)\b",
        ],
        "bad_phrases": [
            r"\b(disclaim(s|er)|excludes?) (all|other) (warrant(y|ies)|representations)\b",
            r"\b(as.?is|as is) .* (all )?(warrant(y|ies)|fitness|merchantability)\b",
            r"\bno (warrant(y|ies)|guarantee) .* (fitness|merchantability|non-?infringement)\b",
        ],
        "good_phrases": [
            r"\b(express|implied) warrant(y|ies) (of|for) (merchantability|fitness|non-?infringement|conformance)\b",
            r"\bservice (will|shall) conform .* (material )?specifications?\b",
            r"\bvendor (warrants?|represents?) (that|its service) (will|conforms)\b",
        ],
        "description": "An 'as-is, all warranties disclaimed' clause leaves the buyer with no recourse for substandard deliverables. Retain key warranties.",
        "fix": "Preserve warranties of merchantability, fitness for purpose, non-infringement, and conformance to specifications. Add a conformance remedy (rework → refund → termination).",
        "evidence_hint": "warranty",
    },
    {
        "id": "compliance_attestations",
        "axis": "governance",
        "label": "Compliance attestations (SOC2, ISO27001, PCI, HIPAA)",
        "severity": "high",
        "patterns": [
            r"\bSOC (2|II)\b",
            r"\bISO 27001\b",
            r"\bHIPAA\b",
            r"\bPCI.?DSS?\b",
            r"\bFedRAMP\b",
        ],
        "bad_phrases": [
            r"\b(vendor|provider) (will use|shall use) (commercially reasonable|appropriate) (security|controls)\b",
            r"\bno (specific )?(compliance|attestation|certification) (required|committed)\b",
        ],
        "good_phrases": [
            r"\bSOC 2 Type II\b.*\bannually|furnished (annually|on request)\b",
            r"\b(maintain|currently holds?) (SOC 2 Type II|ISO 27001|HIPAA|PCI DSS|FedRAMP)\b",
            r"\bprompt(ly)? (notify|notify the customer) .* (compliance|attestation|certification) (change|status|withdrawal)\b",
        ],
        "description": "Vague security language is a regulatory red flag. Pin the certifications the vendor must maintain and require prompt notice of any withdrawal.",
        "fix": "Require SOC 2 Type II (or appropriate) certification maintained throughout the term. Require prompt notice (≤30 days) of any withdrawal, lapse, or material finding.",
        "evidence_hint": "compliance",
    },
    {
        "id": "governing_law",
        "axis": "governance",
        "label": "Governing law / venue / arbitration",
        "severity": "medium",
        "patterns": [
            r"\bgoverning law\b",
            r"\bgoverned by (the )?laws? of\b",
            r"\bjurisdiction\b",
            r"\bvenue\b",
            r"\barbitration\b",
        ],
        "bad_phrases": [
            r"\bgoverned by (the )?laws? of .* (foreign|offshore|unfamiliar) jurisdiction\b",
            r"\barbitration (in|at) .* (foreign|offshore)\b",
            r"\bgoverned by (the )?laws? of (Singapore|Hong Kong|Cayman|BVI|British Virgin Islands)\b",
        ],
        "good_phrases": [
            r"\bgoverned by (the )?laws? of (the )?(State of (Delaware|New York|California)|(Commonwealth of )?Massachusetts)\b",
            r"\bvenue (in|at) .* (state|federal) court .* (buyer|customer|home)\b",
            r"\bdispute (resolution|forum) .* (Delaware|New York|California)\b",
            r"\bgoverned by (the )?laws? of (the )?State of Delaware\b",
            r"\b(laws?|jurisdiction) of (the )?(State|New York|California|Delaware)\b",
        ],
        "description": "Governing-law and venue clauses can force you to litigate in the vendor's home jurisdiction or in an unfamiliar offshore venue. Push to a buyer-friendly forum.",
        "fix": "Negotiate governing law and venue in the buyer's home jurisdiction (e.g. Delaware / New York / California). For arbitration, ICC or AAA in a buyer-friendly city, with expedited procedures available.",
        "evidence_hint": "governing law",
    },
    {
        "id": "confidentiality_mutual",
        "axis": "governance",
        "label": "Mutual confidentiality & survival",
        "severity": "high",
        "patterns": [
            r"\b(confidentiality|non-?disclosure)\b",
            r"\bconfidential information\b",
        ],
        "bad_phrases": [
            r"\b(confidentiality|non-?disclosure) .* (one.year|1.year) .* (term|expiration)\b",
            r"\b(confidentiality (obligation|survival)) (terminates|ends|expires) (on|with) (this )?agreement\b",
        ],
        "good_phrases": [
            r"\b(confidentiality|confidential information) (obligation|protection) (survives|continues) (for \d+ years? (after|of) termination)\b",
            r"\b(mutual|reciprocal) confidentiality\b",
            r"\b(injunctive relief|equitable remedies) (available|appropriate) .* breach of confidentiality\b",
        ],
        "description": "Confidentiality that expires with the contract is buyer-hostile — your trade secrets still need protection post-termination. Pin the survival period.",
        "fix": "Mutual confidentiality surviving ≥5 years post-termination (and indefinitely for trade secrets). Add injunctive-relief language so breach triggers immediate court action.",
        "evidence_hint": "confidentiality",
    },
    {
        "id": "force_majeure",
        "axis": "governance",
        "label": "Force majeure (scope & carveouts)",
        "severity": "low",
        "patterns": [
            r"\bforce majeure\b",
            r"\bacts? of (God|nature|government)\b",
            r"\bbeyond (the )?(reasonable )?control (of either party)?\b",
        ],
        "bad_phrases": [
            r"\bforce majeure (includes?|covers?) .* (supply chain|subcontractor|raw materials)\b",
            r"\bno (liability|obligation) .* (during|throughout) force majeure\b",
        ],
        "good_phrases": [
            r"\bforce majeure (does not include|excludes?) .* (subcontractor|supply chain|raw materials)\b",
            r"\bright to (terminate|withdraw) .* (force majeure (event )?(continues|persists)) (for )?\d+ (days?|months?)\b",
            r"\b(payment|fees) (obligation|due) .* (not|never) (excused|waived) .* force majeure\b",
        ],
        "description": "Overbroad force majeure (especially covering subcontractors) lets the vendor pause obligations indefinitely. Exclude payment obligations and allow termination for prolonged events.",
        "fix": "Tighten FM definition (natural disaster / government action / war only — NOT vendor subcontractor failures). Payment obligations never excused. Termination right after 30-60 days of continued FM.",
        "evidence_hint": "force majeure",
    },
    {
        "id": "non_solicit",
        "axis": "governance",
        "label": "Non-solicit of personnel",
        "severity": "low",
        "patterns": [
            r"\bnon-?solicit(ation)?\b",
            r"\bno (hire|solicit) (of )?(employees?|personnel|staff)\b",
        ],
        "bad_phrases": [
            r"\b(non-?solicit|non-?hire) (period|term) .* (5|seven|five) years?\b",
            r"\b(non-?solicit|non-?hire) .* (worldwide|globally)\b",
        ],
        "good_phrases": [
            r"\b(non-?solicit|non-?hire) (period|term) (of |limited to )?(12 months?|one year|18 months?)\b",
            r"\bnon-?solicit (does not apply|except for) .* (general (advertising|job postings?)|employee (who|initiates))\b",
        ],
        "description": "Multi-year worldwide non-solicits limit your hiring flexibility. Keep it ≤12-18 months and carve out general job postings / employee-initiated outreach.",
        "fix": "Limit non-solicit to ≤18 months. Carve out general advertising, third-party recruiters, and employees who initiate contact. Make it mutual if the vendor is large.",
        "evidence_hint": "non-solicit",
    },
    {
        "id": "background_checks",
        "axis": "governance",
        "label": "Personnel background checks",
        "severity": "medium",
        "patterns": [
            r"\bbackground (check|checks|screening)\b",
            r"\b(criminal|criminal.?record|reference) (check|verification)\b",
        ],
        "bad_phrases": [
            r"\b(no |not required )(background|reference|screening)\b",
            r"\bvendor (sole|absolute) discretion .* (background|screening)\b",
        ],
        "good_phrases": [
            r"\b(criminal|background) (check|checks|screening) (for|of) (all |personnel )?(assigned|engaged) (personnel|employees?|contractors?)\b",
            r"\b(industry.?standard|comprehensive) (background|reference) (check|verification)\b",
        ],
        "description": "For vendors handling sensitive data or accessing your premises, background checks are non-negotiable. Vague 'as appropriate' lets the vendor skip this.",
        "fix": "Require comprehensive background checks (criminal, employment, education verification) for any vendor personnel accessing customer data or systems. Refresh annually.",
        "evidence_hint": "background check",
    },
    {
        "id": "most_favored_customer",
        "axis": "commercial",
        "label": "Most-favored-customer pricing",
        "severity": "low",
        "patterns": [
            r"\bmost.?favored (customer|pricing|client)\b",
            r"\bMFC\b",
        ],
        "bad_phrases": [
            r"\b(no |not )?(MFC|most.?favored) (commitment|pricing|obligation)\b",
            r"\bvendor (may|reserves the right to) (offer|provide) (better|preferential) (pricing|terms) .* (to|with) others\b",
        ],
        "good_phrases": [
            r"\bcustomer (shall receive|enjoys?) (pricing|terms) (no less favorable|at least as favorable) (than|as)\b",
            r"\bright to (audit|verify) .* (pricing|terms) (offered|provided) .* similar customers\b",
        ],
        "description": "If you're a strategic customer, ask for MFC pricing — the vendor shouldn't be offering a competitor materially better terms for the same service.",
        "fix": "Request MFC clause: 'Customer pricing shall be no less favorable than pricing offered to similarly situated customers for materially similar services.' Add right to audit.",
        "evidence_hint": "MFC",
    },
    {
        "id": "reference_customer_rights",
        "axis": "commercial",
        "label": "Reference / case-study consent",
        "severity": "low",
        "patterns": [
            r"\b(reference|case study|testimonial)\b.*\b(consent|approval|right)\b",
        ],
        "bad_phrases": [
            r"\bvendor (may|reserves the right to) (use|reference) .* (customer's|client's) (name|logo|brand)\b",
            r"\b(implied|automatic) (consent|permission) .* (reference|case study)\b",
        ],
        "good_phrases": [
            r"\bprior (written )?(consent|approval) (of|from) (customer|client) (for|to use) .* (name|logo|brand)\b",
            r"\bopt.?out .* (reference|case study) (at any time)\b",
        ],
        "description": "Vendors often claim 'implied consent' to use your logo / name as a reference. Lock down approval rights and the right to opt out.",
        "fix": "Require prior written consent for any use of customer name / logo / metrics as reference. Allow opt-out at any time with 30 days notice.",
        "evidence_hint": "reference",
    },
    {
        "id": "anti_bribery_compliance",
        "axis": "governance",
        "label": "Anti-bribery / FCPA / sanctions compliance",
        "severity": "medium",
        "patterns": [
            r"\b(anti.?bribery|FCPA|foreign corrupt practices|sanctions|OFAC)\b",
            r"\bcode of conduct\b.*\b(bribery|corruption)\b",
        ],
        "bad_phrases": [
            r"\bno (specific )?(anti.?bribery|sanctions|FCPA) (representation|warranty|compliance)\b",
        ],
        "good_phrases": [
            r"\b(FCPA|anti.?bribery|sanctions|OFAC) (compliance|laws?) (applicable|followed|complied with)\b",
            r"\bvendor (warrants?|represents?) (compliance|adherence) (with|to) .* (FCPA|anti.?bribery|sanctions|OFAC)\b",
        ],
        "description": "For vendors with international reach or those operating in regulated industries, anti-bribery and sanctions compliance are non-negotiable.",
        "fix": "Require FCPA / anti-bribery / OFAC sanctions compliance representation. Add right to audit and immediate termination for material breach.",
        "evidence_hint": "anti-bribery",
    },
    {
        "id": "non_disparagement",
        "axis": "governance",
        "label": "Non-disparagement / public statements",
        "severity": "low",
        "patterns": [r"\bnon-?disparagement\b", r"\bpublic (statement|comment) (about|regarding)\b"],
        "bad_phrases": [
            r"\b(non-?disparagement|mutual non-?disparagement) (survives|continues) (for|in perpetuity)\b",
            r"\b(non-?disparagement) (covers?|includes?) .* (legitimate|good faith) (complaints?|whistleblowing)\b",
        ],
        "good_phrases": [
            r"\b(non-?disparagement) .* (terminates|ends|expires) (with|at end of) (this )?agreement\b",
            r"\b(non-?disparagement) (does not apply|except for) .* (whistleblowing|regulatory|complaints?)\b",
        ],
        "description": "Overbroad non-disparagement can silence legitimate complaints (whistleblowing, regulatory complaints). Add explicit carveouts.",
        "fix": "Limit non-disparagement to the contract term + 1 year. Carve out: regulatory complaints, whistleblower reports, legal testimony, and good-faith responses to legal process.",
        "evidence_hint": "non-disparagement",
    },
    {
        "id": "setoff_rights",
        "axis": "commercial",
        "label": "Set-off rights (buyer may withhold for breach)",
        "severity": "medium",
        "patterns": [
            r"\b(set.?off|setoff|withhold)\b.*\b(payment|fees|amount)\b",
            r"\bright to (withhold|set.?off)\b",
        ],
        "bad_phrases": [
            r"\b(no |not )?(right to (withhold|set.?off|offset))\b",
            r"\bpayment (obligation|due) (unconditional|absolute)\b",
        ],
        "good_phrases": [
            r"\b(customer|client) (may|reserves the right to) (withhold|set.?off) .* (amounts? due|payment)\b",
            r"\b(withhold|set.?off) (amounts?) (allegedly|reasonably) (owed|due) .* (breach|non.?conformance)\b",
        ],
        "description": "Without a setoff right, the buyer must keep paying even if the vendor is in breach. Lock the right to withhold payment for vendor non-conformance.",
        "fix": "Add explicit right to set off / withhold payments for amounts reasonably believed to be owed as a result of vendor breach or non-conforming deliverables.",
        "evidence_hint": "set-off",
    },
    {
        "id": "benchmarking_rights",
        "axis": "commercial",
        "label": "Benchmarking / rate parity rights",
        "severity": "low",
        "patterns": [r"\bbenchmark(ing)?\b.*\b(right|pricing|rates?)\b", r"\brate parity\b"],
        "bad_phrases": [
            r"\b(no |not )?benchmark(ing)? (right|obligation)\b",
        ],
        "good_phrases": [
            r"\bright to (benchmark|compare) .* (pricing|rates?|terms) .* (against|other) (customers?|competitors?)\b",
            r"\bbenchmark (study|report) (provided|furnished) (annually|on request)\b",
        ],
        "description": "Vendors often charge similar customers wildly different rates. A benchmarking clause gives you evidence if you suspect you're paying premium.",
        "fix": "Add right to benchmark against similarly situated customers. If pricing is materially above market, allow termination for convenience or rate renegotiation.",
        "evidence_hint": "benchmark",
    },
    {
        "id": "background_checks",
        "axis": "governance",
        "label": "Personnel security vetting (clean)",
        "severity": "low",
        "patterns": [r"\bpersonnel (security|vetting|clearance)\b"],
        "bad_phrases": [r"\bno (vetting|clearance|security check)\b"],
        "good_phrases": [r"\b(all |personnel )?(security|background) (check|vetting|clearance) (performed|conducted)\b"],
        "description": "For vendors accessing sensitive systems or data, personnel vetting is essential.",
        "fix": "Require vendor to maintain documented security/background vetting for any personnel with access to customer data or production systems.",
        "evidence_hint": "vetting",
    },
]


# ------------------------------------------------------------------ #
# Analysis engine
# ------------------------------------------------------------------ #
def _strip_for_match(text: str) -> str:
    """Lowercase, normalize whitespace, keep punctuation. Used for matching only."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def analyze_contract(
    contract_text: str,
    vendor_type: str = "",
    contract_value_band: str = "",
    brief: str = "",
) -> dict:
    raw = contract_text or ""
    raw_lower = _strip_for_match(raw)

    findings = []  # each: {clause_id, label, axis, severity, status, evidence, fix, description}
    axis_scores = {
        "data_governance": {"present": 0, "total": 0, "weight": 0.25 if "data" in (vendor_type or "").lower() or "saas" in (vendor_type or "").lower() else 0.15},
        "commercial":      {"present": 0, "total": 0, "weight": 0.20},
        "liability":       {"present": 0, "total": 0, "weight": 0.25 if "high_value" in (contract_value_band or "") else 0.20},
        "operational":     {"present": 0, "total": 0, "weight": 0.15},
        "exit":            {"present": 0, "total": 0, "weight": 0.20},
        "governance":      {"present": 0, "total": 0, "weight": 0.10},
    }

    for clause in CLAUSE_LIBRARY:
        axis = clause["axis"]
        if axis not in axis_scores:
            continue
        axis_scores[axis]["total"] += 1

        # Pattern detection — does the clause appear at all?
        present_match = None
        for pat in clause.get("patterns", []):
            m = re.search(pat, raw_lower, re.IGNORECASE)
            if m:
                present_match = m
                break

        if not present_match:
            findings.append({
                "clause_id": clause["id"],
                "label": clause["label"],
                "axis": axis,
                "severity": clause["severity"],
                "status": "missing",
                "evidence": "",
                "fix": clause["fix"],
                "description": clause["description"],
            })
            continue

        # Clause appears — is it buyer-friendly or buyer-hostile?
        good_match = None
        for pat in clause.get("good_phrases", []):
            m = re.search(pat, raw_lower, re.IGNORECASE)
            if m:
                good_match = m
                break

        bad_match = None
        for pat in clause.get("bad_phrases", []):
            m = re.search(pat, raw_lower, re.IGNORECASE)
            if m:
                bad_match = m
                break

        # Resolve status
        if good_match and not bad_match:
            status = "buyer_friendly"
            evidence = _evidence_snippet(raw, good_match)
        elif bad_match and not good_match:
            status = "buyer_hostile"
            evidence = _evidence_snippet(raw, bad_match)
        elif good_match and bad_match:
            # Both present — favor the buyer-friendly reading only if good is more specific;
            # otherwise flag as mixed (buyer-hostile-leaning)
            status = "buyer_hostile"
            evidence = _evidence_snippet(raw, bad_match) + "  |  " + _evidence_snippet(raw, good_match)
        else:
            # Clause present but no quality signal either way → buyer-neutral
            status = "present_neutral"
            evidence = _evidence_snippet(raw, present_match)

        if status == "buyer_friendly":
            axis_scores[axis]["present"] += 1
        elif status == "present_neutral":
            axis_scores[axis]["present"] += 0.5

        # Always emit a finding — UI uses status badges to color-code.
        # Buyer-friendly findings are just informational ("this one is OK").
        if status == "buyer_friendly":
            severity_for_finding = "low"
        elif status == "present_neutral":
            severity_for_finding = "low"
        else:
            severity_for_finding = clause["severity"]

        findings.append({
            "clause_id": clause["id"],
            "label": clause["label"],
            "axis": axis,
            "severity": severity_for_finding,
            "status": status,
            "evidence": evidence,
            "fix": clause["fix"] if status != "buyer_friendly" else "Clause is buyer-friendly as written — no fix needed.",
            "description": clause["description"],
        })

    # Axis scoring (0-100) + weighted overall
    # Strategy: an axis scores 100 if all clauses that ARE present are buyer-friendly,
    # minus deductions for any buyer-hostile clauses. Missing clauses only cost if
    # they're high-severity. This rewards dense, well-written contracts and punishes
    # the silent omissions AND the anti-buyer language that is the real risk.
    axis_pcts = {}
    weighted_sum = 0.0
    weight_sum = 0.0

    for axis, info in axis_scores.items():
        if info["total"] == 0:
            axis_pcts[axis] = 100.0
            continue
        # Per-axis quality score: start at 100, subtract for hostile and high-missing.
        hostile_in_axis = sum(1 for f in findings if f["axis"] == axis and f["status"] == "buyer_hostile")
        neutral_in_axis = sum(1 for f in findings if f["axis"] == axis and f["status"] == "present_neutral")
        missing_high_in_axis = sum(1 for f in findings if f["axis"] == axis and f["status"] == "missing" and f["severity"] == "high")
        missing_med_in_axis = sum(1 for f in findings if f["axis"] == axis and f["status"] == "missing" and f["severity"] == "medium")

        # Each buyer-hostile in this axis costs 12 points, ambiguous 3, missing-high 8, missing-med 4.
        deduction = (hostile_in_axis * 12) + (neutral_in_axis * 3) + (missing_high_in_axis * 8) + (missing_med_in_axis * 4)
        pct = max(0.0, 100.0 - deduction)
        axis_pcts[axis] = round(pct, 1)
        weighted_sum += pct * info["weight"]
        weight_sum += info["weight"]

    overall = round(weighted_sum / weight_sum) if weight_sum else 0

    # Global hostile penalty — these are the real "don't sign this" signals.
    hostile_high = sum(1 for f in findings if f["status"] == "buyer_hostile" and f["severity"] == "high")
    hostile_med = sum(1 for f in findings if f["status"] == "buyer_hostile" and f["severity"] == "medium")
    global_penalty = (hostile_high * 6) + (hostile_med * 3)
    overall = max(0, min(100, overall - global_penalty))

    # Verdict band
    if overall >= 85:
        verdict = "ship_ready"
    elif overall >= 70:
        verdict = "mostly_ready"
    elif overall >= 55:
        verdict = "needs_polish"
    elif overall >= 40:
        verdict = "tight_but_usable"
    else:
        verdict = "needs_rework"

    # Sort findings: missing+high first, then hostile+high, then med, then low
    severity_order = {"high": 0, "medium": 1, "low": 2}
    status_order = {"missing": 0, "buyer_hostile": 1, "present_neutral": 2}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), status_order.get(f["status"], 9), f["label"]))

    # Top 3 recommended fixes (highest severity first)
    top_fixes = []
    seen = set()
    for f in findings:
        if f["status"] in ("missing", "buyer_hostile") and f["clause_id"] not in seen and f["severity"] in ("high", "medium"):
            top_fixes.append({
                "clause_id": f["clause_id"],
                "label": f["label"],
                "severity": f["severity"],
                "fix": f["fix"],
                "status": f["status"],
            })
            seen.add(f["clause_id"])
        if len(top_fixes) >= 3:
            break

    # Risk summary
    risk_summary = {
        "total_clauses_checked": sum(info["total"] for info in axis_scores.values()),
        "missing": sum(1 for f in findings if f["status"] == "missing"),
        "buyer_hostile": sum(1 for f in findings if f["status"] == "buyer_hostile"),
        "present_neutral": sum(1 for f in findings if f["status"] == "present_neutral"),
        "buyer_friendly": sum(1 for f in findings if f["status"] == "buyer_friendly"),
        "high_severity_open": sum(1 for f in findings if f["severity"] == "high" and f["status"] in ("missing", "buyer_hostile")),
    }

    return {
        "overall_score": overall,
        "verdict": verdict,
        "axis_scores": axis_pcts,
        "findings": findings,
        "top_fixes": top_fixes,
        "risk_summary": risk_summary,
        "vendor_type": vendor_type,
        "contract_value_band": contract_value_band,
        "brief": brief,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _evidence_snippet(raw: str, match: re.Match, before: int = 80, after: int = 120) -> str:
    start = max(0, match.start() - before)
    end = min(len(raw), match.end() + after)
    snippet = raw[start:end].replace("\n", " ").strip()
    snippet = re.sub(r"\s+", " ", snippet)
    if start > 0:
        snippet = "…" + snippet
    if end < len(raw):
        snippet = snippet + "…"
    return snippet


# ------------------------------------------------------------------ #
# Routes
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "time": datetime.now(timezone.utc).isoformat(timespec="seconds")})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    contract_text = (payload.get("contract_text") or "").strip()
    if len(contract_text) < 200:
        return jsonify({"error": "contract_text must be at least 200 characters"}), 400

    vendor_type = (payload.get("vendor_type") or "").strip()
    contract_value_band = (payload.get("contract_value_band") or "").strip()
    brief = (payload.get("brief") or "").strip()
    save = bool(payload.get("save", True))

    analysis = analyze_contract(
        contract_text=contract_text,
        vendor_type=vendor_type,
        contract_value_band=contract_value_band,
        brief=brief,
    )

    session_id = None
    if save:
        db = get_db()
        cur = db.execute(
            "INSERT INTO sessions (brief, contract_text, vendor_type, contract_value_band, analysis_json, overall_score, verdict, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                brief,
                contract_text,
                vendor_type,
                contract_value_band,
                json.dumps(analysis),
                analysis["overall_score"],
                analysis["verdict"],
                analysis["analyzed_at"],
            ),
        )
        db.commit()
        session_id = cur.lastrowid

    return jsonify({"session_id": session_id, "analysis": analysis})


@app.route("/api/sessions", methods=["GET"])
def api_sessions_list():
    db = get_db()
    rows = db.execute(
        "SELECT id, brief, vendor_type, contract_value_band, overall_score, verdict, self_rating, created_at FROM sessions ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return jsonify({"sessions": [dict(r) for r in rows]})


@app.route("/api/sessions/<int:session_id>", methods=["GET"])
def api_sessions_get(session_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    payload = dict(row)
    payload["analysis"] = json.loads(payload.pop("analysis_json"))
    return jsonify(payload)


@app.route("/api/sessions/<int:session_id>", methods=["PATCH"])
def api_sessions_patch(session_id: int):
    payload = request.get_json(silent=True) or {}
    fields = []
    values = []
    if "self_rating" in payload:
        try:
            sr = int(payload["self_rating"])
            if sr < 1 or sr > 5:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "self_rating must be int 1-5"}), 400
        fields.append("self_rating = ?")
        values.append(sr)
    if "notes" in payload:
        fields.append("notes = ?")
        values.append(str(payload["notes"])[:2000])
    if not fields:
        return jsonify({"error": "no fields to update"}), 400
    values.append(session_id)
    db = get_db()
    db.execute(f"UPDATE sessions SET {', '.join(fields)} WHERE id = ?", values)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/export/<int:session_id>")
def api_export(session_id: int):
    fmt = (request.args.get("fmt") or "md").lower()
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    analysis = json.loads(row["analysis_json"])

    if fmt == "json":
        return jsonify({"session": dict(row), "analysis": analysis})
    if fmt != "md":
        return jsonify({"error": "fmt must be md or json"}), 400

    lines = []
    lines.append(f"# Vendor Risk Screener — Session #{row['id']}")
    lines.append("")
    lines.append(f"- **Created:** {row['created_at']}")
    if row["vendor_type"]:
        lines.append(f"- **Vendor type:** {row['vendor_type']}")
    if row["contract_value_band"]:
        lines.append(f"- **Contract value band:** {row['contract_value_band']}")
    if row["brief"]:
        lines.append(f"- **Brief:** {row['brief']}")
    lines.append(f"- **Overall score:** {analysis['overall_score']} / 100 — **{analysis['verdict']}**")
    if row["self_rating"]:
        lines.append(f"- **Self-rating:** {row['self_rating']} / 5")
    if row["notes"]:
        lines.append(f"- **Notes:** {row['notes']}")
    lines.append("")
    lines.append("## Axis scores")
    lines.append("")
    for axis, pct in analysis["axis_scores"].items():
        lines.append(f"- **{axis}**: {pct}")
    lines.append("")
    lines.append("## Risk summary")
    lines.append("")
    rs = analysis["risk_summary"]
    lines.append(f"- Total clauses checked: {rs['total_clauses_checked']}")
    lines.append(f"- Missing: {rs['missing']}")
    lines.append(f"- Buyer-hostile: {rs['buyer_hostile']}")
    lines.append(f"- Present but ambiguous: {rs['present_neutral']}")
    lines.append(f"- Buyer-friendly: {rs['buyer_friendly']}")
    lines.append(f"- High-severity open issues: {rs['high_severity_open']}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for f in analysis["findings"]:
        lines.append(f"### {f['label']} — {f['status']} ({f['severity']})")
        lines.append("")
        lines.append(f"- Axis: {f['axis']}")
        if f.get("evidence"):
            lines.append(f"- Evidence: `{f['evidence']}`")
        lines.append(f"- Why it matters: {f['description']}")
        lines.append(f"- Negotiation fix: {f['fix']}")
        lines.append("")
    md = "\n".join(lines)
    return app.response_class(md, mimetype="text/markdown")


@app.route("/api/sample")
def api_sample():
    """Return a sample buyer-hostile MSA so users can see the tool in action."""
    return jsonify({
        "contract_text": (
            "MASTER SERVICES AGREEMENT\n"
            "This Master Services Agreement (the \"Agreement\") is entered into between Acme Cloud Inc. (\"Vendor\") and Customer.\n\n"
            "1. SERVICES. Vendor will provide the services described in any Statement of Work signed by both parties. "
            "Vendor may engage subcontractors and sub-processors at Vendor's sole discretion without prior notice to Customer.\n\n"
            "2. PAYMENT. All fees are due net 7 from the invoice date. Vendor reserves the right to increase prices at any time "
            "during the term. Customer's payment obligations are unconditional and Customer shall not set off or withhold any amounts.\n\n"
            "3. TERM AND AUTO-RENEWAL. The initial term is twelve (12) months and shall be automatically renewed for successive "
            "twelve-month terms unless Customer provides written notice of non-renewal at least thirty (30) days prior to the end of the then-current term.\n\n"
            "4. DATA PROCESSING. Vendor processes Customer data as an independent controller. Vendor stores Customer data in its "
            "globally distributed infrastructure. A list of sub-processors will be made available upon request.\n\n"
            "5. SECURITY. Vendor will use commercially reasonable security measures, including industry-standard encryption. "
            "Vendor will notify Customer of any security incident without undue delay.\n\n"
            "6. WARRANTIES. THE SERVICES ARE PROVIDED \"AS IS\" AND VENDOR DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, "
            "INCLUDING ANY WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.\n\n"
            "7. INDEMNIFICATION. Vendor will indemnify Customer for third-party claims arising solely from Vendor's gross negligence, "
            "subject to the limitation of liability below.\n\n"
            "8. LIMITATION OF LIABILITY. IN NO EVENT SHALL EITHER PARTY'S AGGREGATE LIABILITY EXCEED THE FEES PAID BY CUSTOMER "
            "IN THE THREE (3) MONTHS PRECEDING THE CLAIM. IN NO EVENT SHALL EITHER PARTY BE LIABLE FOR ANY CONSEQUENTIAL DAMAGES.\n\n"
            "9. INSURANCE. Vendor will maintain commercially appropriate insurance during the term.\n\n"
            "10. CONFIDENTIALITY. Each party will protect the other's confidential information during the term. "
            "Confidentiality obligations expire with this Agreement.\n\n"
            "11. INTELLECTUAL PROPERTY. Vendor retains all right, title, and interest in and to the services and any work product. "
            "Customer receives a non-exclusive, non-transferable license to use the deliverables solely for Customer's internal business.\n\n"
            "12. TERMINATION. Customer may terminate this Agreement for material breach upon thirty (30) days' written notice and "
            "Vendor's failure to cure. Vendor may terminate at any time. There is no termination for convenience.\n\n"
            "13. FORCE MAJEURE. Neither party shall be liable for any failure due to causes beyond its reasonable control, "
            "including supply chain disruptions and raw materials shortages.\n\n"
            "14. DISPUTES. This Agreement is governed by the laws of the State of Delaware. Any disputes shall be resolved by "
            "binding arbitration in Wilmington, Delaware. Each party bears its own costs.\n\n"
            "15. GENERAL. Vendor may assign this Agreement without Customer's consent. Vendor may use Customer's name and logo "
            "as a reference without prior approval. Vendor maintains comprehensive background checks on its personnel at Vendor's sole discretion.\n"
        )
    })


# ------------------------------------------------------------------ #
# Entrypoint
# ------------------------------------------------------------------ #
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5007"))
    app.run(host="127.0.0.1", port=port, debug=False)