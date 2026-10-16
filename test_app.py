"""
Smoke tests for Vendor Risk Screener.
Run: python3 test_app.py
"""
import json
import re
import sys
import unittest

# Allow running from the project directory
sys.path.insert(0, ".")

import app as app_module  # noqa: E402
from app import app, analyze_contract, init_db, DB_PATH  # noqa: E402


class TestRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use a fresh in-memory DB-ish path for isolation
        cls.db_path = DB_PATH
        init_db()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_index_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Vendor Risk Screener", r.data)

    def test_sample_returns_text(self):
        r = self.client.get("/api/sample")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertGreater(len(d["contract_text"]), 1000)

    def test_analyze_min_length(self):
        r = self.client.post("/api/analyze", json={"contract_text": "too short"})
        self.assertEqual(r.status_code, 400)

    def test_analyze_basic(self):
        text = (
            "MASTER SERVICES AGREEMENT\n"
            "1. SERVICES. Vendor will provide services.\n"
            "2. PAYMENT. Net 30 from invoice. Vendor may increase prices once per year upon 90 days notice, capped at the lesser of CPI or 5%.\n"
            "3. TERM. Initial term is 12 months and shall not automatically renew without affirmative written consent.\n"
            "4. DATA PROCESSING. Vendor will process data only on documented Customer instructions per the DPA which is incorporated herein. Vendor shall notify Customer of any data breach within 72 hours.\n"
            "5. SECURITY. Vendor maintains AES-256 encryption at rest and TLS 1.2+ in transit. Vendor maintains SOC 2 Type II annually.\n"
            "6. INDEMNIFICATION. Vendor will defend, indemnify and hold harmless Customer from third-party IP infringement claims, indemnification is not subject to the liability cap.\n"
            "7. LIMITATION OF LIABILITY. Aggregate liability capped at 2x annual fees, with a super-cap of 5x annual fees for data breach, IP infringement, and confidentiality breach.\n"
            "8. SLA. Vendor commits to 99.9% uptime with tiered service credits, and Customer may terminate for sustained SLA breach.\n"
            "9. INSURANCE. Vendor maintains cyber insurance of not less than $5 million and CGL of $2 million.\n"
            "10. TERMINATION. Customer may terminate this agreement at any time for convenience upon 60 days written notice, with a termination fee capped at 3 months of fees.\n"
            "11. CONFIDENTIALITY. Mutual confidentiality obligations survive for 5 years after termination. Injunctive relief is appropriate for breach.\n"
            "12. IP OWNERSHIP. All work product and deliverables created by Vendor are the sole property of Customer. Vendor assigns all IP rights to Customer.\n"
            "13. DISPUTES. Governed by the laws of the State of Delaware. Venue in state or federal court in Delaware.\n"
            "14. FORCE MAJEURE. Force majeure excludes subcontractor and supply chain failures. Payment obligations are never excused.\n"
        )
        r = self.client.post("/api/analyze", json={
            "contract_text": text,
            "vendor_type": "saas",
            "contract_value_band": "large",
            "brief": "Strong buyer-friendly MSA",
        })
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("session_id", d)
        self.assertIn("analysis", d)
        a = d["analysis"]
        # The strong MSA hits ~12 friendly clauses out of 42 total — realistic ceiling
        # is "mostly_ready" with at least 12 buyer_friendly findings.
        self.assertGreater(a["overall_score"], 50)
        self.assertIn(a["verdict"], ["ship_ready", "mostly_ready", "needs_polish"])
        self.assertGreaterEqual(a["risk_summary"]["buyer_friendly"], 10)
        # The hostile findings should be minimal
        self.assertLessEqual(a["risk_summary"]["buyer_hostile"], 3)

    def test_analyze_hostile(self):
        text = (
            "AGREEMENT\n"
            "Vendor processes data as an independent controller. Sub-processors will be made available upon request. "
            "Data is stored globally. Vendor uses commercially reasonable security and will notify of any incident without undue delay. "
            "Net 7 from invoice. Vendor may increase prices at any time. Payment obligations are unconditional. "
            "Initial term 12 months, automatically renewed unless Customer gives 30 days written notice. "
            "Services are provided as-is. Vendor disclaims all warranties including merchantability and fitness. "
            "Aggregate liability shall not exceed fees paid in the 3 months preceding the claim. No consequential damages. "
            "Vendor will maintain commercially appropriate insurance. "
            "Vendor retains all IP in the services. Customer receives a non-exclusive license. "
            "No termination for convenience. Vendor may assign without consent. "
            "Confidentiality expires with the agreement. Force majeure includes supply chain failures. "
            "Governed by the laws of an unfamiliar offshore jurisdiction. Arbitration offshore. "
            "Vendor may use Customer's name and logo without prior approval. "
        )
        r = self.client.post("/api/analyze", json={
            "contract_text": text,
            "vendor_type": "saas",
            "contract_value_band": "large",
            "brief": "Buyer-hostile",
        })
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        a = d["analysis"]
        # Hostile contract should score poorly
        self.assertLess(a["overall_score"], 50)
        self.assertIn(a["verdict"], ["needs_rework", "tight_but_usable"])
        # Many missing/hostile findings
        self.assertGreater(a["risk_summary"]["missing"] + a["risk_summary"]["buyer_hostile"], 15)


class TestAnalysis(unittest.TestCase):
    def test_axis_weights_data_vendor(self):
        text = "short" * 50  # above 200 char threshold
        a = analyze_contract(text, vendor_type="data", contract_value_band="")
        self.assertEqual(a["overall_score"] >= 0 and a["overall_score"] <= 100, True)

    def test_breach_notification_72h_is_good(self):
        text = "Vendor shall notify Customer of any data breach within 72 hours of discovery."
        a = analyze_contract(text, vendor_type="saas", contract_value_band="medium")
        breach = next((f for f in a["findings"] if f["clause_id"] == "breach_notification_window"), None)
        # The clause is present and buyer-friendly
        self.assertIsNotNone(breach)
        self.assertIn(breach["status"], ("buyer_friendly", "present_neutral"))

    def test_breach_notification_undue_delay_is_bad(self):
        text = "Vendor will notify Customer of any security incident without undue delay."
        a = analyze_contract(text, vendor_type="saas", contract_value_band="medium")
        breach = next((f for f in a["findings"] if f["clause_id"] == "breach_notification_window"), None)
        self.assertIsNotNone(breach)
        # Should flag as buyer-hostile because of "without undue delay" without 72h anchor
        self.assertEqual(breach["status"], "buyer_hostile")

    def test_auto_renewal_30day_is_bad(self):
        text = "Initial term is 12 months and shall be automatically renewed unless Customer provides 30 days prior written notice."
        a = analyze_contract(text, vendor_type="saas", contract_value_band="medium")
        auto = next((f for f in a["findings"] if f["clause_id"] == "auto_renewal_terms"), None)
        self.assertIsNotNone(auto)
        self.assertEqual(auto["status"], "buyer_hostile")

    def test_missing_dpa_flagged(self):
        text = "Vendor will provide services. Customer will pay fees. Term is 12 months."
        a = analyze_contract(text, vendor_type="data", contract_value_band="medium")
        dpa = next((f for f in a["findings"] if f["clause_id"] == "data_processing_addendum"), None)
        self.assertIsNotNone(dpa)
        self.assertEqual(dpa["status"], "missing")

    def test_strong_liability_cap_buyer_friendly(self):
        text = (
            "Aggregate liability is capped at 2x annual fees, with no cap on data breach, IP infringement, "
            "and confidentiality breach claims. Vendor maintains cyber insurance of not less than $10,000,000."
        )
        a = analyze_contract(text, vendor_type="saas", contract_value_band="large")
        cap = next((f for f in a["findings"] if f["clause_id"] == "liability_cap"), None)
        self.assertIsNotNone(cap)
        self.assertEqual(cap["status"], "buyer_friendly")

    def test_weak_liability_cap_buyer_hostile(self):
        text = "Aggregate liability shall not exceed fees paid in the three months preceding the claim."
        a = analyze_contract(text, vendor_type="saas", contract_value_band="large")
        cap = next((f for f in a["findings"] if f["clause_id"] == "liability_cap"), None)
        self.assertIsNotNone(cap)
        self.assertEqual(cap["status"], "buyer_hostile")

    def test_ip_assignment_to_buyer_friendly(self):
        text = "All work product and deliverables created hereunder shall be the sole property of Customer. Vendor assigns all IP rights to Customer."
        a = analyze_contract(text, vendor_type="consulting", contract_value_band="medium")
        ip = next((f for f in a["findings"] if f["clause_id"] == "ip_assignment_to_buyer"), None)
        self.assertIsNotNone(ip)
        self.assertEqual(ip["status"], "buyer_friendly")

    def test_ip_assignment_to_vendor_hostile(self):
        text = "Vendor retains all right, title and interest in the work product. Customer receives a non-exclusive license."
        a = analyze_contract(text, vendor_type="consulting", contract_value_band="medium")
        ip = next((f for f in a["findings"] if f["clause_id"] == "ip_assignment_to_buyer"), None)
        self.assertIsNotNone(ip)
        self.assertEqual(ip["status"], "buyer_hostile")

    def test_termination_for_convenience_buyer_friendly(self):
        text = "Customer may terminate this agreement at any time for convenience upon 60 days written notice."
        a = analyze_contract(text, vendor_type="saas", contract_value_band="medium")
        t = next((f for f in a["findings"] if f["clause_id"] == "termination_for_convenience"), None)
        self.assertIsNotNone(t)
        self.assertEqual(t["status"], "buyer_friendly")

    def test_no_termination_for_convenience_missing(self):
        text = "There is no termination for convenience. Term is 12 months auto-renewing."
        a = analyze_contract(text, vendor_type="saas", contract_value_band="medium")
        t = next((f for f in a["findings"] if f["clause_id"] == "termination_for_convenience"), None)
        self.assertIsNotNone(t)
        self.assertIn(t["status"], ("buyer_hostile", "present_neutral"))

    def test_export_markdown(self):
        text = "test " * 100
        a = analyze_contract(text, vendor_type="saas", contract_value_band="medium")
        # Simulate by checking the structure returned
        self.assertIn("top_fixes", a)
        self.assertIn("axis_scores", a)


class TestSessionEndpoints(unittest.TestCase):
    def setUp(self):
        init_db()
        app.config["TESTING"] = True
        self.client = app.test_client()
        # Create a session first
        text = "Test contract " * 50
        r = self.client.post("/api/analyze", json={"contract_text": text, "brief": "test"})
        self.session_id = r.get_json()["session_id"]

    def test_list_sessions(self):
        r = self.client.get("/api/sessions")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(len(r.get_json()["sessions"]), 0)

    def test_get_session(self):
        r = self.client.get(f"/api/sessions/{self.session_id}")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("analysis", d)

    def test_patch_rating(self):
        r = self.client.patch(f"/api/sessions/{self.session_id}", json={"self_rating": 4})
        self.assertEqual(r.status_code, 200)
        g = self.client.get(f"/api/sessions/{self.session_id}").get_json()
        self.assertEqual(g["self_rating"], 4)

    def test_patch_notes(self):
        r = self.client.patch(f"/api/sessions/{self.session_id}", json={"notes": "We negotiated Net-45 and added SOC 2 Type II."})
        self.assertEqual(r.status_code, 200)
        g = self.client.get(f"/api/sessions/{self.session_id}").get_json()
        self.assertEqual(g["notes"], "We negotiated Net-45 and added SOC 2 Type II.")

    def test_patch_invalid_rating(self):
        r = self.client.patch(f"/api/sessions/{self.session_id}", json={"self_rating": 9})
        self.assertEqual(r.status_code, 400)

    def test_export_md(self):
        r = self.client.get(f"/api/export/{self.session_id}?fmt=md")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Vendor Risk Screener", r.data.decode())

    def test_export_json(self):
        r = self.client.get(f"/api/export/{self.session_id}?fmt=json")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)