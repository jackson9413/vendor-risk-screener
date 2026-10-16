// Vendor Risk Screener — vanilla JS, no framework
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));

const els = {
  brief: $("#brief"),
  contractText: $("#contractText"),
  vendorType: $("#vendorType"),
  valueBand: $("#valueBand"),
  analyzeBtn: $("#analyzeBtn"),
  sampleBtn: $("#sampleBtn"),
  charCount: $("#charCount"),
  resultPanel: $("#resultPanel"),
  scoreCard: $("#scoreCard"),
  scoreNumber: $("#scoreNumber"),
  scoreBand: $("#scoreBand"),
  scoreMeta: $("#scoreMeta"),
  axisGrid: $("#axisGrid"),
  riskGrid: $("#riskGrid"),
  topFixes: $("#topFixes"),
  findings: $("#findings"),
  filterChips: $$(".filter-chip input"),
  axisOnly: $("#axisOnly"),
  historyList: $("#historyList"),
  vendorTypePill: $("#vendorTypePill"),
  valuePill: $("#valuePill"),
};

const VERBAND = {
  ship_ready: { color: "ship_ready", label: "ship-ready" },
  mostly_ready: { color: "mostly_ready", label: "mostly ready" },
  needs_polish: { color: "needs_polish", label: "needs polish" },
  tight_but_usable: { color: "tight_but_usable", label: "tight but usable" },
  needs_rework: { color: "needs_rework", label: "needs rework" },
};

const AXIS_LABEL = {
  data_governance: "Data governance",
  commercial: "Commercial",
  liability: "Liability",
  operational: "Operational",
  exit: "Exit",
  governance: "Governance",
};

let lastAnalysis = null;
let lastSessionId = null;

// --- wire up basic UI ---
els.contractText.addEventListener("input", () => {
  els.charCount.textContent = `${els.contractText.value.length.toLocaleString()} chars`;
});

els.vendorType.addEventListener("change", () => {
  els.vendorTypePill.textContent = `Vendor: ${els.vendorType.value || "—"}`;
});
els.valueBand.addEventListener("change", () => {
  els.valuePill.textContent = `Value: ${els.valueBand.value || "—"}`;
});

els.analyzeBtn.addEventListener("click", analyze);
els.sampleBtn.addEventListener("click", loadSample);

els.filterChips.forEach(c => c.addEventListener("change", renderFindings));
els.axisOnly.addEventListener("change", renderFindings);

// --- main flow ---
async function analyze() {
  const text = els.contractText.value.trim();
  if (text.length < 200) {
    alert("Please paste at least 200 characters of contract text.");
    return;
  }
  els.analyzeBtn.disabled = true;
  els.analyzeBtn.textContent = "Analyzing…";
  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contract_text: text,
        vendor_type: els.vendorType.value,
        contract_value_band: els.valueBand.value,
        brief: els.brief.value,
      }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      alert(`Analyze failed: ${err.error || resp.status}`);
      return;
    }
    const data = await resp.json();
    lastAnalysis = data.analysis;
    lastSessionId = data.session_id;
    renderResult(lastAnalysis);
    els.resultPanel.classList.remove("hidden");
    els.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    await loadHistory();
  } catch (e) {
    alert(`Network error: ${e.message}`);
  } finally {
    els.analyzeBtn.disabled = false;
    els.analyzeBtn.textContent = "Analyze contract";
  }
}

async function loadSample() {
  const resp = await fetch("/api/sample");
  const data = await resp.json();
  els.contractText.value = data.contract_text;
  els.brief.value = "Sample buyer-hostile MSA — review for typical vendor traps";
  els.vendorType.value = "saas";
  els.valueBand.value = "medium";
  els.contractText.dispatchEvent(new Event("input"));
  els.vendorType.dispatchEvent(new Event("change"));
  els.valueBand.dispatchEvent(new Event("change"));
}

function renderResult(a) {
  // score card
  els.scoreNumber.textContent = a.overall_score;
  const vb = VERBAND[a.verdict] || VERBAND.needs_rework;
  els.scoreBand.textContent = vb.label;
  els.scoreMeta.textContent = `${a.risk_summary.high_severity_open} high-severity open`;
  els.scoreCard.className = "score-card " + vb.color;

  // axis pills
  els.axisGrid.innerHTML = "";
  for (const axis in a.axis_scores) {
    const pct = a.axis_scores[axis];
    const color = pct >= 85 ? "var(--green)" : pct >= 60 ? "var(--yellow)" : pct >= 40 ? "var(--orange)" : "var(--red)";
    const pill = document.createElement("div");
    pill.className = "axis-pill";
    pill.innerHTML = `
      <div class="axis-name">${AXIS_LABEL[axis] || axis}</div>
      <div class="axis-value" style="color:${color}">${pct}</div>
      <div class="axis-bar"><div class="axis-fill" style="width:${pct}%; background:${color}"></div></div>
    `;
    els.axisGrid.appendChild(pill);
  }

  // risk summary
  const rs = a.risk_summary;
  els.riskGrid.innerHTML = `
    <div class="risk-stat severity-high"><div class="num">${rs.high_severity_open}</div><div class="label">High-sev open</div></div>
    <div class="risk-stat"><div class="num">${rs.missing}</div><div class="label">Missing clauses</div></div>
    <div class="risk-stat"><div class="num">${rs.buyer_hostile}</div><div class="label">Buyer-hostile</div></div>
    <div class="risk-stat"><div class="num">${rs.present_neutral}</div><div class="label">Ambiguous</div></div>
    <div class="risk-stat"><div class="num">${rs.buyer_friendly}</div><div class="label">Buyer-friendly</div></div>
    <div class="risk-stat"><div class="num">${rs.total_clauses_checked}</div><div class="label">Total checked</div></div>
  `;

  // top fixes
  els.topFixes.innerHTML = "";
  if (a.top_fixes.length === 0) {
    els.topFixes.innerHTML = "<li>No critical negotiation asks — contract is in great shape.</li>";
  } else {
    a.top_fixes.forEach(f => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="fix-severity ${f.severity}">${f.severity}</span> <strong>${f.label}</strong> — ${escapeHtml(f.fix)}`;
      els.topFixes.appendChild(li);
    });
  }

  renderFindings();
}

function renderFindings() {
  if (!lastAnalysis) return;
  const allowed = els.filterChips.filter(c => c.checked).map(c => c.value);
  const axis = els.axisOnly.value;
  els.findings.innerHTML = "";
  let count = 0;
  for (const f of lastAnalysis.findings) {
    if (!allowed.includes(f.status)) continue;
    if (axis && f.axis !== axis) continue;
    count++;

    const card = document.createElement("div");
    card.className = "finding";
    const sev = `<span class="badge badge-severity-${f.severity}">${f.severity}</span>`;
    const st = `<span class="badge badge-status-${f.status}">${f.status.replace("_", " ")}</span>`;
    const ax = `<span class="finding-axis">${AXIS_LABEL[f.axis] || f.axis}</span>`;
    const ev = f.evidence
      ? `<div class="finding-evidence">${escapeHtml(f.evidence)}</div>`
        : "";
      card.innerHTML = `
        <div class="finding-header">
          <span class="finding-label">${escapeHtml(f.label)}</span>
          ${sev}${st}${ax}
        </div>
        <div class="finding-body"><strong>Why it matters:</strong> ${escapeHtml(f.description)}</div>
        ${ev}
        ${f.status === "buyer_friendly" ? "" : `<div class="finding-fix"><span class="fix-label">Negotiation fix</span> ${escapeHtml(f.fix)}</div>`}
      `;
    els.findings.appendChild(card);
  }
  if (count === 0) {
    els.findings.innerHTML = "<p class=\"muted\">No findings match the current filters.</p>";
  }
}

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// --- history ---
async function loadHistory() {
  const resp = await fetch("/api/sessions");
  const data = await resp.json();
  if (!data.sessions.length) {
    els.historyList.innerHTML = "<p class=\"muted\">No history yet — analyze your first contract above.</p>";
    return;
  }
  els.historyList.innerHTML = "";
  for (const s of data.sessions) {
    const row = document.createElement("div");
    row.className = "history-row";
    const created = new Date(s.created_at).toLocaleString();
    const meta = [
      s.vendor_type ? `vendor_type: ${s.vendor_type}` : null,
      s.contract_value_band ? `value: ${s.contract_value_band}` : null,
    ].filter(Boolean).join(" · ");
    row.innerHTML = `
      <div class="h-id">#${s.id}</div>
      <div class="h-meta">
        <div class="h-brief">${escapeHtml((s.brief || "(no brief)").slice(0, 120))}</div>
        <div>${meta} · ${created}</div>
      </div>
      <div class="h-score" style="color:${s.overall_score >= 70 ? "var(--green)" : s.overall_score >= 55 ? "var(--yellow)" : s.overall_score >= 40 ? "var(--orange)" : "var(--red)"}">${s.overall_score}</div>
      <div class="h-band ${s.verdict}">${s.verdict.replace(/_/g, " ")}</div>
    `;

    // detail panel below
    const detail = document.createElement("div");
    detail.className = "history-detail";
    detail.innerHTML = `
      <div class="h-rating" data-id="${s.id}">
        ${[1,2,3,4,5].map(n => `<span class="star ${s.self_rating && n <= s.self_rating ? "on" : ""}" data-rating="${n}">★</span>`).join("")}
        <span class="muted" style="margin-left:8px">self-rate how the contract went</span>
      </div>
      <textarea placeholder="Notes (saved on blur) — what you negotiated, what you accepted, what you wish you'd asked for">${escapeHtml(s.notes || "")}</textarea>
      <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap">
        <a class="btn btn-ghost" href="/api/export/${s.id}?fmt=md" target="_blank">Export Markdown</a>
        <a class="btn btn-ghost" href="/api/export/${s.id}?fmt=json" target="_blank">Export JSON</a>
      </div>
    `;

    row.addEventListener("click", e => {
      if (e.target.classList.contains("star") || e.target.tagName === "TEXTAREA") return;
      detail.classList.toggle("open");
      if (detail.classList.contains("open")) {
        loadSession(s.id, detail);
      }
    });

    // star rating
    detail.querySelectorAll(".star").forEach(star => {
      star.addEventListener("click", async (e) => {
        e.stopPropagation();
        const r = parseInt(star.dataset.rating, 10);
        await fetch(`/api/sessions/${s.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ self_rating: r }),
        });
        detail.querySelectorAll(".star").forEach((st, i) => {
          st.classList.toggle("on", i < r);
        });
      });
    });

    // notes save on blur
    const ta = detail.querySelector("textarea");
    ta.addEventListener("blur", async () => {
      await fetch(`/api/sessions/${s.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: ta.value }),
      });
    });
    ta.addEventListener("click", e => e.stopPropagation());

    els.historyList.appendChild(row);
    els.historyList.appendChild(detail);
  }
}

async function loadSession(id, detail) {
  const resp = await fetch(`/api/sessions/${id}`);
  const data = await resp.json();
  lastAnalysis = data.analysis;
  lastSessionId = id;
  renderResult(lastAnalysis);
  els.resultPanel.classList.remove("hidden");
}

// initial history load
loadHistory();