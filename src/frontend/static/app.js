/* SOC AI Assistant Pro — Frontend Logic */
"use strict";

/* ── State ──────────────────────────────────────────── */
const state = {
  logFile:    null,
  logText:    "",
  pcapFile:   null,
  pcapText:   "",
  lastResult: null,
  reports:    [],
  riskGauge:  null,
  timelineChart: null,
};

/* ── Init ───────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  checkEngineStatus();
  setInterval(checkEngineStatus, 30000);
  initDragDrop();
  buildMitreHeatmap([]);   // empty initial heatmap
});

/* ── Engine status ──────────────────────────────────── */
async function checkEngineStatus() {
  try {
    const r = await fetch("/health");
    const d = await r.json();
    const dot  = document.getElementById("engine-dot");
    const lbl  = document.getElementById("engine-status");
    if (d.status === "ok") {
      dot.className  = "dot online";
      lbl.textContent = d.engine_ready ? "Engine Ready" : "Loading...";
    } else {
      dot.className  = "dot error";
      lbl.textContent = "Engine Error";
    }
  } catch {
    document.getElementById("engine-dot").className = "dot error";
    document.getElementById("engine-status").textContent = "Offline";
  }
}

/* ── Tab switching ──────────────────────────────────── */
function showTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".pill").forEach(p => p.classList.remove("pill--active"));
  document.getElementById("tab-" + name).classList.add("active");
  event.target.classList.add("pill--active");
}

function showResult(name) {
  document.querySelectorAll(".res-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".rtab").forEach(t => t.classList.remove("active"));
  document.getElementById("res-" + name).classList.add("active");
  event.target.classList.add("active");
}

/* ── Drag & drop ────────────────────────────────────── */
function initDragDrop() {
  const zone = document.getElementById("drop-zone");
  ["dragenter","dragover"].forEach(e => zone.addEventListener(e, ev => {
    ev.preventDefault(); zone.classList.add("drag-over");
  }));
  ["dragleave","drop"].forEach(e => zone.addEventListener(e, ev => {
    ev.preventDefault(); zone.classList.remove("drag-over");
  }));
  zone.addEventListener("drop", ev => {
    const files = Array.from(ev.dataTransfer.files);
    files.forEach(f => {
      if (f.name.match(/\.(pcap|cap|pcapng)$/i)) attachFile(f, "pcap");
      else attachFile(f, "log");
    });
  });
}

function handleFileSelect(input, type) {
  if (input.files[0]) attachFile(input.files[0], type);
}

function attachFile(file, type) {
  const reader = new FileReader();
  reader.onload = e => {
    if (type === "log") {
      state.logFile = file;
      state.logText = e.target.result;
    } else {
      state.pcapFile = file;
      state.pcapText = e.target.result;
    }
    const status = document.getElementById("file-status");
    const cur = status.textContent;
    status.textContent = (cur ? cur + "  |  " : "") +
      `${type.toUpperCase()}: ${file.name} (${(file.size/1024).toFixed(1)} KB)`;
  };
  reader.readAsText(file);
}

/* ── Run analysis ───────────────────────────────────── */
async function runAnalysis() {
  const ioc = document.getElementById("ioc-input").value.trim();
  const fmt = document.getElementById("fmt-select").value;
  const btn = document.getElementById("run-btn");

  if (!state.logText && !state.pcapText && !ioc) {
    alert("Please upload a file or enter an IOC before running analysis.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "ANALYSING...";

  document.getElementById("terminal-card").style.display = "block";
  document.getElementById("results-section").style.display = "none";
  document.getElementById("zd-alert-banner").style.display = "none";
  clearTerminal();

  try {
    // Use streaming endpoint for real-time terminal feed
    const body = {
      log_file:  btoa(unescape(encodeURIComponent(state.logText  || ""))),
      pcap_file: btoa(unescape(encodeURIComponent(state.pcapText || ""))),
      ioc:       ioc,
      format:    fmt,
    };

    // Start SSE stream for terminal feed
    const termStream = await startTerminalStream(body);
    const result = await termStream;

    if (result) {
      state.lastResult = result;
      addReport(result);
      renderResults(result);
      if (fmt === "pdf" && result.pdf_b64) downloadPDFfromB64(result.pdf_b64);
    }

  } catch (err) {
    terminalLine(`[ERROR] ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "RUN ANALYSIS";
    const spinner = document.getElementById("spinner");
    if (spinner) spinner.style.display = "none";
  }
}

async function startTerminalStream(body) {
  return new Promise((resolve, reject) => {
    const spinner = document.getElementById("spinner");
    if (spinner) spinner.style.display = "block";

    fetch("/stream-analysis", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(response => {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      function read() {
        reader.read().then(({ done, value }) => {
          if (done) { resolve(null); return; }
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          buffer = lines.pop();
          for (const line of lines) {
            if (!line.startsWith("data:")) continue;
            try {
              const data = JSON.parse(line.slice(5).trim());
              if (data.step) {
                terminalLine(data.step);
              }
              if (data.done && data.result) {
                if (spinner) spinner.style.display = "none";
                resolve(data.result);
                return;
              }
            } catch {}
          }
          read();
        }).catch(reject);
      }
      read();
    }).catch(reject);
  });
}

/* ── Terminal helpers ───────────────────────────────── */
function clearTerminal() {
  document.getElementById("terminal-body").innerHTML = "";
}

function terminalLine(text, cls = "") {
  const body = document.getElementById("terminal-body");
  const div  = document.createElement("div");
  div.className = "terminal-line" + (cls ? " " + cls : "");
  div.textContent = text;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

/* ── Render results ─────────────────────────────────── */
function renderResults(result) {
  document.getElementById("results-section").style.display = "block";

  const risk = result.risk || {};
  renderRiskBanner(risk);
  renderExecutive(result);
  renderZeroDay(result.zero_day || {});
  renderTechnical(result);
  renderMitreResults(result.existing?.mitre_hits || []);
  renderRemediation(result);
  document.getElementById("json-pre").textContent = JSON.stringify(result, null, 2);

  // Zero-day alert banner
  if ((result.zero_day?.zero_day_score || 0) > 60) {
    const b = document.getElementById("zd-alert-banner");
    const sc = result.zero_day.zero_day_score.toFixed(1);
    document.getElementById("zd-alert-text").textContent =
      `ZERO-DAY THREAT DETECTED — Score: ${sc}/100 — Level: ${result.zero_day.label}`;
    b.style.display = "flex";
  }

  // Update global MITRE heatmap
  buildMitreHeatmap(result.existing?.mitre_hits || []);
}

function renderRiskBanner(risk) {
  const level    = risk.level || "INFO";
  const composite= (risk.composite_score || 0).toFixed(1);
  const lbl      = document.getElementById("risk-level-label");
  lbl.textContent = level;
  lbl.className   = "risk-level " + level;

  document.getElementById("risk-scores-detail").innerHTML = `
    <div>Ensemble: <strong>${(risk.ensemble_score||0).toFixed(1)}</strong></div>
    <div>Zero-Day: <strong>${(risk.zero_day_score||0).toFixed(1)}</strong></div>
    <div>Rules:    <strong>${(risk.rule_score||0).toFixed(1)}</strong></div>
    <div>Alert:    <strong style="color:${risk.alert?'var(--neon-red)':'var(--neon-green)'}">${risk.alert?'YES':'NO'}</strong></div>
  `;

  // Gauge arc
  drawGauge(composite);
}

function drawGauge(score) {
  const canvas = document.getElementById("risk-gauge");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, 160, 80);

  const cx = 80, cy = 80, r = 60;
  const startA = Math.PI, endA = Math.PI + (score / 100) * Math.PI;

  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, 2 * Math.PI);
  ctx.strokeStyle = "rgba(255,255,255,0.06)";
  ctx.lineWidth = 14;
  ctx.lineCap = "round";
  ctx.stroke();

  const colour = score >= 80 ? "#ff003c" : score >= 60 ? "#ff6b00" : score >= 40 ? "#ffcc00" : "#00d4ff";
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, endA);
  ctx.strokeStyle = colour;
  ctx.lineWidth = 14;
  ctx.lineCap = "round";
  ctx.stroke();

  ctx.fillStyle = "#e0e6ef";
  ctx.font = "bold 20px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(score.toFixed(0), cx, cy - 10);
  ctx.font = "11px sans-serif";
  ctx.fillStyle = "#6b7a99";
  ctx.fillText("/ 100", cx, cy + 8);
}

function renderExecutive(result) {
  const el = document.getElementById("res-executive");
  const v  = result.ensemble?.verdict || {};
  const expl = v.explanation || "Analysis complete.";
  const models = v.model_details || [];

  let html = `<h3 class="card-title">Executive Summary</h3>
    <p style="margin-bottom:20px;line-height:1.7;">${esc(expl)}</p>
    <h4 style="font-size:12px;color:var(--neon-cyan);letter-spacing:1px;margin-bottom:12px;">MODEL SCORES</h4>`;

  for (const m of models) {
    const sc  = m.score || 0;
    const col = sc >= 75 ? "var(--neon-red)" : sc >= 50 ? "var(--neon-orange)" : sc >= 25 ? "var(--neon-yellow)" : "var(--neon-green)";
    html += `<div class="model-row">
      <span class="model-name">${esc(m.model.replace(/_/g,' '))}</span>
      <div class="score-bar-wrap"><div class="score-bar-fill" style="width:${sc}%;background:${col}"></div></div>
      <span class="score-val" style="color:${col}">${sc}</span>
    </div>`;
  }
  el.innerHTML = html;
}

function renderZeroDay(zd) {
  const el = document.getElementById("res-zeroday");
  if (!zd.zero_day_score) { el.innerHTML = "<p class='muted'>No zero-day signals detected.</p>"; return; }
  const sc = (zd.zero_day_score||0).toFixed(1);
  let html = `<h3 class="card-title">Zero-Day Intelligence</h3>
    <p style="margin-bottom:16px;">Score: <strong style="color:${sc>60?'var(--neon-red)':'var(--neon-orange)'}">${sc}/100</strong> — ${esc(zd.label||'')} — Action: <strong>${esc((zd.action||'').replace(/_/g,' ').toUpperCase())}</strong></p>`;

  for (const sig of (zd.signals||[])) {
    const col = sig.score > 60 ? "var(--neon-red)" : sig.score > 30 ? "var(--neon-orange)" : "var(--text-muted)";
    html += `<div class="signal-item">
      <div class="signal-method">${esc(sig.method.replace(/_/g,' '))}
        <span class="signal-score" style="color:${col}">${sig.score.toFixed(1)}</span>
      </div>
      <div class="signal-evidence">${esc(sig.evidence||'')}</div>
    </div>`;
  }
  if (zd.yara_rule) {
    html += `<h4 style="margin:16px 0 8px;font-size:12px;color:var(--neon-cyan)">Auto-Generated YARA Rule</h4>
      <pre class="json-dump" style="font-size:11px">${esc(zd.yara_rule)}</pre>`;
  }
  if (zd.hunting_queries) {
    html += `<h4 style="margin:16px 0 8px;font-size:12px;color:var(--neon-cyan)">Hunting Queries</h4>`;
    for (const [k,v] of Object.entries(zd.hunting_queries||{})) {
      html += `<p style="margin-bottom:4px;font-size:11px;color:var(--text-muted)">${k.toUpperCase()}</p>
        <pre class="json-dump" style="font-size:11px;margin-bottom:10px">${esc(v)}</pre>`;
    }
  }
  el.innerHTML = html;
}

function renderTechnical(result) {
  const el  = document.getElementById("res-technical");
  const ex  = result.existing || {};
  let html  = `<h3 class="card-title">Technical Details</h3>`;

  // YARA hits
  const yara = ex.yara_hits || [];
  if (yara.length) {
    html += `<h4 style="color:var(--neon-cyan);font-size:12px;margin-bottom:8px">YARA MATCHES (${yara.length})</h4>
      <table class="hit-table"><thead><tr><th>Rule</th><th>Strings Matched</th></tr></thead><tbody>`;
    yara.forEach(h => {
      html += `<tr><td class="sev-high">${esc(h.rule)}</td><td>${esc((h.strings||[]).slice(0,3).join(', '))}</td></tr>`;
    });
    html += `</tbody></table><br>`;
  }

  // Sigma hits
  const sigma = ex.sigma_hits || [];
  if (sigma.length) {
    html += `<h4 style="color:var(--neon-cyan);font-size:12px;margin-bottom:8px">SIGMA RULE MATCHES (${sigma.length})</h4>
      <table class="hit-table"><thead><tr><th>Title</th><th>Level</th><th>Matched</th></tr></thead><tbody>`;
    sigma.forEach(h => {
      const cls = `sev-${(h.level||'low').toLowerCase()}`;
      html += `<tr><td>${esc(h.title)}</td><td class="${cls}">${esc(h.level)}</td><td>${esc((h.matched||[]).slice(0,3).join(', '))}</td></tr>`;
    });
    html += `</tbody></table><br>`;
  }

  // CVEs
  const cves = ex.cves || [];
  if (cves.length) {
    html += `<h4 style="color:var(--neon-cyan);font-size:12px;margin-bottom:8px">CVE CORRELATIONS (${cves.length})</h4>
      <table class="hit-table"><thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Description</th></tr></thead><tbody>`;
    cves.forEach(c => {
      const cls = `sev-${(c.severity||'info').toLowerCase()}`;
      html += `<tr><td class="sev-critical">${esc(c.cve_id)}</td><td>${c.cvss_score||0}</td><td class="${cls}">${esc(c.severity)}</td><td>${esc((c.description||'').slice(0,80))}</td></tr>`;
    });
    html += `</tbody></table>`;
  }

  // IOCs
  const iocs = ex.iocs || {};
  if (Object.values(iocs).some(a => a && a.length)) {
    html += `<br><h4 style="color:var(--neon-cyan);font-size:12px;margin-bottom:8px">EXTRACTED IOCs</h4>`;
    for (const [k,v] of Object.entries(iocs)) {
      if (v && v.length)
        html += `<p style="margin-bottom:4px"><span style="color:var(--text-muted);font-size:11px">${k.toUpperCase()}: </span>${v.map(x=>`<span class="mitre-badge">${esc(x)}</span>`).join('')}</p>`;
    }
  }

  if (!html.includes("table")) html += `<p class="muted">No signature matches found.</p>`;
  el.innerHTML = html;
}

function renderMitreResults(hits) {
  const el = document.getElementById("res-mitre-res");
  if (!hits.length) { el.innerHTML = "<p class='muted'>No MITRE ATT&CK techniques detected.</p>"; return; }
  let html = `<h3 class="card-title">MITRE ATT&CK — ${hits.length} Technique(s) Detected</h3>
    <table class="hit-table"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Matched On</th></tr></thead><tbody>`;
  hits.forEach(h => {
    html += `<tr>
      <td class="sev-critical" style="font-family:var(--font-mono)">${esc(h.technique_id)}</td>
      <td>${esc(h.name)}</td>
      <td style="color:var(--text-muted)">${esc(h.tactic)}</td>
      <td>${(h.matched_on||[]).slice(0,3).map(x=>`<code style="font-size:10px;background:rgba(0,0,0,0.3);padding:1px 5px;border-radius:2px">${esc(x)}</code>`).join(' ')}</td>
    </tr>`;
  });
  html += `</tbody></table>`;
  el.innerHTML = html;
}

function renderRemediation(result) {
  const el   = document.getElementById("res-remediation");
  const risk = result.risk || {};
  const ex   = result.existing || {};
  const zd   = result.zero_day || {};

  const steps = deriveRemediationSteps(risk, ex, zd);
  let html = `<h3 class="card-title">Remediation Steps</h3>`;
  steps.forEach((s, i) => {
    html += `<div class="remedy-step">
      <div class="remedy-num">${i+1}</div>
      <div class="remedy-text">${esc(s)}</div>
    </div>`;
  });
  el.innerHTML = html;
}

function deriveRemediationSteps(risk, existing, zd) {
  const steps = [];
  const level = risk.level || "INFO";
  if (["CRITICAL","HIGH"].includes(level))
    steps.push("Isolate affected host(s) from the network immediately to prevent lateral movement.");
  if ((existing.yara_hits||[]).length)
    steps.push(`Quarantine files matching YARA rules: ${(existing.yara_hits||[]).slice(0,3).map(h=>h.rule).join(', ')}. Run full AV scan.`);
  if ((existing.cves||[]).length)
    steps.push(`Apply patches for: ${(existing.cves||[]).slice(0,3).map(c=>c.cve_id).join(', ')}.`);
  const mitre = existing.mitre_hits || [];
  if (mitre.some(h => (h.technique_id||'').startsWith('T1059')))
    steps.push("Audit PowerShell execution policy. Enable ScriptBlock logging. Review all encoded commands.");
  if (mitre.some(h => (h.technique_id||'').startsWith('T1003')))
    steps.push("Rotate all credentials on affected systems. Check for LSASS/credential exposure.");
  if (mitre.some(h => (h.technique_id||'').startsWith('T1071')))
    steps.push("Block identified C2 IPs and domains at firewall and DNS. Capture traffic for forensic analysis.");
  if ((zd.zero_day_score||0) > 60)
    steps.push("Novel attack pattern detected. Preserve memory image and logs. Engage incident response team immediately.");
  if (!steps.length)
    steps.push("No immediate action required. Continue monitoring. Review logs periodically.");
  return steps.slice(0, 6);
}

/* ── MITRE heatmap (D3) ─────────────────────────────── */
const MITRE_TACTICS = [
  "Reconnaissance","Resource Development","Initial Access","Execution",
  "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
  "Discovery","Lateral Movement","Collection","Command & Control",
  "Exfiltration","Impact"
];

function buildMitreHeatmap(hitsList) {
  const container = document.getElementById("mitre-heatmap");
  container.innerHTML = "";

  const hitMap = {};
  (hitsList||[]).forEach(h => { hitMap[h.technique_id] = true; });

  const cellW = 70, cellH = 60, cols = 7;
  const rows  = Math.ceil(MITRE_TACTICS.length / cols);
  const W = cellW * cols, H = cellH * rows;

  const svg = d3.select(container).append("svg")
    .attr("width", W).attr("height", H)
    .style("overflow", "visible");

  MITRE_TACTICS.forEach((tactic, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const hasHit = hitsList && hitsList.some(h => (h.tactic||'').toLowerCase() === tactic.toLowerCase().replace('&','and').replace(' & ',' and '));
    const g = svg.append("g").attr("transform", `translate(${col*cellW},${row*cellH})`);

    g.append("rect")
      .attr("width", cellW - 3)
      .attr("height", cellH - 3)
      .attr("rx", 4)
      .attr("fill", hasHit ? "rgba(255,0,60,0.3)" : "rgba(255,255,255,0.04)")
      .attr("stroke", hasHit ? "#ff003c" : "rgba(255,255,255,0.08)")
      .attr("stroke-width", hasHit ? 1.5 : 0.5);

    g.append("text")
      .attr("x", (cellW-3)/2).attr("y", (cellH-3)/2)
      .attr("text-anchor", "middle").attr("dominant-baseline", "middle")
      .attr("font-size", "9px")
      .attr("font-weight", hasHit ? "700" : "400")
      .attr("fill", hasHit ? "#ff003c" : "#6b7a99")
      .text(tactic.length > 12 ? tactic.slice(0, 11) + "…" : tactic);
  });
}

/* ── Reports list ───────────────────────────────────── */
function addReport(result) {
  const risk    = result.risk || {};
  const level   = risk.level || "INFO";
  const score   = (risk.composite_score||0).toFixed(1);
  const ts      = new Date().toLocaleTimeString();
  state.reports.unshift({ score, level, ts, result });

  const list = document.getElementById("reports-list");
  const colMap = {CRITICAL:"var(--neon-red)",HIGH:"var(--neon-orange)",MEDIUM:"var(--neon-yellow)",LOW:"var(--neon-cyan)",INFO:"var(--text-muted)"};
  const div = document.createElement("div");
  div.className = "report-item";
  div.innerHTML = `<div class="report-score" style="color:${colMap[level]}">${score}</div>
    <div class="report-meta">
      <div>${level} — ${(result.existing?.yara_hits||[]).length} YARA hits · ${(result.existing?.mitre_hits||[]).length} MITRE techniques</div>
      <div class="report-time">${ts}</div>
    </div>
    <button class="btn btn--secondary" style="font-size:11px" onclick="reloadReport(${state.reports.length-1})">View</button>`;
  list.prepend(div);
}

function reloadReport(idx) {
  const entry = state.reports[idx];
  if (!entry) return;
  state.lastResult = entry.result;
  renderResults(entry.result);
  showTab("analyze");
  document.querySelectorAll(".pill").forEach((p,i) => i===0 && p.classList.add("pill--active"));
}

/* ── Export ─────────────────────────────────────────── */
async function exportPDF() {
  if (!state.lastResult) { alert("Run an analysis first."); return; }
  const r = await fetch("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      log_file:  btoa(unescape(encodeURIComponent(state.logText||""))),
      ioc:       document.getElementById("ioc-input").value.trim(),
      format:    "pdf",
    }),
  });
  if (r.ok) {
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `soc_report_${Date.now()}.pdf`;
    a.click(); URL.revokeObjectURL(url);
  }
}

function exportJSON() {
  if (!state.lastResult) { alert("Run an analysis first."); return; }
  const blob = new Blob([JSON.stringify(state.lastResult, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a"); a.href = url; a.download = `soc_report_${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(url);
}

function exportCSV() {
  if (!state.lastResult) { alert("Run an analysis first."); return; }
  const r    = state.lastResult;
  const rows = [
    ["Field","Value"],
    ["Composite Score", r.risk?.composite_score||0],
    ["Level", r.risk?.level||""],
    ["Alert", r.risk?.alert||false],
    ["Zero-Day Score", r.zero_day?.zero_day_score||0],
    ["YARA Hits", (r.existing?.yara_hits||[]).length],
    ["MITRE Techniques", (r.existing?.mitre_hits||[]).length],
    ["CVEs Found", (r.existing?.cves||[]).length],
  ];
  const csv  = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a"); a.href = url; a.download = `soc_report_${Date.now()}.csv`;
  a.click(); URL.revokeObjectURL(url);
}

function downloadPDFfromB64(b64) {
  const raw  = atob(b64);
  const arr  = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  const blob = new Blob([arr], { type: "application/pdf" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a"); a.href = url; a.download = `soc_report_${Date.now()}.pdf`;
  a.click(); URL.revokeObjectURL(url);
}

/* ── Helpers ────────────────────────────────────────── */
function esc(str) {
  return String(str||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
