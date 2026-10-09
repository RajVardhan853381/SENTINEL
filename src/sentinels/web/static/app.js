// src/sentinels/web/static/app.js
/**
 * Sentinels Security Audit Cockpit - Executive Light Theme Engine
 * Manages:
 * 1. 5-Stage Live Scan Pipeline telemetry and animations
 * 2. Deep explanation of each stage and what the agent mesh does
 * 3. PDF report deconstruction and inline document previewer
 * 4. Interactive unified git diff inspector
 */

document.addEventListener("DOMContentLoaded", () => {
  initSystemStatus();
  loadPdfSections();
  loadFindings();
  setupEventListeners();
});

// State
let currentFindings = [];
let scanInProgress = false;

// -----------------------------------------------------------------------------
// 1. INITIALIZATION & TELEMETRY STATUS
// -----------------------------------------------------------------------------
async function initSystemStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    const providerBadge = document.getElementById("label-provider");
    if (providerBadge) {
      providerBadge.textContent = `${data.provider} ${data.model} Active`;
    }
    logToTerminal(`[SYSTEM] Sentinels Engine online. Active Model: ${data.provider} (${data.model})`);
  } catch (err) {
    console.warn("Status check failed:", err);
  }
}

// -----------------------------------------------------------------------------
// 2. PDF DECONSTRUCTION & SECTIONS EXPLAINER (Solid Light Theme)
// -----------------------------------------------------------------------------
async function loadPdfSections() {
  const container = document.getElementById("pdf-sections-list");
  if (!container) return;

  try {
    const res = await fetch("/api/pdf/sections");
    const data = await res.json();

    container.innerHTML = data.sections.map(sec => `
      <div class="pdf-section-card p-4 rounded-lg bg-white border border-slate-200 flex flex-col gap-2.5 shadow-xs">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-100 text-indigo-700 border border-slate-300">
              ${sec.badge}
            </span>
            <h4 class="text-sm font-semibold text-slate-900">${sec.title}</h4>
          </div>
          <span class="text-xs text-slate-500 font-mono">PDF Page Content</span>
        </div>
        <p class="text-xs text-slate-600 leading-relaxed">${sec.description}</p>
        <ul class="flex flex-col gap-1.5 pl-4 list-disc text-xs text-slate-500 border-t border-slate-100 pt-2">
          ${sec.details.map(d => `<li>${d}</li>`).join("")}
        </ul>
      </div>
    `).join("");
  } catch (err) {
    container.innerHTML = `<div class="text-xs text-rose-600">Failed to load PDF sections metadata.</div>`;
  }
}

// -----------------------------------------------------------------------------
// 3. FINDINGS MATRIX & UNIFIED GIT DIFF
// -----------------------------------------------------------------------------
async function loadFindings() {
  const tbody = document.getElementById("findings-table-body");
  if (!tbody) return;

  try {
    const res = await fetch("/api/findings");
    const data = await res.json();
    currentFindings = data.findings || [];

    tbody.innerHTML = currentFindings.map((f, idx) => {
      const sevColor = f.severity === "Critical" 
        ? "bg-rose-50 text-rose-700 border-rose-200"
        : (f.severity === "High" ? "bg-amber-50 text-amber-800 border-amber-200" : "bg-sky-50 text-sky-800 border-sky-200");
      
      const lineNum = f.line_start || f.line || 1;

      return `
        <tr class="hover:bg-slate-50 transition-colors">
          <td class="py-3 px-4">
            <div class="flex items-center gap-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${sevColor}">${(f.severity || "INFO").toUpperCase()}</span>
              <span class="font-mono text-slate-900 font-semibold text-xs">${f.cwe || "CWE-Unknown"}</span>
            </div>
          </td>
          <td class="py-3 px-4">
            <div class="font-medium text-slate-900">${f.title || "Untitled Finding"}</div>
            <div class="text-[11px] text-slate-500">${f.owasp || ""}</div>
          </td>
          <td class="py-3 px-4 font-mono text-xs text-slate-600">
            ${f.file || "unknown"}:<span class="text-rose-600 font-bold">${lineNum}</span>
          </td>
          <td class="py-3 px-4">
            <span class="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-300 text-[10px] font-mono font-medium">${f.confidence || "High"}</span>
          </td>
          <td class="py-3 px-4 text-right">
            <button onclick="inspectFindingDiff(${idx})" class="bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-mono px-2.5 py-1 rounded transition-colors shadow-xs">
              Review Patch
            </button>
          </td>
        </tr>
      `;
    }).join("");

    if (currentFindings.length > 0) {
      renderDiff(currentFindings[0]);
    }
  } catch (err) {
    console.error("Failed to load findings:", err);
  }
}

window.inspectFindingDiff = function(index) {
  if (currentFindings[index]) {
    renderDiff(currentFindings[index]);
    if (typeof switchStitchTab === "function") {
      switchStitchTab(2);
    }
  }
};

function renderDiff(finding) {
  const titleEl = document.getElementById("diff-filename");
  const bodyEl = document.getElementById("diff-body");
  if (!bodyEl) return;

  if (titleEl) {
    titleEl.textContent = finding.file;
  }

  const patchLines = (finding.patch || "").split("\n");
  bodyEl.innerHTML = patchLines.map((line, idx) => {
    let lineClass = "diff-line-context";
    let sign = "&nbsp;";
    if (line.startsWith("-")) {
      lineClass = "diff-line-delete";
      sign = "-";
    } else if (line.startsWith("+")) {
      lineClass = "diff-line-add";
      sign = "+";
    } else if (line.startsWith("@@")) {
      lineClass = "text-indigo-800 font-semibold bg-indigo-50/60";
      sign = "@";
    }

    const safeText = line.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return `
      <div class="px-3 py-1 ${lineClass} flex items-center font-mono">
        <span class="w-7 select-none opacity-40 text-right pr-2 text-slate-400">${idx + 1}</span>
        <span class="w-4 select-none font-bold">${sign}</span>
        <span class="pl-2 whitespace-pre">${safeText}</span>
      </div>
    `;
  }).join("");
}

// -----------------------------------------------------------------------------
// 4. LIVE 5-STAGE SCAN PROGRESSION & REAL-TIME EXPLANATION
// -----------------------------------------------------------------------------
async function startLiveScan() {
  if (scanInProgress) return;
  scanInProgress = true;

  const btn = document.getElementById("btn-start-scan");
  const repoInput = document.getElementById("input-repo-url");
  const repoUrl = repoInput ? repoInput.value.trim() : "https://github.com/pallets/flask";

  if (btn) {
    btn.disabled = true;
    btn.classList.add("opacity-60");
    btn.innerHTML = `<span class="material-symbols-outlined text-base animate-spin">progress_activity</span><span>Scanning Target...</span>`;
  }

  const badgeStatus = document.getElementById("badge-pipeline-status");
  if (badgeStatus) {
    badgeStatus.className = "px-2.5 py-0.5 text-xs font-mono font-medium rounded bg-indigo-50 text-indigo-700 border border-indigo-200 animate-pulse";
    badgeStatus.textContent = "INSPECTION ACTIVE";
  }

  // Reset all stages to standby
  for (let s = 1; s <= 5; s++) {
    setStageState(s, "waiting", "Waiting");
  }
  updateOverallProgress(5);
  logToTerminal(`[ORCHESTRATOR] Initializing multi-agent security audit for target: ${repoUrl}`);

  try {
    const response = await fetch("/api/scan/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: repoUrl })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const raw = line.substring(6).trim();
          if (!raw) continue;
          try {
            const eventPayload = JSON.parse(raw);
            handleScanEvent(eventPayload);
          } catch (e) {
            console.error("Failed to parse SSE event:", e);
          }
        }
      }
    }
  } catch (err) {
    console.error("Scan error:", err);
    logToTerminal(`[ERROR] Scan execution interrupted: ${err.message}`);
  } finally {
    scanInProgress = false;
    if (btn) {
      btn.disabled = false;
      btn.classList.remove("opacity-60");
      btn.innerHTML = `<span class="material-symbols-outlined text-base">bolt</span><span>Initiate Multi-Agent Audit</span>`;
    }
    if (badgeStatus) {
      badgeStatus.className = "px-2.5 py-0.5 text-xs font-mono font-medium rounded bg-emerald-50 text-emerald-800 border border-emerald-300";
      badgeStatus.textContent = "AUDIT COMPLETE";
    }
    updateOverallProgress(100);
  }
}

function handleScanEvent(evt) {
  if (evt.event === "stage_update") {
    const stage = evt.data;
    const stageNum = stage.stage;

    for (let prev = 1; prev < stageNum; prev++) {
      setStageState(prev, "completed", "100% Done");
    }

    setStageState(stageNum, "active", "Executing...");
    updateOverallProgress(stage.progress);

    updateStageExplanation(
      stage.title,
      stage.explanation
    );

    if (stage.logs && Array.isArray(stage.logs)) {
      stage.logs.forEach(logMsg => {
        logToTerminal(`${evt.timestamp} ${logMsg}`);
      });
    }
  } else if (evt.event === "scan_complete") {
    for (let s = 1; s <= 5; s++) {
      setStageState(s, "completed", "Verified");
    }
    logToTerminal(`[DELIVERABLE] Executive PDF generated cleanly at reports/pallets_flask_report.pdf`);
    logToTerminal(`[COMPLETION] Overall risk: ${evt.data.posture}. Verified ${evt.data.total_verified} actionable findings.`);
    loadFindings();
    loadPdfSections();
  }
}

function setStageState(stageNum, state, statText) {
  const card = document.getElementById(`card-stage-${stageNum}`);
  const icon = document.getElementById(`icon-stage-${stageNum}`);
  const stat = document.getElementById(`stat-stage-${stageNum}`);

  if (!card) return;

  card.classList.remove("active", "completed");

  if (state === "active") {
    card.classList.add("active");
    if (icon) {
      icon.textContent = "motion_photos_on";
      icon.className = "material-symbols-outlined text-indigo-600 text-base animate-spin";
    }
    if (stat) {
      stat.textContent = statText;
      stat.className = "text-indigo-600 font-bold";
    }
  } else if (state === "completed") {
    card.classList.add("completed");
    if (icon) {
      icon.textContent = "check_circle";
      icon.className = "material-symbols-outlined text-emerald-600 text-base";
      icon.style.fontVariationSettings = "'FILL' 1";
    }
    if (stat) {
      stat.textContent = statText;
      stat.className = "text-emerald-700 font-semibold";
    }
  } else {
    if (icon) {
      icon.textContent = "radio_button_unchecked";
      icon.className = "material-symbols-outlined text-slate-400 text-base";
    }
    if (stat) {
      stat.textContent = statText;
      stat.className = "text-slate-500";
    }
  }
}

function updateOverallProgress(pct) {
  const bar = document.getElementById("bar-overall-progress");
  const label = document.getElementById("label-progress-pct");
  if (bar) bar.style.width = `${pct}%`;
  if (label) label.textContent = `${pct}%`;
}

function updateStageExplanation(title, body) {
  const titleEl = document.getElementById("exp-title");
  const bodyEl = document.getElementById("exp-body");
  if (titleEl) titleEl.textContent = title;
  if (bodyEl) bodyEl.textContent = body;
}

function logToTerminal(msg) {
  const term = document.getElementById("terminal-logs");
  if (!term) return;

  const div = document.createElement("div");
  if (msg.includes("[ERROR]")) {
    div.className = "text-rose-400 font-bold";
  } else if (msg.includes("[VERIFIED_EXPLOIT]")) {
    div.className = "text-rose-300 bg-rose-950/60 p-1 rounded border border-rose-500/30";
  } else if (msg.includes("[MCP_TRIAGE]")) {
    div.className = "text-cyan-300";
  } else if (msg.includes("[PATCH_SYNTHESIS]") || msg.includes("[DELIVERABLE]")) {
    div.className = "text-emerald-300";
  } else {
    div.className = "text-slate-300";
  }

  div.textContent = msg;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

// -----------------------------------------------------------------------------
// 5. EVENT LISTENERS & TABS
// -----------------------------------------------------------------------------
function setupEventListeners() {
  const btnScan = document.getElementById("btn-start-scan");
  if (btnScan) {
    btnScan.addEventListener("click", startLiveScan);
  }

  const btnClearLogs = document.getElementById("btn-clear-logs");
  if (btnClearLogs) {
    btnClearLogs.addEventListener("click", () => {
      const term = document.getElementById("terminal-logs");
      if (term) term.innerHTML = "";
    });
  }

  const tabs = [
    { btn: "tab-btn-sections", content: "tab-content-sections", id: "sections" },
    { btn: "tab-btn-findings", content: "tab-content-findings", id: "findings" },
    { btn: "tab-btn-diff", content: "tab-content-diff", id: "diff" },
    { btn: "tab-btn-compliance", content: "tab-content-compliance", id: "compliance" }
  ];

  tabs.forEach(t => {
    const b = document.getElementById(t.btn);
    if (b) {
      b.addEventListener("click", () => switchTab(t.id));
    }
  });

  const stageExplanations = {
    1: {
      title: "Stage 1: Shallow Git Ingestion & AST Manifest Clustering",
      desc: "Clones the target repository with shallow depth (--depth 1) into an isolated ephemeral sandbox. Python code parses the file tree without spending LLM tokens, categorizes source languages, and clusters directory scopes to prevent context-window blowup."
    },
    2: {
      title: "Stage 2: Deterministic Static SAST & Secrets Detection",
      desc: "Executes pre-compiled regex engines to find exposed credentials (AWS tokens, GitHub keys, Slack webhooks) and invokes Semgrep rulesets (--config auto) across AST nodes, flagging candidate code patterns for agent verification."
    },
    3: {
      title: "Stage 3: Multi-Agent Deep Triage & False-Positive Verification",
      desc: "Manager Agent delegates specific directories to Worker Agents. Agents call the FastMCP read_file tool to inspect 20 lines around each candidate, evaluating untrusted user input paths and discarding unexploitable false positives."
    },
    4: {
      title: "Stage 4: Autonomous One-Click Git Patch Synthesis",
      desc: "Workers formulate exact, syntax-valid unified git diffs (--- / +++) replacing vulnerable code with secure implementations (e.g. parameterized queries, bound variables), checked against AST regression guards."
    },
    5: {
      title: "Stage 5: Multi-Format Deliverables Compilation",
      desc: "Manager compiles the executive narrative, runs Pydantic schema validation, and invokes Python ReportLab to generate the Executive White-Theme PDF report, Developer Markdown, and OASIS SARIF 2.1.0."
    }
  };

  for (let s = 1; s <= 5; s++) {
    const card = document.getElementById(`card-stage-${s}`);
    if (card) {
      card.addEventListener("click", () => {
        const exp = stageExplanations[s];
        if (exp) {
          updateStageExplanation(exp.title, exp.desc);
        }
      });
    }
  }

  // PDF Preview Modal
  const modal = document.getElementById("modal-pdf");
  const btnOpenModal1 = document.getElementById("btn-quick-pdf");
  const btnOpenModal2 = document.getElementById("btn-preview-pdf-modal");
  const btnCloseModal = document.getElementById("btn-close-pdf-modal");

  const openPdf = () => {
    if (modal) modal.classList.remove("hidden");
  };
  const closePdf = () => {
    if (modal) modal.classList.add("hidden");
  };

  if (btnOpenModal1) btnOpenModal1.addEventListener("click", openPdf);
  if (btnOpenModal2) btnOpenModal2.addEventListener("click", openPdf);
  if (btnCloseModal) btnCloseModal.addEventListener("click", closePdf);

  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closePdf();
    });
  }

  // Copy Markdown PR button
  const btnCopyMd = document.getElementById("btn-copy-md");
  if (btnCopyMd) {
    btnCopyMd.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/markdown");
        const data = await res.json();
        await navigator.clipboard.writeText(data.content);
        btnCopyMd.innerHTML = `<span class="material-symbols-outlined text-sm text-emerald-600">check</span><span>Copied!</span>`;
        setTimeout(() => {
          btnCopyMd.innerHTML = `<span class="material-symbols-outlined text-sm">content_copy</span><span>Copy PR MD</span>`;
        }, 2000);
      } catch (e) {
        alert("Failed to copy markdown report.");
      }
    });
  }

  // View SARIF button
  const btnViewSarif = document.getElementById("btn-view-sarif");
  if (btnViewSarif) {
    btnViewSarif.addEventListener("click", (e) => {
      e.preventDefault();
      window.open("/api/sarif", "_blank");
    });
  }
}

function switchTab(activeId) {
  const map = { "sections": 0, "findings": 1, "diff": 2, "compliance": 3 };
  if (typeof switchStitchTab === "function" && activeId in map) {
    switchStitchTab(map[activeId]);
  }
}
