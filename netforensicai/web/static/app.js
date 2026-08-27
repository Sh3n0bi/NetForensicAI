const API = "/api";

let _capturePollTimer = null;

function stopCapturePolling() {
  if (_capturePollTimer) {
    clearInterval(_capturePollTimer);
    _capturePollTimer = null;
  }
}

async function apiGet(path) {
  const res = await fetch(API + path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// Sent on every state-changing request - see the CSRF paragraph in
// web/app.py's module docstring. The server rejects POST/PUT/PATCH/DELETE
// without it.
const CSRF_HEADERS = { "X-Requested-With": "NetForensicAI" };

async function apiPost(path, body) {
  const res = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...CSRF_HEADERS },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function apiUpload(path, formData) {
  // No Content-Type header: the browser sets multipart/form-data with the
  // correct boundary itself when the body is a FormData instance.
  const res = await fetch(API + path, { method: "POST", body: formData, headers: CSRF_HEADERS });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "text") e.textContent = v;
      else if (k === "html") e.innerHTML = v;
      else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
  }
  if (children) for (const c of children) e.appendChild(c);
  return e;
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

function cssClass(s) {
  return String(s == null ? "" : s).replace(/\s+/g, "-");
}

function toast(message, isError) {
  const t = document.getElementById("toast");
  t.textContent = message;
  t.className = "toast" + (isError ? " error" : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => {
    t.hidden = true;
  }, 4000);
}

// --- Router ---

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);

function parseHash() {
  return location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
}

async function route() {
  const parts = parseHash();
  const nav = document.getElementById("case-nav");
  const app = document.getElementById("app");

  if (parts[0] === "case" && parts[1]) {
    const caseId = parts[1];
    const tab = parts[2] || "overview";
    nav.hidden = false;
    nav.querySelectorAll("a[data-tab]").forEach((a) => {
      a.classList.toggle("active", a.dataset.tab === tab);
      a.href = `#/case/${caseId}/${a.dataset.tab}`;
    });
    app.innerHTML = "";
    try {
      const c = await apiGet(`/cases/${caseId}`);
      document.getElementById("case-nav-name").textContent = `${c.case_id} · ${c.name}`;
      await renderCaseTab(app, c, tab, parts.slice(3));
    } catch (e) {
      nav.hidden = true;
      app.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  } else if (parts[0] === "settings") {
    stopCapturePolling();
    nav.hidden = true;
    document.getElementById("case-nav-name").textContent = "";
    app.innerHTML = "";
    await renderSettings(app);
  } else {
    nav.hidden = true;
    document.getElementById("case-nav-name").textContent = "";
    await renderCaseList(app);
  }
}

// --- Settings (API keys + provider preferences) ---

const SECRET_FIELDS = [
  ["virustotal_api_key", "VirusTotal API key", "Threat-intel lookups for IPs and file hashes"],
  ["anthropic_api_key", "Anthropic API key", "AI assistant - Claude"],
  ["openai_api_key", "OpenAI API key", "AI assistant - GPT"],
  ["gemini_api_key", "Gemini API key", "AI assistant - Google"],
];

async function renderSettings(app) {
  app.appendChild(el("h1", { text: "Settings" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Optional API keys, saved once instead of passed on every command. Stored outside your cases " +
        "directory, so they are never included in a `case export` archive. Everything here is optional - " +
        "parsing, correlation, timeline, and the bundled detection rules all work fully offline without any key.",
    })
  );

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);
  panel.appendChild(el("div", { class: "loading", text: "Loading..." }));

  let data;
  try {
    data = await apiGet("/settings");
  } catch (e) {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    return;
  }

  panel.innerHTML = "";
  panel.appendChild(el("h3", { text: "API Keys" }));
  const inputs = {};

  for (const [key, label, help] of SECRET_FIELDS) {
    const info = data.secrets[key] || {};
    const row = el("div", { class: "setting-row" });
    row.appendChild(el("label", { text: label }));
    const input = el("input", {
      type: "password",
      placeholder: info.set ? `Saved (${info.hint}) - type to replace` : help,
    });
    inputs[key] = input;
    row.appendChild(input);

    const status = el("span", {
      class: "setting-status" + (info.set ? " is-set" : ""),
      text: info.set ? `set via ${info.source}` : "not set",
    });
    row.appendChild(status);
    panel.appendChild(row);

    if (info.overridden_by_env) {
      panel.appendChild(
        el("div", {
          class: "setting-note",
          text: `${info.env_var} is set in your environment and takes priority over anything saved here.`,
        })
      );
    }
  }

  panel.appendChild(el("h3", { text: "AI Defaults", style: "margin-top:18px;" }));

  let providerInfo = { providers: ["anthropic", "openai", "ollama", "gemini"], default_models: {} };
  try {
    providerInfo = await apiGet("/ai-providers");
  } catch (e) {
    /* keep the fallback list */
  }

  const providerRow = el("div", { class: "setting-row" });
  providerRow.appendChild(el("label", { text: "Default AI provider" }));
  const providerSelect = selectEl(providerInfo.providers, data.preferences.ai_provider || "anthropic");
  providerRow.appendChild(providerSelect);
  providerRow.appendChild(el("span", { class: "setting-status", text: "" }));
  panel.appendChild(providerRow);

  const modelRow = el("div", { class: "setting-row" });
  modelRow.appendChild(el("label", { text: "Default model (optional)" }));
  const modelInput = el("input", {
    type: "text",
    value: data.preferences.ai_model || "",
    placeholder: "Leave blank to use each provider's default",
  });
  modelRow.appendChild(modelInput);
  modelRow.appendChild(el("span", { class: "setting-status", text: "" }));
  panel.appendChild(modelRow);

  const ollamaRow = el("div", { class: "setting-row" });
  ollamaRow.appendChild(el("label", { text: "Ollama server URL" }));
  const ollamaInput = el("input", {
    type: "text",
    value: data.preferences.ollama_base_url || "",
    placeholder: "http://localhost:11434",
  });
  ollamaRow.appendChild(ollamaInput);
  ollamaRow.appendChild(el("span", { class: "setting-status", text: "" }));
  panel.appendChild(ollamaRow);

  const actions = el("div", { class: "filter-bar", style: "margin-top:16px;" });
  const saveBtn = el("button", { text: "Save Settings" });
  actions.appendChild(saveBtn);
  panel.appendChild(actions);

  panel.appendChild(
    el("div", {
      class: "subtitle",
      style: "margin-top:6px; font-size:12px;",
      text: `Saved to ${data.config_path}`,
    })
  );

  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    try {
      const body = {
        ai_provider: providerSelect.value,
        ai_model: modelInput.value.trim(),
        ollama_base_url: ollamaInput.value.trim(),
      };
      // Only send keys the user actually typed into: an untouched field
      // must leave the saved key alone, not clear it.
      for (const [key] of SECRET_FIELDS) {
        if (inputs[key].value.trim()) body[key] = inputs[key].value.trim();
      }
      await apiPost("/settings", body);
      toast("Settings saved.");
      // Re-render from the server's masked view so the fields show the
      // newly-saved state (and clear the plaintext the user just typed).
      const container = document.getElementById("app");
      container.innerHTML = "";
      await renderSettings(container);
    } catch (e) {
      toast("Save failed: " + e.message, true);
      saveBtn.disabled = false;
    }
  });

  // --- connection tests ---
  panel.appendChild(el("h3", { text: "Test Connections", style: "margin-top:18px;" }));
  panel.appendChild(
    el("div", {
      class: "subtitle",
      style: "font-size:12px;",
      text: "Makes one real request to confirm a credential works, rather than finding out mid-investigation.",
    })
  );
  const testBar = el("div", { class: "filter-bar" });
  const testResult = el("div", { style: "margin-top:8px;" });
  for (const target of ["virustotal", "anthropic", "openai", "gemini", "ollama"]) {
    const btn = el("button", { class: "secondary", text: target });
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      testResult.innerHTML = "";
      testResult.appendChild(el("div", { class: "loading", text: `Testing ${target}...` }));
      try {
        const r = await apiPost("/settings/test", { target });
        testResult.innerHTML = "";
        testResult.appendChild(
          el("div", { class: r.ok ? "lead" : "error-box", text: `${target}: ${r.message}` })
        );
      } catch (e) {
        testResult.innerHTML = "";
        testResult.appendChild(el("div", { class: "error-box", text: `${target}: ${e.message}` }));
      } finally {
        btn.disabled = false;
      }
    });
    testBar.appendChild(btn);
  }
  panel.appendChild(testBar);
  panel.appendChild(testResult);
}

async function renderCaseTab(app, c, tab, rest) {
  stopCapturePolling(); // leaving (or re-rendering) any tab cancels a live capture-status poll loop
  if (tab === "evidence") return renderEvidence(app, c);
  if (tab === "timeline") return renderTimeline(app, c);
  if (tab === "entities") return renderEntities(app, c, rest[0]);
  if (tab === "findings") return renderFindings(app, c);
  if (tab === "audit") return renderAudit(app, c);
  if (tab === "detections") return renderDetections(app, c);
  if (tab === "attack") return renderAttack(app, c);
  if (tab === "reports") return renderReports(app, c);
  if (tab === "capture") return renderCapture(app, c);
  return renderOverview(app, c);
}

// --- Case list ---

async function renderCaseList(app) {
  app.innerHTML = "";
  app.appendChild(el("h1", { text: "Cases" }));
  app.appendChild(el("div", { class: "subtitle", text: "Local-first DFIR investigation platform" }));
  const list = el("div", {});
  app.appendChild(list);
  try {
    const cases = await apiGet("/cases");
    if (!cases.length) {
      list.appendChild(
        el("div", {
          class: "empty",
          text: 'No cases found. Create one with: netforensic case create --name "..."',
        })
      );
      return;
    }
    for (const c of cases) {
      const card = el("a", { class: "case-card", href: `#/case/${c.case_id}/overview` });
      card.innerHTML = `
        <div class="id">${escapeHtml(c.case_id)}</div>
        <div class="name">${escapeHtml(c.name)}</div>
        <div class="meta">
          <span class="badge badge-${cssClass(c.status)}">${escapeHtml(c.status)}</span>
          &nbsp; ${escapeHtml(c.investigator)} &nbsp; created ${escapeHtml((c.created_at || "").split("T")[0])}
        </div>`;
      list.appendChild(card);
    }
  } catch (e) {
    list.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
  }
}

// --- Overview ---

function renderOverview(app, c) {
  app.appendChild(el("h1", { text: c.name }));
  app.appendChild(el("div", { class: "subtitle", text: c.description || "No description." }));

  const stats = el("div", { class: "grid-stats" });
  const statDefs = [
    ["Status", c.status],
    ["Investigator", c.investigator],
    ["Evidence", c.evidence_count],
    ["Events", c.event_count],
    ["Entities", c.entity_count],
    ["Findings", c.finding_count],
    ["Detections", c.detection_count],
  ];
  for (const [l, n] of statDefs) {
    stats.appendChild(el("div", { class: "stat" }, [el("div", { class: "n", text: n }), el("div", { class: "l", text: l })]));
  }
  app.appendChild(el("div", { class: "panel" }, [stats]));

  const meta = el("div", { class: "panel" });
  meta.innerHTML = `
    <h3>Case Details</h3>
    <table>
      <tr><th>Case ID</th><td class="mono">${escapeHtml(c.case_id)}</td></tr>
      <tr><th>Created</th><td>${escapeHtml(c.created_at)}</td></tr>
      <tr><th>Updated</th><td>${escapeHtml(c.updated_at)}</td></tr>
    </table>`;
  app.appendChild(meta);
}

// --- Evidence ---

async function renderEvidence(app, c) {
  app.appendChild(el("h1", { text: "Evidence" }));

  const uploadBar = el("div", { class: "filter-bar" });
  const fileInput = el("input", { type: "file" });
  const uploadBtn = el("button", { text: "Upload Evidence" });
  const analyzeBtn = el("button", { class: "secondary", text: "Run Analyze" });
  uploadBar.appendChild(fileInput);
  uploadBar.appendChild(uploadBtn);
  uploadBar.appendChild(analyzeBtn);
  app.appendChild(uploadBar);

  const statusBox = el("div");
  app.appendChild(statusBox);

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);

  async function loadList() {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "loading", text: "Loading..." }));
    try {
      const items = await apiGet(`/cases/${c.case_id}/evidence`);
      panel.innerHTML = "";
      if (!items.length) {
        panel.appendChild(el("div", { class: "empty", text: "No evidence recorded." }));
        return;
      }
      const table = el("table");
      table.innerHTML =
        "<tr><th>ID</th><th>Filename</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Imported</th></tr>" +
        items
          .map(
            (e) => `<tr>
          <td class="mono">${escapeHtml(e.evidence_id)}</td>
          <td>${escapeHtml(e.filename)}</td>
          <td>${escapeHtml(e.evidence_type)}</td>
          <td>${e.size_bytes}</td>
          <td class="mono" title="${escapeHtml(e.sha256)}">${escapeHtml(e.sha256.slice(0, 16))}…</td>
          <td>${escapeHtml((e.imported_at || "").split("T")[0])}</td>
        </tr>`
          )
          .join("");
      panel.appendChild(table);
    } catch (e) {
      panel.innerHTML = "";
      panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  uploadBtn.addEventListener("click", async () => {
    const file = fileInput.files[0];
    if (!file) {
      toast("Choose a file first.", true);
      return;
    }
    uploadBtn.disabled = true;
    statusBox.innerHTML = "";
    statusBox.appendChild(el("div", { class: "loading", text: `Uploading ${file.name}...` }));
    try {
      const formData = new FormData();
      formData.append("file", file);
      const evidence = await apiUpload(`/cases/${c.case_id}/evidence`, formData);
      statusBox.innerHTML = "";
      statusBox.appendChild(
        el("div", { text: `Ingested ${evidence.evidence_id}: ${evidence.filename} (${evidence.evidence_type})` })
      );
      fileInput.value = "";
      await loadList();
    } catch (e) {
      statusBox.innerHTML = "";
      statusBox.appendChild(el("div", { class: "error-box", text: "Upload failed: " + e.message }));
    } finally {
      uploadBtn.disabled = false;
    }
  });

  analyzeBtn.addEventListener("click", async () => {
    analyzeBtn.disabled = true;
    statusBox.innerHTML = "";
    statusBox.appendChild(el("div", { class: "loading", text: "Analyzing (parsing evidence + correlating)..." }));
    try {
      const result = await apiPost(`/cases/${c.case_id}/analyze`);
      statusBox.innerHTML = "";
      const lines = result.results.map((r) =>
        r.error
          ? `${r.evidence_id}: skipped - ${r.error}`
          : `${r.evidence_id} (${r.evidence_type}): ${r.event_count} events, ${r.entity_count} entities`
      );
      lines.push(`Total: ${result.total_events} events, ${result.total_entities} distinct entities`);
      statusBox.appendChild(el("div", { text: lines.join(" · ") }));
    } catch (e) {
      statusBox.innerHTML = "";
      statusBox.appendChild(el("div", { class: "error-box", text: "Analyze failed: " + e.message }));
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  await loadList();
}

// --- Timeline ---

async function renderTimeline(app, c) {
  app.appendChild(el("h1", { text: "Timeline" }));
  const fields = ["user", "ip", "hostname", "process", "file", "type", "evidence"];
  const filterBar = el("div", { class: "filter-bar" });
  const inputs = {};
  for (const f of fields) {
    const input = el("input", { placeholder: f });
    inputs[f] = input;
    filterBar.appendChild(input);
  }
  const applyBtn = el("button", { text: "Filter" });
  const clearBtn = el("button", { class: "secondary", text: "Clear" });
  filterBar.appendChild(applyBtn);
  filterBar.appendChild(clearBtn);
  app.appendChild(filterBar);

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);

  async function load() {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "loading", text: "Loading..." }));
    const params = new URLSearchParams();
    for (const f of fields) {
      const v = inputs[f].value.trim();
      if (v) params.set(f, v);
    }
    try {
      const entries = await apiGet(`/cases/${c.case_id}/timeline?` + params.toString());
      panel.innerHTML = "";
      if (!entries.length) {
        panel.appendChild(el("div", { class: "empty", text: "No timeline entries match." }));
        return;
      }
      const table = el("table");
      table.innerHTML =
        "<tr><th>Timestamp</th><th>Type</th><th>Source</th><th>Evidence</th><th>Summary</th></tr>" +
        entries
          .map(
            (e) => `<tr>
          <td class="mono">${escapeHtml(e.timestamp || "unknown")}</td>
          <td>${escapeHtml(e.event_type)}</td>
          <td>${escapeHtml(e.source)}</td>
          <td class="mono">${escapeHtml(e.evidence_id)}</td>
          <td>${escapeHtml(summarizeEntry(e))}</td>
        </tr>`
          )
          .join("");
      panel.appendChild(table);
    } catch (e) {
      panel.innerHTML = "";
      panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  applyBtn.addEventListener("click", load);
  clearBtn.addEventListener("click", () => {
    for (const f of fields) inputs[f].value = "";
    load();
  });
  await load();
}

function summarizeEntry(e) {
  if (e.message) return e.message;
  const parts = [];
  for (const [label, key] of [
    ["user", "user"],
    ["hostname", "hostname"],
    ["src_ip", "src_ip"],
    ["dst_ip", "dst_ip"],
    ["process", "process_name"],
    ["file", "file_name"],
  ]) {
    if (e[key]) parts.push(`${label}=${e[key]}`);
  }
  return parts.join(" ") || "(no details)";
}

// --- Entities + graph + investigate ---

async function renderEntities(app, c, focusEntityId) {
  app.appendChild(el("h1", { text: "Entities" }));
  const filterBar = el("div", { class: "filter-bar" });
  const searchInput = el("input", { placeholder: "Search value..." });
  const typeSelect = el("select", {});
  typeSelect.innerHTML =
    '<option value="">All types</option>' +
    ["user", "hostname", "device", "ip_address", "domain", "url", "file", "hash", "process", "port", "network_connection"]
      .map((t) => `<option value="${t}">${t}</option>`)
      .join("");
  const searchBtn = el("button", { text: "Search" });
  filterBar.appendChild(searchInput);
  filterBar.appendChild(typeSelect);
  filterBar.appendChild(searchBtn);
  app.appendChild(filterBar);

  const layout = el("div", { class: "two-col" });
  const leftCol = el("div", {});
  const rightCol = el("div", { class: "investigate-panel" });
  layout.appendChild(leftCol);
  layout.appendChild(rightCol);
  app.appendChild(layout);

  const listPanel = el("div", { class: "panel" });
  leftCol.appendChild(listPanel);

  const canvasPanel = el("div", { class: "panel" });
  const canvasTitle = el("h3", { text: "Entity Graph" });
  canvasPanel.appendChild(canvasTitle);
  const canvas = el("canvas", { id: "graph-canvas", width: "760", height: "420" });
  canvasPanel.appendChild(canvas);
  leftCol.appendChild(canvasPanel);

  rightCol.appendChild(el("div", { class: "panel" }, [el("div", { class: "empty", text: "Select an entity to investigate." })]));

  async function loadList() {
    listPanel.innerHTML = "";
    listPanel.appendChild(el("div", { class: "loading", text: "Loading..." }));
    const params = new URLSearchParams();
    const q = searchInput.value.trim();
    const t = typeSelect.value;
    if (q) params.set("q", q);
    if (t) params.set("type", t);
    try {
      const items = await apiGet(`/cases/${c.case_id}/entities?` + params.toString());
      listPanel.innerHTML = "";
      if (!items.length) {
        listPanel.appendChild(el("div", { class: "empty", text: "No entities match." }));
        return;
      }
      const table = el("table");
      table.innerHTML = "<tr><th>Type</th><th>Value</th></tr>";
      listPanel.appendChild(table);
      for (const item of items.slice(0, 200)) {
        const tr = el("tr", { class: "clickable", onclick: () => selectEntity(item) });
        tr.innerHTML = `<td>${escapeHtml(item.entity_type)}</td><td class="mono">${escapeHtml(item.value)}</td>`;
        table.appendChild(tr);
      }
    } catch (e) {
      listPanel.innerHTML = "";
      listPanel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  async function selectEntity(item) {
    history.replaceState(null, "", `#/case/${c.case_id}/entities/${item.entity_id}`);
    canvasTitle.textContent = `Entity Graph — ${item.entity_type}: ${item.value}`;
    try {
      const graphData = await apiGet(`/cases/${c.case_id}/entities/${item.entity_id}/graph`);
      drawGraph(canvas, graphData.entity, graphData.related);
    } catch (e) {
      toast("Graph error: " + e.message, true);
    }

    rightCol.innerHTML = "";
    const panel = el("div", { class: "panel" });
    panel.appendChild(el("div", { class: "loading", text: "Investigating..." }));
    rightCol.appendChild(panel);
    try {
      const result = await apiGet(
        `/cases/${c.case_id}/investigate?type=${encodeURIComponent(item.entity_type)}&value=${encodeURIComponent(item.value)}`
      );
      await renderInvestigatePanel(panel, c, result);
    } catch (e) {
      panel.innerHTML = "";
      panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  searchBtn.addEventListener("click", loadList);
  searchInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") loadList();
  });
  await loadList();

  if (focusEntityId) {
    try {
      const graphData = await apiGet(`/cases/${c.case_id}/entities/${focusEntityId}/graph`);
      await selectEntity(graphData.entity);
    } catch (e) {
      /* deep-linked entity may not exist; ignore */
    }
  }
}

async function renderInvestigatePanel(panel, c, result) {
  panel.innerHTML = "";
  panel.appendChild(el("h3", { text: "Investigation" }));
  panel.innerHTML += `
    <div class="mono" style="margin-bottom:8px;">${escapeHtml(result.entity.entity_type)}: ${escapeHtml(result.entity.value)}</div>
    <div style="margin-bottom:10px; color: var(--text-dim); font-size:12px;">
      Evidence: ${result.evidence_ids.map(escapeHtml).join(", ") || "none"} &middot; Events: ${result.timeline.length}
    </div>`;

  panel.appendChild(el("h3", { text: "Potential Investigation Leads" }));
  const leadsBox = el("div");
  if (result.leads.length) {
    for (const lead of result.leads) leadsBox.appendChild(el("div", { class: "lead", text: lead }));
  } else {
    leadsBox.appendChild(el("div", { class: "empty", text: "No leads." }));
  }
  panel.appendChild(leadsBox);

  // Threat intel
  panel.appendChild(el("h3", { text: "Threat Intelligence" }));
  const tiBox = el("div");
  tiBox.appendChild(el("div", { class: "empty", text: "Not checked in this session." }));
  panel.appendChild(tiBox);
  const tiKeyInput = el("input", {
    placeholder: "VT API key (optional if VT_API_KEY set server-side)",
    style: "width:100%; margin-bottom:6px;",
  });
  const tiBtn = el("button", { class: "secondary", text: "Check VirusTotal" });
  panel.appendChild(tiKeyInput);
  panel.appendChild(tiBtn);
  tiBtn.addEventListener("click", async () => {
    tiBtn.disabled = true;
    tiBox.innerHTML = "";
    tiBox.appendChild(el("div", { class: "loading", text: "Checking..." }));
    try {
      const body = {
        entity_id: result.entity.entity_id,
        entity_type: result.entity.entity_type,
        value: result.entity.value,
      };
      if (tiKeyInput.value.trim()) body.api_key = tiKeyInput.value.trim();
      const r = await apiPost(`/cases/${c.case_id}/threat-intel`, body);
      tiBox.innerHTML = "";
      if (r.error) {
        // A "no API key" / HTTP / network error means no real check
        // happened - r.malicious is just an unset default in that case,
        // not a genuine negative result, so never show a verdict line
        // alongside an error.
        const message = r.error === "no API key" ? "Not checked: no API key provided." : "Error: " + r.error;
        tiBox.appendChild(el("div", { class: "error-box", text: message }));
      } else {
        const verdict = r.malicious ? "FLAGGED MALICIOUS" : "not flagged malicious";
        const engines = `${r.malicious_count ?? "?"}/${r.total_engines ?? "?"} engines`;
        tiBox.appendChild(el("div", { text: `${verdict} (${engines})${r.cached ? " — cached" : ""}` }));
      }
    } catch (e) {
      tiBox.innerHTML = "";
      tiBox.appendChild(el("div", { class: "error-box", text: e.message }));
    } finally {
      tiBtn.disabled = false;
    }
  });

  // AI hypothesis
  panel.appendChild(el("h3", { text: "AI Investigation Hypothesis" }));
  const aiBox = el("div");
  aiBox.appendChild(el("div", { class: "empty", text: "Not requested - this calls an external AI service (optional)." }));
  panel.appendChild(aiBox);

  let providerInfo = { providers: ["anthropic", "openai", "ollama", "gemini"], default_models: {} };
  try {
    providerInfo = await apiGet("/ai-providers");
  } catch (e) {
    /* falls back to the hardcoded list above if the endpoint can't be reached */
  }
  const PROVIDER_KEY_HINTS = {
    anthropic: "Anthropic API key (optional if ANTHROPIC_API_KEY set server-side)",
    openai: "OpenAI API key (optional if OPENAI_API_KEY set server-side)",
    gemini: "Gemini API key (optional if GEMINI_API_KEY set server-side)",
    ollama: "Not needed - Ollama runs locally",
  };

  const aiRow = el("div", { class: "filter-bar" });
  const aiProviderSelect = selectEl(providerInfo.providers, "anthropic");
  const aiKeyInput = el("input", { placeholder: PROVIDER_KEY_HINTS.anthropic, style: "min-width:260px;" });
  aiRow.appendChild(aiProviderSelect);
  aiRow.appendChild(aiKeyInput);
  panel.appendChild(aiRow);
  const aiModelInput = el("input", {
    placeholder: `Model override (default: ${providerInfo.default_models.anthropic || "provider default"})`,
    style: "width:100%; margin-bottom:6px;",
  });
  const aiBaseUrlInput = el("input", {
    placeholder: "Ollama server URL (default http://localhost:11434)",
    style: "width:100%; margin-bottom:6px; display:none;",
  });
  panel.appendChild(aiModelInput);
  panel.appendChild(aiBaseUrlInput);
  const aiBtn = el("button", { class: "secondary", text: "Ask AI Assistant" });
  panel.appendChild(aiBtn);

  aiProviderSelect.addEventListener("change", () => {
    const p = aiProviderSelect.value;
    aiKeyInput.placeholder = PROVIDER_KEY_HINTS[p] || "API key";
    aiKeyInput.style.display = p === "ollama" ? "none" : "";
    aiBaseUrlInput.style.display = p === "ollama" ? "" : "none";
    aiModelInput.placeholder = `Model override (default: ${providerInfo.default_models[p] || "provider default"})`;
  });

  aiBtn.addEventListener("click", async () => {
    aiBtn.disabled = true;
    aiBox.innerHTML = "";
    aiBox.appendChild(el("div", { class: "loading", text: "Asking..." }));
    try {
      const body = {
        entity_type: result.entity.entity_type,
        value: result.entity.value,
        provider: aiProviderSelect.value,
      };
      if (aiKeyInput.value.trim()) body.api_key = aiKeyInput.value.trim();
      if (aiModelInput.value.trim()) body.model = aiModelInput.value.trim();
      if (aiBaseUrlInput.value.trim()) body.base_url = aiBaseUrlInput.value.trim();
      const h = await apiPost(`/cases/${c.case_id}/ai-hypothesis`, body);
      aiBox.innerHTML = "";
      const box = el("div", { class: "hypothesis-box" });
      if (!h.evidence_sufficient) {
        box.innerHTML = `
          <div class="k">Claim</div><div>${escapeHtml(h.claim)}</div>
          <div class="k">Recommended validation</div><div>${escapeHtml(h.recommended_validation)}</div>`;
      } else {
        const citations = h.evidence.map((x) => `${escapeHtml(x.evidence_id)}/${escapeHtml(x.event_id)}`).join(", ") || "none";
        box.innerHTML = `
          <div class="k">Assessment</div><div>${escapeHtml(h.assessment)}</div>
          <div class="k">Claim</div><div>${escapeHtml(h.claim)}</div>
          <div class="k">Confidence</div><div><span class="badge badge-${cssClass(h.confidence)}">${escapeHtml(h.confidence)}</span></div>
          <div class="k">Observed Evidence</div><div>${h.observed_evidence.map((x) => "&bull; " + escapeHtml(x)).join("<br>")}</div>
          <div class="k">Alternative Explanation</div><div>${escapeHtml(h.alternative_explanation)}</div>
          <div class="k">Recommended Validation</div><div>${escapeHtml(h.recommended_validation)}</div>
          <div class="k">Cited Evidence</div><div class="mono">${citations}</div>
          <div style="margin-top:8px; color: var(--text-dim); font-size:11px;">
            AI-generated hypothesis, not a conclusion - review the cited events yourself.
          </div>`;
      }
      aiBox.appendChild(box);
    } catch (e) {
      aiBox.innerHTML = "";
      aiBox.appendChild(el("div", { class: "error-box", text: e.message }));
    } finally {
      aiBtn.disabled = false;
    }
  });
}

// --- Entity graph rendering (simple radial layout, no external libs) ---

function drawGraph(canvas, center, related) {
  const ctx = canvas.getContext("2d");
  const w = canvas.width,
    h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const cx = w / 2,
    cy = h / 2;

  const items = related.slice(0, 24);
  const maxCount = Math.max(1, ...items.map((r) => r.shared_event_count));
  const n = items.length;
  const nodes = items.map((r, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, n);
    const strength = r.shared_event_count / maxCount;
    const radius = 170 - strength * 90; // stronger relationship = drawn closer to center
    return { r, angle, x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius };
  });

  ctx.strokeStyle = "rgba(91,157,255,0.35)";
  ctx.lineWidth = 1;
  for (const node of nodes) {
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(node.x, node.y);
    ctx.stroke();
  }

  ctx.fillStyle = "#5b9dff";
  ctx.beginPath();
  ctx.arc(cx, cy, 14, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = "#e6e8ef";
  ctx.font = "12px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(truncate(center.value, 22), cx, cy - 20);

  for (const node of nodes) {
    ctx.fillStyle = colorForType(node.r.entity_type);
    ctx.beginPath();
    ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
    ctx.fill();
    ctx.fillStyle = "#9aa0b4";
    ctx.font = "10px sans-serif";
    const labelY = node.y + (node.y > cy ? 18 : -12);
    ctx.fillText(truncate(node.r.value, 18), node.x, labelY);
  }

  if (n === 0) {
    ctx.fillStyle = "#9aa0b4";
    ctx.font = "13px sans-serif";
    ctx.fillText("No related entities", cx, cy + 40);
  }
}

function truncate(s, n) {
  s = String(s || "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function colorForType(t) {
  const colors = {
    ip_address: "#5b9dff",
    user: "#4caf50",
    hostname: "#e0a030",
    domain: "#c084fc",
    hash: "#e05a4e",
    file: "#e05a4e",
    process: "#4caf50",
    port: "#9aa0b4",
    network_connection: "#5b9dff",
    device: "#e0a030",
    url: "#c084fc",
  };
  return colors[t] || "#9aa0b4";
}

// --- Chain of custody (append-only; this view is strictly read-only) ---

async function renderAudit(app, c) {
  app.appendChild(el("h1", { text: "Chain of Custody" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Every action taken on this case, in order, with who did it and when. Entries are hash-chained, " +
        "so editing or removing one is detectable. This detects accidental corruption and casual " +
        "after-the-fact editing - not someone who controls the machine, who could recompute the chain.",
    })
  );

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);
  panel.appendChild(el("div", { class: "loading", text: "Loading..." }));

  try {
    const data = await apiGet(`/cases/${c.case_id}/audit`);
    panel.innerHTML = "";

    if (data.intact) {
      panel.appendChild(
        el("div", {
          class: "lead",
          text: `Chain intact - ${data.entries.length} recorded action(s) verified.`,
        })
      );
    } else {
      const box = el("div", { class: "error-box" });
      box.appendChild(el("div", { text: "WARNING - the chain of custody does not verify:" }));
      for (const problem of data.problems) box.appendChild(el("div", { text: "• " + problem }));
      panel.appendChild(box);
    }

    if (!data.entries.length) {
      panel.appendChild(el("div", { class: "empty", text: "No actions recorded yet." }));
      return;
    }

    const table = el("table");
    table.innerHTML =
      "<tr><th>#</th><th>Timestamp (UTC)</th><th>Actor</th><th>Action</th><th>Details</th></tr>" +
      data.entries
        .map((e) => {
          const details = Object.entries(e.details || {})
            .map(([k, v]) => `${k}=${v}`)
            .join(", ");
          return `<tr>
            <td>${e.sequence}</td>
            <td class="mono">${escapeHtml(String(e.timestamp || "").slice(0, 19).replace("T", " "))}</td>
            <td>${escapeHtml(e.actor || "")}</td>
            <td class="mono">${escapeHtml(e.action || "")}</td>
            <td>${escapeHtml(details)}</td>
          </tr>`;
        })
        .join("");
    panel.appendChild(table);
  } catch (e) {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
  }
}

// --- Detections (bundled offline rules - read-only, recomputed by Analyze) ---

async function renderDetections(app, c) {
  app.appendChild(el("h1", { text: "Detections" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Local, deterministic pattern matches - no AI, no external network call. Recomputed automatically every " +
        "time you run Analyze; a flag pointing at evidence worth a look, never a claim that something malicious happened.",
    })
  );

  const filterBar = el("div", { class: "filter-bar" });
  const severitySelect = selectEl(["", "high", "medium", "low"], "");
  severitySelect.querySelector('option[value=""]').textContent = "All severities";
  filterBar.appendChild(severitySelect);
  app.appendChild(filterBar);

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);

  async function loadList() {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "loading", text: "Loading..." }));
    try {
      const query = severitySelect.value ? `?severity=${encodeURIComponent(severitySelect.value)}` : "";
      const detections = await apiGet(`/cases/${c.case_id}/detections${query}`);
      panel.innerHTML = "";
      if (!detections.length) {
        panel.appendChild(
          el("div", { class: "empty", text: "No detections. Run `netforensic analyze` to (re)scan." })
        );
        return;
      }
      const table = el("table");
      table.innerHTML =
        "<tr><th>Severity</th><th>Rule</th><th>Event</th><th>Description</th></tr>" +
        detections
          .map(
            (d) => `<tr>
          <td><span class="badge badge-${cssClass(d.severity)}">${escapeHtml(d.severity)}</span></td>
          <td class="mono">${escapeHtml(d.rule_name)}</td>
          <td class="mono">${escapeHtml(d.evidence_id)}/${escapeHtml(d.event_id)}</td>
          <td>${escapeHtml(d.description)}</td>
        </tr>`
          )
          .join("");
      panel.appendChild(table);
    } catch (e) {
      panel.innerHTML = "";
      panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  severitySelect.addEventListener("change", loadList);
  await loadList();
}

// --- Findings ---

const FINDING_STATUSES = ["Open", "Investigating", "Confirmed", "Rejected", "False Positive", "Resolved"];
const FINDING_SEVERITIES = ["Low", "Medium", "High", "Critical"];

function selectEl(options, selected) {
  const s = el("select");
  for (const opt of options) {
    const o = el("option", { value: opt, text: opt });
    if (opt === selected) o.setAttribute("selected", "selected");
    s.appendChild(o);
  }
  return s;
}

async function renderFindings(app, c) {
  app.appendChild(el("h1", { text: "Findings" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text: "Investigator-owned - nothing here is inferred or auto-generated. Creating or updating a finding here is the same explicit action as `netforensic finding create/update`.",
    })
  );

  // --- create form ---
  const createPanel = el("div", { class: "panel" });
  createPanel.appendChild(el("h3", { text: "New Finding" }));
  const titleInput = el("input", { type: "text", placeholder: "Title", style: "min-width:260px;" });
  const severitySelect = selectEl(FINDING_SEVERITIES, "Medium");
  const statusSelect = selectEl(FINDING_STATUSES, "Open");
  const assessmentInput = el("textarea", {
    placeholder: "Assessment (free text)",
    rows: "3",
    style: "width:100%; background:var(--panel-2); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:8px; margin-top:8px; font-family:inherit; font-size:13px;",
  });
  const eventIdsInput = el("input", {
    type: "text",
    placeholder: "Event IDs this is based on, comma-separated (optional)",
    style: "width:100%; margin-top:8px;",
  });
  const createRow = el("div", { class: "filter-bar", style: "margin-top:0;" });
  createRow.appendChild(titleInput);
  createRow.appendChild(severitySelect);
  createRow.appendChild(statusSelect);
  const createBtn = el("button", { text: "Create Finding" });
  createRow.appendChild(createBtn);
  createPanel.appendChild(createRow);
  createPanel.appendChild(assessmentInput);
  createPanel.appendChild(eventIdsInput);
  app.appendChild(createPanel);

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);

  async function loadList() {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "loading", text: "Loading..." }));
    try {
      const findings = await apiGet(`/cases/${c.case_id}/findings`);
      panel.innerHTML = "";
      if (!findings.length) {
        panel.appendChild(el("div", { class: "empty", text: "No findings recorded yet." }));
        return;
      }
      for (const f of findings) {
        panel.appendChild(renderFindingCard(f));
      }
    } catch (e) {
      panel.innerHTML = "";
      panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  function renderFindingCard(f) {
    const evidenceList = f.evidence_refs.map((r) => `${escapeHtml(r.evidence_id)}/${escapeHtml(r.event_id)}`).join(", ") || "none";
    const notesHtml = f.investigator_notes.length
      ? `<div style="margin-top:8px;"><h3>Notes</h3>` +
        f.investigator_notes
          .map((n) => `<div class="lead">${escapeHtml(n.timestamp)} (${escapeHtml(n.author)}): ${escapeHtml(n.text)}</div>`)
          .join("") +
        `</div>`
      : "";
    const card = el("div", { class: "panel", style: "margin-bottom:10px;" });
    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div><b>${escapeHtml(f.finding_id)}</b> &middot; ${escapeHtml(f.title)}</div>
        <div>
          <span class="badge badge-${cssClass(f.status)}">${escapeHtml(f.status)}</span>
          <span class="badge badge-${cssClass(f.severity)}">${escapeHtml(f.severity)}</span>
        </div>
      </div>
      <div style="color:var(--text-dim); margin-top:6px;">${escapeHtml(f.assessment || "(no assessment)")}</div>
      <div style="margin-top:6px; font-size:12px;" class="mono">Evidence: ${evidenceList}</div>
      ${notesHtml}`;

    const updateRow = el("div", { class: "filter-bar", style: "margin-top:10px;" });
    const newStatusSelect = selectEl(FINDING_STATUSES, f.status);
    const statusBtn = el("button", { class: "secondary", text: "Update Status" });
    updateRow.appendChild(newStatusSelect);
    updateRow.appendChild(statusBtn);
    card.appendChild(updateRow);

    const noteRow = el("div", { class: "filter-bar" });
    const noteInput = el("input", { type: "text", placeholder: "Add a note...", style: "min-width:300px;" });
    const noteBtn = el("button", { class: "secondary", text: "Add Note" });
    noteRow.appendChild(noteInput);
    noteRow.appendChild(noteBtn);
    card.appendChild(noteRow);

    statusBtn.addEventListener("click", async () => {
      statusBtn.disabled = true;
      try {
        await apiPost(`/cases/${c.case_id}/findings/${f.finding_id}`, { status: newStatusSelect.value });
        toast(`${f.finding_id} status updated to ${newStatusSelect.value}.`);
        await loadList();
      } catch (e) {
        toast("Update failed: " + e.message, true);
      } finally {
        statusBtn.disabled = false;
      }
    });

    noteBtn.addEventListener("click", async () => {
      if (!noteInput.value.trim()) {
        toast("Enter a note first.", true);
        return;
      }
      noteBtn.disabled = true;
      try {
        await apiPost(`/cases/${c.case_id}/findings/${f.finding_id}`, { note: noteInput.value.trim() });
        toast(`Note added to ${f.finding_id}.`);
        await loadList();
      } catch (e) {
        toast("Add note failed: " + e.message, true);
      } finally {
        noteBtn.disabled = false;
      }
    });

    return card;
  }

  createBtn.addEventListener("click", async () => {
    if (!titleInput.value.trim()) {
      toast("Enter a title first.", true);
      return;
    }
    createBtn.disabled = true;
    try {
      const eventIds = eventIdsInput.value
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const finding = await apiPost(`/cases/${c.case_id}/findings`, {
        title: titleInput.value.trim(),
        severity: severitySelect.value,
        status: statusSelect.value,
        assessment: assessmentInput.value.trim(),
        event_ids: eventIds,
      });
      toast(`Created ${finding.finding_id}.`);
      titleInput.value = "";
      assessmentInput.value = "";
      eventIdsInput.value = "";
      await loadList();
    } catch (e) {
      toast("Create failed: " + e.message, true);
    } finally {
      createBtn.disabled = false;
    }
  });

  await loadList();
}

// --- ATT&CK (read-only here - run/validate via `netforensic attack scan|update`) ---

async function renderAttack(app, c) {
  app.appendChild(el("h1", { text: "ATT&CK Mapping" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Deterministic, evidence-cited technique suggestions - never an automated claim that a technique " +
        "occurred. Run `netforensic attack scan --case " +
        c.case_id +
        "` to (re)scan, and `netforensic attack update` to confirm or reject a mapping.",
    })
  );

  const panel = el("div", { class: "panel" });
  app.appendChild(panel);
  panel.appendChild(el("div", { class: "loading", text: "Loading..." }));
  try {
    const techniques = await apiGet(`/cases/${c.case_id}/attack`);
    panel.innerHTML = "";
    if (!techniques.length) {
      panel.appendChild(
        el("div", { class: "empty", text: "No potential ATT&CK techniques detected. Run `netforensic attack scan`." })
      );
      return;
    }
    const table = el("table");
    table.innerHTML =
      "<tr><th>Technique</th><th>Name</th><th>Confidence</th><th>Status</th><th>Events</th></tr>" +
      techniques
        .map(
          (t) => `<tr>
        <td class="mono">${escapeHtml(t.technique_id)}</td>
        <td>${escapeHtml(t.technique_name)}</td>
        <td><span class="badge badge-${cssClass(t.confidence)}">${escapeHtml(t.confidence)}</span></td>
        <td><span class="badge badge-${cssClass(t.status)}">${escapeHtml(t.status)}</span></td>
        <td>${t.event_count}</td>
      </tr>`
        )
        .join("");
    panel.appendChild(table);
  } catch (e) {
    panel.innerHTML = "";
    panel.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
  }
}

// --- Reports ---

async function renderReports(app, c) {
  app.appendChild(el("h1", { text: "Reports" }));
  const tabs = el("div", { class: "report-tabs" });
  const formats = ["markdown", "json", "html"];
  const body = el("div", { class: "report-body" });
  app.appendChild(tabs);
  app.appendChild(body);

  async function show(fmt) {
    tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("secondary", b.dataset.fmt !== fmt));
    body.innerHTML = "";
    body.appendChild(el("div", { class: "loading", text: `Generating ${fmt} report...` }));
    try {
      const res = await fetch(`/api/cases/${c.case_id}/report/${fmt}`);
      const text = await res.text();
      if (!res.ok) throw new Error(JSON.parse(text).error || res.statusText);
      body.innerHTML = "";
      if (fmt === "html") {
        const iframe = el("iframe", { sandbox: "" });
        body.appendChild(iframe);
        iframe.srcdoc = text;
      } else {
        body.appendChild(el("pre", { text }));
      }
    } catch (e) {
      body.innerHTML = "";
      body.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  for (const fmt of formats) {
    const btn = el("button", { text: fmt, onclick: () => show(fmt) });
    btn.dataset.fmt = fmt;
    tabs.appendChild(btn);
  }
  await show("markdown");
}

// --- Live Capture ---
//
// Polled (not streamed via SSE): the server runs single-threaded so DuckDB
// access from the web request thread and a capture session's background
// ingestion thread stay serialized through one lock - see web/app.py.
// ~1.5s polling is plenty responsive for this dashboard.

async function renderCapture(app, c) {
  app.appendChild(el("h1", { text: "Live Capture" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Captures real traffic on the chosen interface into rotating pcap windows, each auto-ingested as " +
        "case evidence when it completes. Needs a packet-capture driver (Npcap/libpcap) and elevated " +
        "privileges on the machine running `netforensic web` - this UI does not grant those.",
    })
  );

  const controlBar = el("div", { class: "filter-bar" });
  const interfaceSelect = el("select", {});
  interfaceSelect.innerHTML = '<option value="">Loading interfaces...</option>';
  const filterInput = el("input", { placeholder: "BPF filter, e.g. tcp port 443" });
  const rotateInput = el("input", { type: "number", value: "30", min: "5", style: "width:80px;" });
  const rotateLabel = el("span", { text: "sec/window", style: "color:var(--text-dim); font-size:12px;" });
  const startBtn = el("button", { text: "Start Capture" });
  const stopBtn = el("button", { class: "secondary", text: "Stop Capture" });
  stopBtn.disabled = true;
  controlBar.appendChild(interfaceSelect);
  controlBar.appendChild(filterInput);
  controlBar.appendChild(rotateInput);
  controlBar.appendChild(rotateLabel);
  controlBar.appendChild(startBtn);
  controlBar.appendChild(stopBtn);
  app.appendChild(controlBar);

  const statusPanel = el("div", { class: "panel" });
  statusPanel.appendChild(el("div", { class: "empty", text: "Not running." }));
  app.appendChild(statusPanel);

  const feedPanel = el("div", { class: "panel" });
  feedPanel.appendChild(el("h3", { text: "Ingested Windows" }));
  const feedList = el("div");
  feedPanel.appendChild(feedList);
  app.appendChild(feedPanel);

  apiGet("/interfaces")
    .then((interfaces) => {
      interfaceSelect.innerHTML = interfaces.length
        ? interfaces.map((i) => `<option value="${escapeHtml(i)}">${escapeHtml(i)}</option>`).join("")
        : '<option value="">(none found)</option>';
    })
    .catch((e) => {
      interfaceSelect.innerHTML = '<option value="">(could not list interfaces)</option>';
      toast("Could not list interfaces: " + e.message, true);
    });

  function renderStatus(snap) {
    statusPanel.innerHTML = "";
    if (!snap.running) {
      statusPanel.appendChild(el("div", { class: "empty", text: "Not running." }));
      startBtn.disabled = false;
      stopBtn.disabled = true;
      return;
    }
    startBtn.disabled = true;
    stopBtn.disabled = false;

    const stats = el("div", { class: "grid-stats" });
    const defs = [
      ["Total Packets", snap.total_packet_count],
      ["Window Packets", snap.window_packet_count],
      ["Window Bytes", snap.window_byte_count],
      ["Window Age (s)", Math.round(snap.window_elapsed_seconds)],
      ["Elapsed (s)", Math.round(snap.elapsed_seconds)],
    ];
    for (const [l, n] of defs) {
      stats.appendChild(el("div", { class: "stat" }, [el("div", { class: "n", text: n }), el("div", { class: "l", text: l })]));
    }
    statusPanel.appendChild(stats);

    const protoEntries = Object.entries(snap.window_protocols || {});
    if (protoEntries.length) {
      const protoBox = el("div", { style: "margin-top:12px;" });
      protoBox.appendChild(el("h3", { text: "Current Window - Protocol Breakdown" }));
      for (const [proto, count] of protoEntries.sort((a, b) => b[1] - a[1])) {
        protoBox.appendChild(el("div", { class: "lead", text: `${proto}: ${count}` }));
      }
      statusPanel.appendChild(protoBox);
    }
  }

  // Evidence IDs already toasted, so a window's detections alert fires
  // once - not on every ~1.5s poll for as long as that window stays in
  // recent_events. Scoped to this renderCapture() call, so navigating
  // away and back (or reloading) starts fresh, which is fine.
  const alertedEvidenceIds = new Set();

  function renderFeed(events) {
    feedList.innerHTML = "";
    if (!events || !events.length) {
      feedList.appendChild(el("div", { class: "empty", text: "No windows ingested yet." }));
      return;
    }
    for (const evt of [...events].reverse()) {
      if (evt.error) {
        feedList.appendChild(el("div", { class: "lead error-box", text: `${evt.at}: error - ${evt.error}` }));
        continue;
      }
      const line = `${evt.at}: ${evt.evidence_id} - ${evt.packet_count} packets -> ${evt.event_count} events, ${evt.entity_count} entities`;
      feedList.appendChild(el("div", { class: "lead", text: line }));

      if (evt.new_detections && evt.new_detections.length) {
        const bySeverity = {};
        for (const d of evt.new_detections) bySeverity[d.severity] = (bySeverity[d.severity] || 0) + 1;
        const summary = Object.entries(bySeverity)
          .map(([s, n]) => `${n} ${s}`)
          .join(", ");
        const ruleNames = evt.new_detections.map((d) => d.rule_name).join("; ");
        feedList.appendChild(
          el("div", {
            class: "lead error-box",
            style: "margin-left:16px;",
            text: `${evt.new_detections.length} bundled detection(s) (${summary}): ${ruleNames}`,
          })
        );

        if (!alertedEvidenceIds.has(evt.evidence_id)) {
          alertedEvidenceIds.add(evt.evidence_id);
          toast(`${evt.evidence_id}: ${evt.new_detections.length} detection(s) - ${summary}`, true);
        }
      }
    }
  }

  async function poll() {
    try {
      const snap = await apiGet(`/cases/${c.case_id}/capture/status`);
      renderStatus(snap);
      renderFeed(snap.recent_events);
    } catch (e) {
      toast("Capture status error: " + e.message, true);
    }
  }

  startBtn.addEventListener("click", async () => {
    startBtn.disabled = true;
    try {
      await apiPost(`/cases/${c.case_id}/capture/start`, {
        interface: interfaceSelect.value || undefined,
        filter: filterInput.value.trim() || undefined,
        rotate_seconds: parseInt(rotateInput.value, 10) || 30,
      });
      toast("Capture started.");
      await poll();
    } catch (e) {
      toast("Could not start capture: " + e.message, true);
      startBtn.disabled = false;
    }
  });

  stopBtn.addEventListener("click", async () => {
    stopBtn.disabled = true;
    try {
      await apiPost(`/cases/${c.case_id}/capture/stop`);
      toast("Capture stopped.");
      await poll();
    } catch (e) {
      toast("Could not stop capture: " + e.message, true);
    }
  });

  await poll();
  stopCapturePolling();
  _capturePollTimer = setInterval(poll, 1500);
}
