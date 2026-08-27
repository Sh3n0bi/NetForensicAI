const API = "/api";

async function apiGet(path) {
  const res = await fetch(API + path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function apiPost(path, body) {
  const res = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
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
  } else {
    nav.hidden = true;
    document.getElementById("case-nav-name").textContent = "";
    await renderCaseList(app);
  }
}

async function renderCaseTab(app, c, tab, rest) {
  if (tab === "evidence") return renderEvidence(app, c);
  if (tab === "timeline") return renderTimeline(app, c);
  if (tab === "entities") return renderEntities(app, c, rest[0]);
  if (tab === "findings") return renderFindings(app, c);
  if (tab === "reports") return renderReports(app, c);
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
  const panel = el("div", { class: "panel" });
  app.appendChild(panel);
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
      renderInvestigatePanel(panel, c, result);
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

function renderInvestigatePanel(panel, c, result) {
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
  const aiKeyInput = el("input", {
    placeholder: "Anthropic API key (optional if ANTHROPIC_API_KEY set server-side)",
    style: "width:100%; margin-bottom:6px;",
  });
  const aiBtn = el("button", { class: "secondary", text: "Ask AI Assistant" });
  panel.appendChild(aiKeyInput);
  panel.appendChild(aiBtn);
  aiBtn.addEventListener("click", async () => {
    aiBtn.disabled = true;
    aiBox.innerHTML = "";
    aiBox.appendChild(el("div", { class: "loading", text: "Asking..." }));
    try {
      const body = { entity_type: result.entity.entity_type, value: result.entity.value };
      if (aiKeyInput.value.trim()) body.api_key = aiKeyInput.value.trim();
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

// --- Findings ---

async function renderFindings(app, c) {
  app.appendChild(el("h1", { text: "Findings" }));
  const panel = el("div", { class: "panel" });
  app.appendChild(panel);
  panel.appendChild(el("div", { class: "loading", text: "Loading..." }));
  try {
    const findings = await apiGet(`/cases/${c.case_id}/findings`);
    panel.innerHTML = "";
    if (!findings.length) {
      panel.appendChild(
        el("div", {
          class: "empty",
          text: `No findings recorded. Create one with: netforensic finding create --case ${c.case_id} --title "..."`,
        })
      );
      return;
    }
    for (const f of findings) {
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
      panel.appendChild(card);
    }
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
