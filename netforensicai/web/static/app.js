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

async function apiDelete(path, body) {
  const res = await fetch(API + path, {
    method: "DELETE",
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
  // Modals attach to document.body, so clearing #app does not remove
  // them. Left open across a navigation, a pivot dialog goes on showing
  // one case's evidence over another case's page - in a forensics tool
  // that is not untidy, it is wrong.
  for (const modal of document.querySelectorAll(".modal")) modal.remove();

  const parts = parseHash();
  const nav = document.getElementById("case-nav");
  const app = document.getElementById("app");

  const switcher = document.getElementById("case-switch");
  const captureCard = document.getElementById("capture-card");

  if (parts[0] === "case" && parts[1]) {
    const caseId = parts[1];
    const tab = parts[2] || "overview";
    app.innerHTML = "";
    try {
      const c = await apiGet(`/cases/${caseId}`);
      // The rail is drawn from the tshark status so the surfaces that
      // need it can be disabled with a reason rather than hidden.
      renderRail(caseId, tab, await wiresharkStatus());
      await renderCaseSwitch(c);
      renderStatusBar(c);
      renderCaptureCard(caseId);
      await renderCaseTab(app, c, tab, parts.slice(3));
    } catch (e) {
      nav.hidden = true;
      app.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  } else if (parts[0] === "settings") {
    stopCapturePolling();
    nav.hidden = true;
    switcher.innerHTML = "";
    captureCard.innerHTML = "";
    app.innerHTML = "";
    renderStatusBar(null);
    await renderSettings(app);
  } else {
    nav.hidden = true;
    switcher.innerHTML = "";
    captureCard.innerHTML = "";
    renderStatusBar(null);
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
  if (tab === "story") return renderStory(app, c);
  if (tab === "evidence") return renderEvidence(app, c);
  if (tab === "timeline") return renderTimeline(app, c);
  if (tab === "entities") return renderEntities(app, c, rest[0]);
  if (tab === "findings") return renderFindings(app, c);
  if (tab === "audit") return renderAudit(app, c);
  if (tab === "detections") return renderDetections(app, c);
  if (tab === "attack") return renderAttack(app, c);
  if (tab === "reports") return renderReports(app, c);
  if (tab === "capture") return renderCapture(app, c);
  if (tab === "search") return renderSearch(app, c);
  if (tab === "streams") return renderStreams(app, c, rest[0]);
  if (tab === "triage") return renderTriage(app, c);
  if (tab === "chat") return renderChat(app, c);
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

async function renderOverview(app, c) {
  // --- header -------------------------------------------------------
  const head = el("div", { class: "case-head" });
  head.appendChild(
    el("div", {}, [el("h1", { text: c.name }), el("div", { class: "subtitle", text: c.description || "No description." })])
  );
  const actions = el("div", { class: "case-head-actions" });
  const statusSel = el("select", { title: "Case status" });
  for (const s of ["open", "investigating", "closed"]) {
    const opt = el("option", { value: s, text: s });
    if (s === c.status) opt.selected = true;
    statusSel.appendChild(opt);
  }
  statusSel.onchange = async () => {
    try {
      await apiPost(`/cases/${c.case_id}/status`, { status: statusSel.value });
      toast(`${c.case_id} is now ${statusSel.value}`);
    } catch (e) {
      toast("Could not change status: " + e.message, true);
      statusSel.value = c.status;
    }
  };
  actions.appendChild(statusSel);
  actions.appendChild(el("button", { class: "danger", text: "Delete case", onclick: () => confirmDelete(c) }));
  head.appendChild(actions);
  app.appendChild(head);

  // --- what happened ------------------------------------------------
  //
  // Above the counts, deliberately. An investigator opening a case
  // wants the account first; "81 events" is context for a finding and
  // was never a finding itself.
  app.appendChild(narrativeCard(c, { compact: true }));

  // --- KPI row ------------------------------------------------------
  const corr = c.correlation_by_type || {};
  const kpis = [
    ["Events", c.event_count, `across ${c.evidence_count} evidence item${c.evidence_count === 1 ? "" : "s"}`, "k-blue", ICONS.event, "#5b9dff"],
    ["Entities", c.entity_count, "deterministic IDs across sources", "k-violet", ICONS.entities, "#b07cff"],
    ["Detections", c.detection_count, "offline rules, no AI", "k-red", ICONS.detections, "#e05a4e"],
    ["Correlations", c.correlation_count ?? 0, `${corr.related || 0} related · ${corr.possible_relationship || 0} possible`, "k-amber", ICONS.attack, "#e0a030"],
    ["Files carved", c.artifact_count ?? 0, "hashed into artifacts/", "k-green", ICONS.file, "#4caf50"],
    ["Findings", c.finding_count, "investigator-owned", "k-blue", ICONS.findings, "#5b9dff"],
  ];
  const row = el("div", { class: "kpis" });
  for (const [label, n, sub, cls, iconPath, stroke] of kpis) {
    const tile = el("div", { class: "kpi " + cls });
    const h = el("div", { class: "kpi-head" });
    const box = el("div", { class: "kpi-icon" });
    box.appendChild(icon(iconPath, { size: 15, stroke, width: 1.9 }));
    h.appendChild(box);
    h.appendChild(el("div", { class: "kpi-l", text: label }));
    tile.appendChild(h);
    tile.appendChild(el("div", { class: "kpi-n", text: Number(n || 0).toLocaleString() }));
    tile.appendChild(el("div", { class: "kpi-s", text: sub }));
    row.appendChild(tile);
  }
  app.appendChild(row);

  // --- analysis runner ---------------------------------------------
  const runPanel = el("div", { class: "card", style: "margin-bottom:14px" });
  const runHead = el("div", { class: "card-head" });
  runHead.appendChild(el("h3", { text: "Analysis" }));
  const runState = el("span", { class: "run-state " + (c.event_count ? "ok" : "idle"), text: c.event_count ? "complete" : "not run yet" });
  runHead.appendChild(runState);
  const runBtn = el("button", { text: c.event_count ? "Re-run analyze" : "Run analyze" });
  runHead.appendChild(el("span", { class: "right" }, [runBtn]));
  runPanel.appendChild(runHead);
  const runOut = el("div");
  runPanel.appendChild(runOut);
  app.appendChild(runPanel);

  runBtn.onclick = async () => {
    runBtn.disabled = true;
    runState.className = "run-state running";
    runState.textContent = "in progress…";
    runOut.innerHTML = "";
    runOut.appendChild(el("div", { class: "loading", text: "Parsing evidence, correlating, scanning rules…" }));
    try {
      const r = await apiPost(`/cases/${c.case_id}/analyze`, {});
      runOut.innerHTML = "";
      // Per-evidence failures are reported even when the request itself
      // succeeded: a partially-failed analyze is not a success.
      const failed = (r.results || []).filter((x) => x.error);
      if (failed.length) {
        runState.className = "run-state bad";
        runState.textContent = `completed with ${failed.length} error${failed.length === 1 ? "" : "s"}`;
        for (const f of failed) runOut.appendChild(el("div", { class: "error-box", text: `${f.evidence_id}: ${f.error}` }));
      } else {
        runState.className = "run-state ok";
        runState.textContent = "complete";
      }
      runOut.appendChild(
        el("div", { class: "dim", text: `${r.total_events} events · ${r.total_entities} entities · ${r.detection_count} detection(s)` })
      );
      setTimeout(route, 700);
    } catch (e) {
      runOut.innerHTML = "";
      runState.className = "run-state bad";
      runState.textContent = "error";
      runOut.appendChild(el("div", { class: "error-box", text: e.message }));
    } finally {
      runBtn.disabled = false;
    }
  };

  // --- charts row ---------------------------------------------------
  const charts = el("div", { class: "dash-row dash-chart" });
  const timelineCard = el("div", { class: "card" });
  timelineCard.appendChild(
    el("div", { class: "card-head" }, [el("h3", { text: "Timeline" }), el("span", { class: "dim", text: "event density" })])
  );
  const entityCard = el("div", { class: "card" });
  entityCard.appendChild(
    el("div", { class: "card-head" }, [el("h3", { text: "Top entities" }), el("span", { class: "dim", text: "by events" })])
  );
  const graphCard = el("div", { class: "card" });
  graphCard.appendChild(el("div", { class: "card-head" }, [el("h3", { text: "Entity graph" })]));
  charts.appendChild(timelineCard);
  charts.appendChild(entityCard);
  charts.appendChild(graphCard);
  app.appendChild(charts);

  // --- three tables -------------------------------------------------
  const tables = el("div", { class: "dash-row dash-3" });
  const detCard = el("div", { class: "card" });
  detCard.appendChild(el("div", { class: "card-head" }, [el("h3", { text: "Recent detections" })]));
  const fileCard = el("div", { class: "card" });
  fileCard.appendChild(el("div", { class: "card-head" }, [el("h3", { text: "Files carved" })]));
  const triCard = el("div", { class: "card" });
  triCard.appendChild(
    el("div", { class: "card-head" }, [el("h3", { text: "Triage matches" }), el("span", { class: "dim", text: "leads, not verdicts" })])
  );
  tables.appendChild(detCard);
  tables.appendChild(fileCard);
  tables.appendChild(triCard);
  app.appendChild(tables);

  // --- assistant + custody ------------------------------------------
  const bottom = el("div", { class: "dash-row dash-2" });
  const askCard = el("div", { class: "card" });
  askCard.appendChild(
    el("div", { class: "card-head" }, [
      el("h3", { text: "Assistant" }),
      el("span", { class: "dim", text: "retrieves evidence, cites what it found" }),
    ])
  );
  const auditCard = el("div", { class: "card" });
  auditCard.appendChild(el("div", { class: "card-head" }, [el("h3", { text: "Chain of custody" })]));
  bottom.appendChild(askCard);
  bottom.appendChild(auditCard);
  app.appendChild(bottom);

  // --- fill everything ----------------------------------------------
  loadInto(timelineCard, () => apiGet(`/cases/${c.case_id}/timeline`), (entries) => densityChart(entries));

  loadInto(entityCard, () => apiGet(`/cases/${c.case_id}/entities?sort=events&limit=8`), (rows) => {
    if (!rows.length) return el("div", { class: "empty", text: "No entities extracted." });
    const t = el("table", { class: "mini" });
    t.innerHTML = "<thead><tr><th>Value</th><th>Type</th><th>Events</th><th>Links</th></tr></thead>";
    const tb = el("tbody");
    for (const e of rows.slice(0, 6)) {
      tb.appendChild(
        el("tr", {}, [
          el("td", {}, [el("a", { href: `#/case/${c.case_id}/entities/${e.entity_id}`, class: "mono", text: e.value })]),
          el("td", { class: "dim", text: e.entity_type }),
          el("td", { class: "mono", text: e.event_count }),
          el("td", { class: "mono dim", text: e.link_count }),
        ])
      );
    }
    t.appendChild(tb);
    return t;
  });

  loadInto(
    graphCard,
    async () => {
      const entities = await apiGet(`/cases/${c.case_id}/entities?sort=events&limit=40`);
      if (!entities.length) return null;
      // Centre on something that identifies a host, not whichever entity
      // simply appears most. By raw event count the winner is invariably
      // a port - "1 hop from port 80" tells an investigator nothing.
      const hub =
        entities.find((e) => e.entity_type === "ip_address") ||
        entities.find((e) => e.entity_type === "domain") ||
        entities[0];
      return { hub, graph: await apiGet(`/cases/${c.case_id}/entities/${hub.entity_id}/graph`) };
    },
    (data) => (data ? entityGraph(data.hub, data.graph) : el("div", { class: "empty", text: "No entities to graph." }))
  );

  loadInto(detCard, () => apiGet(`/cases/${c.case_id}/detections`), (rows) => {
    if (!rows.length) return el("div", { class: "empty", text: "No rule matched." });
    const t = el("table", { class: "mini" });
    const tb = el("tbody");
    for (const d of rows.slice(0, 6)) {
      tb.appendChild(
        el("tr", {}, [
          el("td", { class: "mono", text: d.rule_id }),
          el("td", {}, [el("span", { class: "badge badge-" + cssClass(d.severity), text: d.severity })]),
          el("td", { class: "mono dim", text: d.evidence_id }),
        ])
      );
    }
    t.appendChild(tb);
    return t;
  });

  loadInto(fileCard, () => apiGet(`/cases/${c.case_id}/artifacts`), (rows) => {
    if (!rows.length) return el("div", { class: "empty", text: "No files carved." });
    const t = el("table", { class: "mini" });
    const tb = el("tbody");
    for (const f of rows.slice(0, 6)) {
      tb.appendChild(
        el("tr", {}, [
          el("td", { class: "mono", text: f.name }),
          el("td", { class: "dim", text: f.protocol }),
          el("td", { class: "mono dim", text: f.missing ? "missing" : `${f.size_bytes} B` }),
        ])
      );
    }
    t.appendChild(tb);
    return t;
  });

  loadInto(
    triCard,
    () => apiGet(`/cases/${c.case_id}/triage`),
    (r) => {
      if (!r.candidates.length) return el("div", { class: "empty", text: "Nothing matched the patterns." });
      const t = el("table", { class: "mini" });
      const tb = el("tbody");
      for (const x of r.candidates.slice(0, 6)) {
        tb.appendChild(
          el("tr", {}, [
            el("td", {}, [el("span", { class: "badge badge-low mono", text: x.pattern })]),
            el("td", { class: "mono hit-text", text: x.value.slice(0, 34) }),
            el("td", { class: "mono dim", text: x.frame_number }),
          ])
        );
      }
      t.appendChild(tb);
      return t;
    },
    "Needs Wireshark - install tshark to enable triage."
  );

  loadInto(auditCard, () => apiGet(`/cases/${c.case_id}/audit`), (data) => {
    const entries = data.entries || data;
    const wrap = el("div");
    if (data.intact !== undefined) {
      wrap.appendChild(
        el("div", { class: "dim", style: `color:${data.intact ? "var(--ok)" : "var(--bad)"};margin-bottom:8px` }, [
          el("span", { text: data.intact ? "hash chain intact" : "CHAIN BROKEN" }),
        ])
      );
    }
    const t = el("table", { class: "mini" });
    const tb = el("tbody");
    for (const e of entries.slice(-6).reverse()) {
      tb.appendChild(
        el("tr", {}, [
          el("td", { class: "mono dim", text: e.action }),
          el("td", { text: e.actor }),
          el("td", { class: "mono dim", text: (e.timestamp || "").slice(11, 19) }),
        ])
      );
    }
    t.appendChild(tb);
    wrap.appendChild(t);
    return wrap;
  });

  askCard.appendChild(miniAsk(c));
}

// A one-shot ask box on the dashboard. The full conversation lives on the
// Ask surface; this is for the question you have while looking at totals.
function miniAsk(c) {
  const wrap = el("div");
  const out = el("div");
  wrap.appendChild(out);

  const bar = el("div", { class: "filter-bar", style: "margin-top:10px;margin-bottom:0" });
  const q = el("input", { placeholder: "Ask about this case…", style: "flex-grow:1;min-width:200px" });
  const send = el("button", { text: "Ask" });
  bar.appendChild(q);
  bar.appendChild(send);
  wrap.appendChild(bar);

  async function ask() {
    const question = q.value.trim();
    if (!question) return;
    out.innerHTML = "";
    out.appendChild(el("div", { class: "bubble-me", text: question }));
    const pending = el("div", { class: "loading", text: "Retrieving evidence…" });
    out.appendChild(pending);
    send.disabled = true;
    try {
      const r = await apiPost(`/cases/${c.case_id}/chat`, { question });
      pending.remove();
      out.appendChild(el("div", { class: "answer", text: r.answer }));
      if (r.citations && r.citations.length) {
        const cites = el("div", { class: "cites" });
        for (const cit of r.citations) cites.appendChild(el("span", { class: "cite", text: `${cit.kind} ${cit.reference}` }));
        out.appendChild(cites);
      }
      out.appendChild(
        el("div", { class: "dim", style: "margin-top:8px", text: "Claims citing anything the tools did not return are refused, not shown." })
      );
    } catch (e) {
      pending.remove();
      const refused = /refused/i.test(e.message);
      out.appendChild(el("div", { class: refused ? "refused" : "error-box", text: (refused ? "Answer refused. " : "Error: ") + e.message }));
    } finally {
      send.disabled = false;
    }
  }
  send.onclick = ask;
  q.onkeydown = (ev) => {
    if (ev.key === "Enter") ask();
  };
  return wrap;
}

// --- charts ----------------------------------------------------------
//
// Drawn as inline SVG rather than pulled from a chart library: the UI
// ships with no build step and no CDN, and a stacked bar chart is a
// hundred lines of rectangles.

function densityChart(entries) {
  const stamped = entries.filter((e) => e.timestamp);
  if (!stamped.length) return el("div", { class: "empty", text: "No timestamped events." });

  const times = stamped.map((e) => new Date(e.timestamp).getTime());
  const first = Math.min(...times);
  const last = Math.max(...times);
  const BUCKETS = 36;
  const span = Math.max(last - first, 1);
  const width = Math.max(span / BUCKETS, 1);

  const buckets = Array.from({ length: BUCKETS }, () => ({ all: 0, detection: 0 }));
  for (const e of stamped) {
    const idx = Math.min(BUCKETS - 1, Math.floor((new Date(e.timestamp).getTime() - first) / width));
    buckets[idx].all += 1;
    if (e.event_type === "anomaly" || (e.severity && e.severity !== "info")) buckets[idx].detection += 1;
  }
  const peak = Math.max(...buckets.map((b) => b.all), 1);

  const W = 560;
  const H = 168;
  const pad = 26;
  const barW = (W - pad) / BUCKETS - 3;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("style", "width:100%;height:168px;display:block");

  let markup = "";
  for (let g = 0; g <= 3; g++) {
    const y = 10 + ((H - 40) / 3) * g;
    markup += `<line x1="${pad}" y1="${y}" x2="${W}" y2="${y}" stroke="#2a2f3f" stroke-width="1"/>`;
    const value = Math.round((peak / 3) * (3 - g));
    markup += `<text x="${pad - 5}" y="${y + 3}" fill="#6b7288" font-size="9" text-anchor="end">${value}</text>`;
  }
  buckets.forEach((b, i) => {
    const x = pad + i * ((W - pad) / BUCKETS);
    const full = ((H - 40) * b.all) / peak;
    const flagged = ((H - 40) * b.detection) / peak;
    markup += `<rect x="${x}" y="${H - 30 - full}" width="${barW}" height="${Math.max(full, 0.5)}" fill="#5b9dff" rx="1.5"/>`;
    if (flagged > 0) {
      markup += `<rect x="${x}" y="${H - 30 - flagged}" width="${barW}" height="${flagged}" fill="#e0a030" rx="1.5"/>`;
    }
  });
  const fmt = (ms) => new Date(ms).toISOString().slice(11, 16);
  markup += `<text x="${pad}" y="${H - 8}" fill="#6b7288" font-size="9">${fmt(first)}</text>`;
  markup += `<text x="${W}" y="${H - 8}" fill="#6b7288" font-size="9" text-anchor="end">${fmt(last)}</text>`;
  svg.innerHTML = markup;

  const wrap = el("div");
  wrap.appendChild(
    el("div", { class: "legend" }, [
      el("span", {}, [el("span", { class: "swatch", style: "background:#5b9dff" }), el("span", { text: "all events" })]),
      el("span", {}, [el("span", { class: "swatch", style: "background:#e0a030" }), el("span", { text: "flagged" })]),
    ])
  );
  wrap.appendChild(svg);
  wrap.appendChild(el("div", { class: "dim", style: "margin-top:6px", text: `${stamped.length.toLocaleString()} timestamped events` }));
  return wrap;
}

function entityGraph(hub, data) {
  const related = (data.related || []).slice(0, 14);
  if (!related.length) return el("div", { class: "empty", text: "No related entities." });

  const W = 340;
  const H = 200;
  const cx = W / 2;
  const cy = H / 2 - 6;
  const colour = { ip_address: "#5b9dff", domain: "#b07cff", url: "#e0a030", port: "#4caf50" };

  let markup = "";
  const points = related.map((r, i) => {
    const angle = (i / related.length) * Math.PI * 2 - Math.PI / 2;
    return { x: cx + Math.cos(angle) * 80, y: cy + Math.sin(angle) * 66, r };
  });
  for (const p of points) markup += `<line x1="${cx}" y1="${cy}" x2="${p.x}" y2="${p.y}" stroke="#2a3350" stroke-width="1"/>`;
  for (const p of points) {
    markup += `<circle cx="${p.x}" cy="${p.y}" r="5" fill="${colour[p.r.entity_type] || "#9aa0b4"}"><title>${escapeHtml(
      p.r.entity_type + " " + p.r.value
    )}</title></circle>`;
  }
  markup += `<circle cx="${cx}" cy="${cy}" r="13" fill="#5b9dff" opacity="0.25"/>`;
  markup += `<circle cx="${cx}" cy="${cy}" r="8.5" fill="#5b9dff"/>`;
  markup += `<text x="${cx}" y="${cy + 26}" fill="#9aa0b4" font-size="10" text-anchor="middle" font-family="SF Mono, Consolas, monospace">${escapeHtml(
    hub.value
  )}</text>`;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("style", "width:100%;height:200px;display:block");
  svg.innerHTML = markup;

  const wrap = el("div");
  wrap.appendChild(svg);
  wrap.appendChild(
    el("div", { class: "dim", text: `1 hop from ${hub.value} · ${related.length} of ${(data.related || []).length} shown` })
  );
  return wrap;
}

// Fill a panel from an endpoint, showing loading / empty / a degraded
// note rather than an error box for the surfaces that need Wireshark: a
// missing optional dependency is a setup step, not a fault.
async function loadInto(panel, fetcher, build, degradedNote) {
  const slot = el("div", { class: "loading", text: "Loading…" });
  panel.appendChild(slot);
  try {
    const data = await fetcher();
    slot.replaceWith(build(data));
  } catch (e) {
    const needsTshark = /tshark|wireshark/i.test(e.message);
    slot.replaceWith(
      el("div", {
        class: needsTshark ? "dim" : "error-box",
        text: needsTshark && degradedNote ? degradedNote : (needsTshark ? e.message : "Error: " + e.message),
      })
    );
  }
}

// --- The narrative: the case as an account of what happened ------------
//
// core/narrative.py does the reasoning; this only draws it. Nothing here
// derives a fact, re-orders a phase or picks a severity of its own - if
// the panel disagrees with `netforensic story` on the same case, the bug
// is here, and that is deliberate: one place decides what happened.

// The canonical stages, drawn whether or not they were evidenced. A stage
// with nothing in it is information too - but it means "no bundled rule
// matched", never "this did not happen", which is why absent chips are
// labelled rather than simply left out.
const STAGES = [
  ["reconnaissance", "Recon"],
  ["delivery", "Delivery"],
  ["credential-access", "Credentials"],
  ["collection", "Collection"],
  ["exfiltration", "Exfiltration"],
  ["command-and-control", "C2"],
];

function beatTime(iso) {
  if (!iso) return "unknown time";
  const t = String(iso).replace("T", " ");
  return t.slice(11, 19) || t.slice(0, 19);
}

function stageStrip(present) {
  const strip = el("div", { class: "nar-stages" });
  STAGES.forEach(([key, label], i) => {
    const on = present.has(key);
    strip.appendChild(
      el("span", {
        class: "nar-stage" + (on ? " on" : ""),
        text: label,
        title: on ? "" : "No bundled rule matched this stage - not proof it did not happen.",
      })
    );
    if (i < STAGES.length - 1) strip.appendChild(el("span", { class: "nar-arrow", text: "→" }));
  });
  return strip;
}

function beatRow(c, beat, opts) {
  const row = el("div", { class: "beat sev-" + cssClass(beat.severity) });
  const head = el("div", { class: "beat-head" });
  head.appendChild(el("span", { class: "beat-dot" }));
  head.appendChild(
    el("span", { class: "beat-time mono", text: beatTime(beat.first_seen), title: beat.first_seen || "" })
  );
  head.appendChild(el("span", { class: "beat-title", text: beat.title }));
  if (beat.occurrences > 1) head.appendChild(el("span", { class: "beat-x", text: "×" + beat.occurrences }));
  head.appendChild(el("span", { class: "badge badge-" + cssClass(beat.severity), text: beat.severity }));
  row.appendChild(head);
  row.appendChild(el("div", { class: "beat-desc", text: beat.description }));

  if (!(opts && opts.full)) return row;

  // Citations. The whole claim of this panel is that every sentence walks
  // back to a packet, so the ids are shown rather than summarised, and
  // each one opens where those packets actually are.
  const cite = el("div", { class: "beat-cite" });
  cite.appendChild(el("span", { class: "dim", text: "evidence " }));
  for (const id of (beat.event_ids || []).slice(0, 6)) {
    cite.appendChild(
      el("a", {
        class: "cite-chip mono",
        href: "#",
        text: id,
        title: "Show the display filter that isolates this event",
        onclick: (ev) => {
          ev.preventDefault();
          showPivot(c, id);
        },
      })
    );
  }
  const extra = (beat.event_ids || []).length - 6;
  if (extra > 0) cite.appendChild(el("span", { class: "dim", text: "+" + extra + " more" }));
  if (beat.hosts && beat.hosts.length) {
    cite.appendChild(el("span", { class: "dim", text: " · " + beat.hosts.join(", ") }));
  }
  row.appendChild(cite);
  return row;
}

// The pivot to packets. Read-only: it resolves the display filter and the
// command, and launches nothing on the server's behalf.
async function showPivot(c, eventId) {
  const box = el("div", { class: "modal" });
  const card = el("div", { class: "modal-card" });
  card.appendChild(el("h3", { text: eventId }));
  const body = el("div");
  card.appendChild(body);
  const actions = el("div", { class: "modal-actions" });
  actions.appendChild(el("button", { class: "secondary", text: "Close", onclick: () => box.remove() }));
  card.appendChild(actions);
  box.appendChild(card);
  document.body.appendChild(box);

  body.appendChild(el("div", { class: "loading", text: "Resolving..." }));
  try {
    const p = await apiGet(`/cases/${c.case_id}/events/${eventId}/wireshark`);
    body.innerHTML = "";
    body.appendChild(el("div", { class: "dim", text: "Display filter" }));
    body.appendChild(el("pre", { class: "pivot", text: p.display_filter }));
    body.appendChild(el("div", { class: "dim", text: "Open the packets" }));
    // gui_command() returns one shell-quoted string, ready to paste.
    body.appendChild(el("pre", { class: "pivot", text: p.command }));
    if (!p.gui_available) {
      body.appendChild(
        el("div", {
          class: "dim",
          text: "The Wireshark GUI was not found on this machine - run the command where it is installed.",
        })
      );
    }
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", { class: "error-box", text: e.message }));
  }
}

function narrativeBody(c, n, opts) {
  const full = !!(opts && opts.full);
  const wrap = el("div", { class: "nar-body" });

  const assess = el("div", { class: "nar-assess sev-" + cssClass(n.severity) });
  assess.appendChild(el("span", { class: "badge badge-" + cssClass(n.severity), text: n.severity }));
  assess.appendChild(el("div", { class: "nar-statement", text: n.assessment }));
  wrap.appendChild(assess);

  const bits = [n.headline];
  const window_ = n.window || [null, null];
  if (window_[0]) bits.push(beatTime(window_[0]) + " → " + beatTime(window_[1]));
  if (n.subjects && n.subjects.length) bits.push(n.subjects.join(", "));
  wrap.appendChild(el("div", { class: "nar-meta", text: bits.filter(Boolean).join("  ·  ") }));

  const phases = n.phases || [];
  if (!phases.length) return wrap;

  wrap.appendChild(stageStrip(new Set(phases.map((p) => p.phase))));

  if (full) {
    for (const phase of phases) {
      const sec = el("div", { class: "nar-phase" });
      sec.appendChild(el("div", { class: "nar-phase-title", text: phase.title }));
      for (const beat of phase.beats) sec.appendChild(beatRow(c, beat, { full: true }));
      wrap.appendChild(sec);
    }
    return wrap;
  }

  // Compact: the first few beats in the order they happened, then a way
  // through to the rest. Truncating silently would misrepresent the case.
  const flat = phases.reduce((acc, p) => acc.concat(p.beats), []);
  const shown = flat.slice(0, 4);
  const list = el("div", { class: "nar-beats" });
  for (const beat of shown) list.appendChild(beatRow(c, beat, { full: false }));
  wrap.appendChild(list);
  const hidden = flat.length - shown.length;
  if (hidden > 0) {
    wrap.appendChild(
      el("a", {
        class: "nar-more",
        href: `#/case/${c.case_id}/story`,
        text: `${hidden} more finding${hidden === 1 ? "" : "s"} in the full story →`,
      })
    );
  }
  return wrap;
}

function narrativeCard(c, opts) {
  const card = el("div", { class: "card narrative" });
  const head = el("div", { class: "card-head" });
  head.appendChild(el("h3", { text: "What happened" }));
  head.appendChild(el("span", { class: "dim", text: "assembled from detections - no model, no network" }));
  head.appendChild(
    el("span", { class: "right" }, [el("a", { href: `#/case/${c.case_id}/story`, text: "Full story →" })])
  );
  card.appendChild(head);

  loadInto(card, () => apiGet(`/cases/${c.case_id}/narrative`), (n) => {
    card.classList.add("sev-" + cssClass(n.severity));
    if (!c.event_count) {
      return el("div", {
        class: "empty",
        text: "Nothing has been analysed yet. Run analyze below, and the account of what happened appears here.",
      });
    }
    return narrativeBody(c, n, opts);
  });
  return card;
}

async function renderStory(app, c) {
  app.appendChild(el("h1", { text: "What happened" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "The case as an account rather than a count, assembled from the detections and the events they cite. " +
        "Deterministic: the same evidence produces the same story, and every line names the events it rests on.",
    })
  );
  const panel = el("div", { class: "card narrative" });
  app.appendChild(panel);
  loadInto(panel, () => apiGet(`/cases/${c.case_id}/narrative`), (n) => {
    panel.classList.add("sev-" + cssClass(n.severity));
    return narrativeBody(c, n, { full: true });
  });
}

// Deleting a case destroys the evidence AND the chain of custody, so the
// confirmation makes the caller type the ID rather than click through a
// yes/no - the same bar the CLI sets.
function confirmDelete(c) {
  const box = el("div", { class: "modal" });
  const card = el("div", { class: "modal-card" });
  card.appendChild(el("h3", { text: `Delete ${c.case_id}?` }));
  card.appendChild(
    el("div", { text: `"${c.name}" — ${c.evidence_count} evidence item(s), ${c.finding_count} finding(s).` })
  );
  card.appendChild(
    el("div", {
      class: "warn-note",
      text:
        "This is irreversible. It removes the evidence copies, the event store, carved artifacts, findings, reports and the chain of custody. There is no trash to recover it from.",
    })
  );
  const input = el("input", { placeholder: `Type ${c.case_id} to confirm`, style: "width:100%" });
  card.appendChild(input);
  const actions = el("div", { class: "modal-actions" });
  const cancel = el("button", { class: "secondary", text: "Cancel" });
  const del = el("button", { class: "danger", text: "Delete permanently" });
  del.disabled = true;
  input.oninput = () => {
    del.disabled = input.value.trim() !== c.case_id;
  };
  cancel.onclick = () => box.remove();
  del.onclick = async () => {
    del.disabled = true;
    del.textContent = "Deleting…";
    try {
      const s = await apiDelete(`/cases/${c.case_id}`, { confirm: c.case_id });
      box.remove();
      toast(`Deleted ${s.case_id} — ${s.evidence_count} evidence item(s), ${(s.size_bytes / 1e6).toFixed(1)} MB.`);
      location.hash = "#/";
    } catch (e) {
      del.disabled = false;
      del.textContent = "Delete permanently";
      card.appendChild(el("div", { class: "error-box", text: e.message }));
    }
  };
  actions.appendChild(cancel);
  actions.appendChild(del);
  card.appendChild(actions);
  box.appendChild(card);
  document.body.appendChild(box);
  input.focus();
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
        ? interfaces
            .map((i) => {
              // dumpcap supplies a human description; scapy does not.
              // Showing it is what makes a Windows \\Device\\NPF_{GUID}
              // identifiable as a particular NIC.
              const label = i.description ? `${i.name} (${i.description})` : i.name;
              return `<option value="${escapeHtml(i.name)}">${escapeHtml(label)}</option>`;
            })
            .join("")
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

    // Name the interface actually being captured. When none was chosen it is
    // the backend's own pick, which is frequently a virtual or disconnected
    // adapter - and a capture on the wrong one looks exactly like a quiet
    // network unless the name and the empty-window streak are both visible.
    if (snap.capturing_on) {
      statusPanel.appendChild(
        el("div", {
          style: "margin-top:8px;font-size:12px;opacity:0.75;",
          text: "Capturing on: " + snap.capturing_on + (snap.engine ? " (" + snap.engine + " engine)" : ""),
        })
      );
    }
    if (snap.consecutive_empty_windows >= 3) {
      statusPanel.appendChild(
        el("div", {
          style: "margin-top:8px;color:#e0a030;",
          text:
            snap.consecutive_empty_windows +
            " consecutive windows captured no packets. If traffic is expected, the interface is probably wrong.",
        })
      );
    }

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

// --- Search (content search over a capture's raw bytes) ---
//
// The event pipeline keeps no payload, so this asks the capture file
// directly through POST /search. Every hit names a frame and a stream,
// which is what makes a result a starting point rather than a dead end.

function pivotBar(c, hit) {
  const bar = el("span", { class: "pivot" });
  if (hit.stream !== null && hit.stream !== undefined) {
    bar.appendChild(
      el("a", {
        href: `#/case/${c.case_id}/streams/${hit.stream}`,
        text: `stream ${hit.stream}`,
      })
    );
    bar.appendChild(el("span", { class: "sep", text: "|" }));
  }
  const filter = `frame.number == ${hit.frame_number}`;
  bar.appendChild(
    el("span", {
      class: "clickable dim",
      text: "copy filter",
      title: filter,
      onclick: () => {
        navigator.clipboard?.writeText(filter);
        toast(`Copied: ${filter}`);
      },
    })
  );
  return bar;
}

async function renderSearch(app, c) {
  app.appendChild(el("h1", { text: "Search" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Match raw packet bytes across this case's captures. Parsing keeps no payload, so this reads the capture file directly.",
    })
  );

  const bar = el("div", { class: "filter-bar" });
  const term = el("input", { placeholder: "flag{ , password=, 4d5a9000 ...", style: "min-width:260px" });
  const mode = el("select", {});
  for (const m of ["text", "regex", "hex"]) mode.appendChild(el("option", { value: m, text: m }));
  const dfilter = el("input", { placeholder: "display filter (optional)", class: "mono", style: "min-width:240px" });
  const go = el("button", { text: "Search" });
  bar.appendChild(term);
  bar.appendChild(mode);
  bar.appendChild(dfilter);
  bar.appendChild(go);
  app.appendChild(bar);

  const out = el("div");
  app.appendChild(out);

  async function run() {
    const pattern = term.value.trim();
    if (!pattern) return;
    out.innerHTML = "";
    out.appendChild(el("div", { class: "loading", text: "Searching the capture..." }));
    go.disabled = true;
    try {
      const res = await apiPost(`/cases/${c.case_id}/search`, {
        pattern,
        mode: mode.value,
        display_filter: dfilter.value.trim() || undefined,
      });
      out.innerHTML = "";
      out.appendChild(
        el("div", { class: "result-head" }, [
          el("h3", { text: `${res.hits.length} hit${res.hits.length === 1 ? "" : "s"}` }),
          el("span", { class: "mono dim", text: res.display_filter }),
        ])
      );
      if (!res.hits.length) {
        out.appendChild(el("div", { class: "empty", text: "No packet in this capture contains that." }));
        return;
      }
      const panel = el("div", { class: "panel" });
      const table = el("table");
      table.innerHTML =
        "<thead><tr><th>Frame</th><th>Proto</th><th>Flow</th><th>Match in context</th><th>Pivot</th></tr></thead>";
      const tbody = el("tbody");
      for (const h of res.hits) {
        const excerpt = el("td", { class: "mono" });
        // Highlight the matched run without innerHTML: the excerpt is
        // evidence bytes, and evidence must never be parsed as markup.
        const text = h.excerpt || "";
        const at = h.matched ? text.indexOf(h.matched) : -1;
        if (at >= 0) {
          excerpt.appendChild(document.createTextNode(text.slice(0, at)));
          excerpt.appendChild(el("span", { class: "hit", text: h.matched }));
          excerpt.appendChild(document.createTextNode(text.slice(at + h.matched.length)));
        } else {
          excerpt.textContent = text;
        }
        const row = el("tr", {}, [
          el("td", { class: "mono dim", text: h.frame_number }),
          el("td", {}, [el("span", { class: "badge badge-investigating", text: h.protocol || "?" })]),
          el("td", { class: "mono dim", text: `${h.src || "?"} → ${h.dst || "?"}` }),
          excerpt,
          el("td", {}, [pivotBar(c, h)]),
        ]);
        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      panel.appendChild(table);
      out.appendChild(panel);
      if (res.truncated) {
        out.appendChild(el("div", { class: "dim", text: "Stopped at the hit limit - there may be more." }));
      }
    } catch (e) {
      out.innerHTML = "";
      out.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    } finally {
      go.disabled = false;
    }
  }

  go.onclick = run;
  term.onkeydown = (ev) => {
    if (ev.key === "Enter") run();
  };
}

// --- Streams ---

async function renderStreams(app, c, focus) {
  app.appendChild(el("h1", { text: "Streams" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text: "Conversations reassembled by Wireshark. A credential or a flag rarely lives in one packet.",
    })
  );

  const layout = el("div", { class: "two-col reverse" });
  const list = el("div", { class: "panel" });
  const reader = el("div", { class: "panel" });
  layout.appendChild(list);
  layout.appendChild(reader);
  app.appendChild(layout);

  reader.appendChild(el("div", { class: "empty", text: "Select a conversation to read it." }));

  async function follow(index) {
    reader.innerHTML = "";
    reader.appendChild(el("div", { class: "loading", text: "Reassembling..." }));
    try {
      const s = await apiGet(`/cases/${c.case_id}/streams/${index}`);
      reader.innerHTML = "";
      reader.appendChild(el("h3", { text: `tcp stream ${s.stream}` }));
      reader.appendChild(el("div", { class: "mono dim", text: `${s.node_a} ↔ ${s.node_b}` }));
      for (const turn of s.turns) {
        const fromA = turn.sender === "a";
        const box = el("div", { class: "turn " + (fromA ? "turn-a" : "turn-b") });
        box.appendChild(
          el("div", {
            class: "turn-head",
            text: `${fromA ? s.node_a + " →" : "← " + s.node_b} · ${turn.byte_count} bytes`,
          })
        );
        box.appendChild(el("pre", { text: turn.text }));
        reader.appendChild(box);
      }
      if (s.truncated) reader.appendChild(el("div", { class: "dim", text: "Truncated." }));
    } catch (e) {
      reader.innerHTML = "";
      reader.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
    }
  }

  list.appendChild(el("div", { class: "loading", text: "Loading conversations..." }));
  try {
    const res = await apiGet(`/cases/${c.case_id}/streams`);
    list.innerHTML = "";
    if (!res.streams.length) {
      list.appendChild(el("div", { class: "empty", text: "No TCP conversations in this capture." }));
      return;
    }
    const table = el("table");
    table.innerHTML = "<thead><tr><th>Stream</th><th>Endpoints</th><th>Volume</th><th>Proto</th></tr></thead>";
    const tbody = el("tbody");
    for (const s of res.streams) {
      const row = el("tr", { class: "clickable" }, [
        el("td", { class: "mono", text: s.stream }),
        el("td", { class: "mono dim", text: `${s.endpoint_a} → ${s.endpoint_b}` }),
        el("td", { class: "dim", text: `${s.packets} pkts · ${s.bytes} B` }),
        el("td", { text: (s.applications || []).join(", ") }),
      ]);
      row.onclick = () => follow(s.stream);
      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    list.appendChild(table);
    if (focus !== undefined && focus !== null && focus !== "") follow(focus);
  } catch (e) {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
  }
}

// --- Triage ---

async function renderTriage(app, c) {
  app.appendChild(el("h1", { text: "Triage" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "The first questions worth asking an unfamiliar capture. Read-only - nothing here becomes a finding until you say so.",
    })
  );

  const out = el("div");
  app.appendChild(out);
  out.appendChild(el("div", { class: "loading", text: "Running triage..." }));

  try {
    const r = await apiGet(`/cases/${c.case_id}/triage`);
    out.innerHTML = "";

    const cols = el("div", { class: "two-col reverse" });

    // protocols
    const protoPanel = el("div", { class: "panel" });
    protoPanel.appendChild(el("h3", { text: "Protocols" }));
    for (const p of r.protocols) {
      const row = el("div", { class: "proto-row", style: `padding-left:${p.depth * 14}px` });
      row.appendChild(el("span", { class: "mono", text: p.protocol }));
      if (p.note) row.appendChild(el("span", { class: "badge badge-medium", text: "cleartext" }));
      row.appendChild(el("span", { class: "dim right", text: p.frames }));
      protoPanel.appendChild(row);
      if (p.note) protoPanel.appendChild(el("div", { class: "proto-note", style: `padding-left:${p.depth * 14}px`, text: p.note }));
    }

    const filePanel = el("div", { class: "panel" });
    filePanel.appendChild(el("h3", { text: "Recoverable files" }));
    if (!r.files.length) filePanel.appendChild(el("div", { class: "empty", text: "None recovered." }));
    for (const f of r.files) {
      filePanel.appendChild(
        el("div", { class: "file-row" }, [
          el("div", { text: f.name }),
          el("div", { class: "mono dim", text: `${f.protocol} · ${f.size} B · ${f.sha256.slice(0, 12)}…` }),
        ])
      );
    }
    if (r.files.length) {
      filePanel.appendChild(
        el("div", { class: "dim", text: "Reported, not written. Save them with `netforensic ctf triage --extract-to`." })
      );
    }

    const left = el("div");
    left.appendChild(protoPanel);
    left.appendChild(filePanel);

    // candidates
    const candPanel = el("div", { class: "panel" });
    candPanel.appendChild(
      el("div", { class: "result-head" }, [
        el("h3", { text: `Candidates (${r.candidates.length})` }),
        el("span", { class: "dim", text: "strings that matched a pattern - leads to judge, not verdicts" }),
      ])
    );
    if (!r.candidates.length) {
      candPanel.appendChild(el("div", { class: "empty", text: "Nothing matched." }));
    }
    for (const cat of ["flags", "credentials", "secrets"]) {
      const rows = r.candidates.filter((x) => x.category === cat);
      if (!rows.length) continue;
      candPanel.appendChild(el("h3", { text: cat }));
      const table = el("table");
      const tbody = el("tbody");
      for (const x of rows) {
        tbody.appendChild(
          el("tr", {}, [
            el("td", {}, [el("span", { class: "badge badge-low mono", text: x.pattern })]),
            el("td", { class: "mono hit-text", text: x.value }),
            el("td", { class: "mono dim", text: `frame ${x.frame_number}` }),
            el("td", {}, [pivotBar(c, x)]),
          ])
        );
      }
      table.appendChild(tbody);
      candPanel.appendChild(table);
    }

    cols.appendChild(candPanel);
    cols.appendChild(left);
    out.appendChild(cols);
  } catch (e) {
    out.innerHTML = "";
    out.appendChild(el("div", { class: "error-box", text: "Error: " + e.message }));
  }
}

// --- Assistant ---

async function renderChat(app, c) {
  app.appendChild(el("h1", { text: "Assistant" }));
  app.appendChild(
    el("div", {
      class: "subtitle",
      text:
        "Ask about this case. The assistant retrieves evidence itself, and every claim is checked against what it retrieved - an answer citing anything else is refused rather than shown.",
    })
  );

  const log = el("div", { class: "chat-log" });
  app.appendChild(log);

  const bar = el("div", { class: "filter-bar" });
  const q = el("input", { placeholder: "Was anything downloaded from an external host?", style: "flex-grow:1;min-width:320px" });
  const send = el("button", { text: "Ask" });
  bar.appendChild(q);
  bar.appendChild(send);
  app.appendChild(bar);

  async function ask() {
    const question = q.value.trim();
    if (!question) return;
    q.value = "";
    log.appendChild(el("div", { class: "bubble-me", text: question }));

    const pending = el("div", { class: "loading", text: "Retrieving evidence…" });
    log.appendChild(pending);
    send.disabled = true;
    try {
      const r = await apiPost(`/cases/${c.case_id}/chat`, { question });
      pending.remove();

      if (r.steps && r.steps.length) {
        const steps = el("div", { class: "panel steps" });
        steps.appendChild(el("h3", { text: "Retrieved" }));
        for (const s of r.steps) {
          steps.appendChild(
            el("div", { class: "step" }, [
              el("span", { class: "mono", text: s.tool }),
              el("span", { class: "dim right", text: s.error || s.summary }),
            ])
          );
        }
        log.appendChild(steps);
      }

      log.appendChild(el("div", { class: "answer", text: r.answer }));
      if (!r.evidence_sufficient) {
        log.appendChild(el("div", { class: "badge badge-medium", text: "evidence judged insufficient" }));
      }
      if (r.citations && r.citations.length) {
        const cites = el("div", { class: "cites" });
        cites.appendChild(el("span", { class: "dim", text: "Cited evidence:" }));
        for (const cit of r.citations) {
          const label = `${cit.kind} ${cit.reference}`;
          if (cit.kind === "stream") {
            cites.appendChild(el("a", { class: "cite", href: `#/case/${c.case_id}/streams/${cit.reference}`, text: label }));
          } else {
            cites.appendChild(el("span", { class: "cite", text: label }));
          }
        }
        log.appendChild(cites);
      }
    } catch (e) {
      pending.remove();
      // A refusal is not a crash - it is the contract working. Say so.
      const refused = /refused/i.test(e.message);
      log.appendChild(
        el("div", { class: refused ? "refused" : "error-box", text: (refused ? "Answer refused. " : "Error: ") + e.message })
      );
    } finally {
      send.disabled = false;
      log.scrollTop = log.scrollHeight;
    }
  }

  send.onclick = ask;
  q.onkeydown = (ev) => {
    if (ev.key === "Enter") ask();
  };
}

// --- Application shell: rail, case switcher, status bar --------------
//
// The rail, the switcher and the status bar are chrome: they persist
// across routes and are re-rendered from the case the router already
// fetched, rather than each re-fetching it.

function icon(path, opts) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", (opts && opts.size) || 16);
  svg.setAttribute("height", (opts && opts.size) || 16);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", (opts && opts.stroke) || "currentColor");
  svg.setAttribute("stroke-width", (opts && opts.width) || 1.8);
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.innerHTML = path;
  return svg;
}

const ICONS = {
  overview: '<path d="M3 10.5L12 3l9 7.5"/><path d="M5.5 9.5V21h13V9.5"/>',
  evidence: '<rect x="3" y="6" width="18" height="14" rx="2"/><path d="M3 10h18"/>',
  capture: '<circle cx="12" cy="12" r="3"/><path d="M5 8a9 9 0 0 0 0 8M19 8a9 9 0 0 1 0 8"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.6-3.6"/>',
  streams: '<path d="M4 8h10M4 16h16"/><circle cx="17" cy="8" r="2.2"/><circle cx="7" cy="16" r="2.2"/>',
  triage: '<path d="M5 4h11l4 4v12H5z"/><path d="M9 13l2 2 4-4"/>',
  timeline: '<circle cx="12" cy="12" r="8"/><path d="M12 7.5V12l3 2"/>',
  entities: '<circle cx="9" cy="9" r="3"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><circle cx="17" cy="8" r="2.4"/>',
  detections: '<path d="M12 3l8 3.5v6c0 4.6-3.2 8.5-8 10.5-4.8-2-8-5.9-8-10.5v-6z"/><path d="M12 9v4"/>',
  attack: '<circle cx="6" cy="12" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8.2 10.9l7.6-3.8M8.2 13.1l7.6 3.8"/>',
  findings: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h5"/>',
  reports: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  audit: '<path d="M6 3h12v18l-6-3-6 3z"/>',
  chat: '<path d="M21 11.5a8.4 8.4 0 0 1-9 8.4 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.2A8.4 8.4 0 0 1 12 3a8.4 8.4 0 0 1 9 8.5z"/>',
  check: '<path d="M5 12l5 5L20 7"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  event: '<path d="M3 13h4l3-8 4 16 3-8h4"/>',
  arrow: '<path d="M5 12h13M13 6l6 6-6 6"/>',
  story: '<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H12v18H6.5A2.5 2.5 0 0 1 4 18.5z"/><path d="M20 5.5A2.5 2.5 0 0 0 17.5 3H12v18h5.5A2.5 2.5 0 0 0 20 18.5z"/>',
};

// tab -> [group, label, icon]. The group headings are the four stages of
// an investigation; `null` means the item stands alone.
const RAIL = [
  [null, "overview", "Overview", "overview"],
  [null, "story", "What happened", "story"],
  ["Evidence", "evidence", "Evidence", "evidence"],
  [null, "capture", "Live capture", "capture"],
  ["Dig", "search", "Search", "search"],
  [null, "streams", "Streams", "streams"],
  [null, "triage", "Triage", "triage"],
  ["Analysis", "timeline", "Timeline", "timeline"],
  [null, "entities", "Entities", "entities"],
  [null, "detections", "Detections", "detections"],
  [null, "attack", "ATT&CK", "attack"],
  ["Conclude", "findings", "Findings", "findings"],
  [null, "reports", "Reports", "reports"],
  [null, "audit", "Chain of custody", "audit"],
  ["Assistant", "chat", "Ask (cited)", "chat"],
];

// Surfaces that cannot work without tshark. Disabled with a reason
// rather than hidden - see the CSS note on .rail a.locked.
const NEEDS_TSHARK = new Set(["search", "streams", "triage"]);

let _wiresharkStatus = null;

async function wiresharkStatus() {
  if (_wiresharkStatus === null) {
    try {
      _wiresharkStatus = await apiGet("/wireshark/status");
    } catch (e) {
      _wiresharkStatus = { available: false, error: e.message };
    }
  }
  return _wiresharkStatus;
}

function renderRail(caseId, tab, tshark) {
  const nav = document.getElementById("case-nav");
  nav.innerHTML = "";
  nav.hidden = false;
  for (const [group, key, label, iconKey] of RAIL) {
    if (group) nav.appendChild(el("div", { class: "rail-group", text: group }));
    const locked = NEEDS_TSHARK.has(key) && tshark && !tshark.available;
    const link = el("a", {
      href: locked ? "#" : `#/case/${caseId}/${key}`,
      class: "rail-link" + (key === tab ? " active" : "") + (locked ? " locked" : ""),
      title: locked ? "Needs tshark - install Wireshark to enable this" : "",
    });
    link.appendChild(icon(ICONS[iconKey]));
    link.appendChild(document.createTextNode(label));
    if (key === tab) link.appendChild(icon(ICONS.arrow, { size: 13 })).classList.add("chev");
    if (locked) link.onclick = (ev) => ev.preventDefault();
    nav.appendChild(link);
  }
}

async function renderCaseSwitch(c) {
  const box = document.getElementById("case-switch");
  box.innerHTML = "";
  box.appendChild(el("span", { class: "dim", text: "Case" }));

  const select = el("select", { title: "Switch case" });
  select.appendChild(el("option", { value: c.case_id, text: `${c.case_id} · ${c.name}` }));
  select.onchange = () => {
    location.hash = `#/case/${select.value}/overview`;
  };
  box.appendChild(select);

  const analysed = c.event_count > 0;
  box.appendChild(
    el("div", { class: "case-meta" }, [
      el("span", { class: "dot " + (analysed ? "ok" : "idle") }),
      el("span", { text: analysed ? "Analyzed" : "Not analyzed" }),
      el("span", { class: "badge badge-" + cssClass(c.status), text: c.status }),
      el("span", {
        class: "dim",
        text: `${c.evidence_count} evidence item${c.evidence_count === 1 ? "" : "s"}`,
      }),
    ])
  );

  // Populated after the first paint: the switcher must not wait on a
  // second request before the case it already has can be shown.
  try {
    const cases = await apiGet("/cases");
    select.innerHTML = "";
    for (const other of cases) {
      const opt = el("option", { value: other.case_id, text: `${other.case_id} · ${other.name}` });
      if (other.case_id === c.case_id) opt.selected = true;
      select.appendChild(opt);
    }
  } catch (e) {
    /* one case in the switcher is still a usable switcher */
  }
}

async function renderCaptureCard(caseId) {
  const box = document.getElementById("capture-card");
  box.innerHTML = "";
  let snap;
  try {
    snap = await apiGet(`/cases/${caseId}/capture/status`);
  } catch (e) {
    return;
  }
  if (!snap.running) return;

  const card = el("div", { class: "capture-card" });
  card.appendChild(el("div", { class: "rail-group", style: "padding:0 0 8px", text: "Capture status" }));
  card.appendChild(
    el("div", { style: "display:flex;align-items:center;gap:7px;margin-bottom:8px" }, [
      el("span", { class: "dot ok" }),
      el("span", { style: "color:var(--ok);font-size:13px", text: "Running" }),
      el("span", { class: "badge badge-low", style: "margin-left:auto", text: snap.engine || "" }),
    ])
  );
  const rows = [
    ["Interface", snap.capturing_on || snap.interface || "(default)"],
    ["Window", (snap.window_packet_count || 0).toLocaleString()],
    ["Total", (snap.total_packet_count || 0).toLocaleString()],
    ["Elapsed", formatDuration(snap.elapsed_seconds || 0)],
  ];
  for (const [k, v] of rows) {
    card.appendChild(el("div", { class: "row" }, [el("span", { class: "dim", text: k }), el("span", { text: String(v) })]));
  }
  if (snap.consecutive_empty_windows >= 3) {
    card.appendChild(
      el("div", {
        class: "dim",
        style: "color:var(--warn);margin-top:8px;line-height:1.4",
        text: `${snap.consecutive_empty_windows} empty windows - wrong interface?`,
      })
    );
  }
  box.appendChild(card);
}

function formatDuration(seconds) {
  const s = Math.floor(seconds % 60);
  const m = Math.floor((seconds / 60) % 60);
  const h = Math.floor(seconds / 3600);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

async function renderStatusBar(c) {
  const bar = document.getElementById("statusbar");
  bar.innerHTML = "";
  bar.appendChild(el("span", { text: "NetForensicAI" }));

  const tshark = await wiresharkStatus();
  bar.appendChild(
    el("span", { class: "item" }, [
      el("span", { class: "dot " + (tshark.available ? "ok" : "bad") }),
      el("span", { text: tshark.available ? `tshark ${tshark.version || ""}`.trim() : "tshark not found" }),
    ])
  );
  if (tshark.dumpcap) {
    bar.appendChild(el("span", { class: "item" }, [el("span", { class: "dot ok" }), el("span", { text: "dumpcap" })]));
  }
  if (c) {
    bar.appendChild(el("span", { class: "right", text: `cases/${c.case_id}` }));
  }
}
