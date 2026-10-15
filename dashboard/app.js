/* ARGUS Operator Dashboard client (Phase 11).
 * Dependency-free vanilla JS. Every action is a single, explicit operator step:
 * Approve or Reject a specific hypothesis. There is deliberately NO "approve all"
 * or bulk control on this page, in this client, or in the API (by design).
 *
 * Phase 17 adds a read-only AI analysis panel for the selected run, rendered from
 * GET /runs/{id}/ai-analysis through the same authenticated fetch used by every other
 * call on this page. It adds no control, no credential handling and no framework: the
 * analysis records are shown as they were persisted, and there is deliberately no way to
 * act on them here -- promoting a proposal to a validated finding is still exclusively
 * the explicit approve step on a hypothesis below.
 */
(function () {
  "use strict";

  var KEY_STORE = "argus.dashboard.key";
  var keyInput = document.getElementById("apiKey");
  var connectBtn = document.getElementById("connect");
  var statusEl = document.getElementById("authStatus");
  var runBox = document.getElementById("auth");
  var runsEl = document.getElementById("runs");
  var runList = document.getElementById("runList");
  var hySec = document.getElementById("hypotheses");
  var hyList = document.getElementById("hypoList");
  var runTitle = document.getElementById("currentRun");
  var aiSec = document.getElementById("aiAnalysis");
  var aiList = document.getElementById("aiList");
  var aiEmpty = document.getElementById("aiEmpty");
  var aiDiag = document.getElementById("aiDiag");
  var gapSec = document.getElementById("aiCoverageGaps");
  var gapList = document.getElementById("gapList");
  var gapEmpty = document.getElementById("gapEmpty");
  var gapDiag = document.getElementById("gapDiag");
  var runTitleAnalysis = document.getElementById("currentRunAnalysis");

  var apiKey = "";
  var base = "/api/v1";
  var currentRun = null;

  function warn(msg) {
    statusEl.textContent = msg;
    statusEl.classList.add("err");
  }

  function clearWarn() {
    statusEl.textContent = "";
    statusEl.classList.remove("err");
  }

  function request(method, path, body, key) {
    var opts = {
      method: method,
      headers: { "Authorization": "Bearer " + (key || apiKey), "Accept": "application/json" }
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(base + path, opts).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) {
          var err = new Error((data && data.detail) || ("HTTP " + res.status));
          err.status = res.status;
          throw err;
        }
        return data;
      });
    });
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function connect() {
    var k = keyInput.value.trim();
    if (!k) { warn("API key required"); return; }
    apiKey = k;
    clearWarn();
    request("GET", "/runs", undefined, k)
      .then(renderRuns)
      .catch(function (e) { warn(e.message); apiKey = ""; });
  }

  function renderRuns(data) {
    keyInput.disabled = true;
    connectBtn.disabled = true;
    localStorage.setItem(KEY_STORE, apiKey);
    runBox.hidden = true;
    runsEl.hidden = false;
    runList.innerHTML = "";
    (data.runs || []).forEach(function (r) {
      var li = document.createElement("li");
      var btn = document.createElement("button");
      btn.className = "run";
      btn.type = "button";
      btn.textContent = "Run " + r.id + " -- " + r.status;
      btn.addEventListener("click", function () { openRun(r.id, r.status); });
      li.appendChild(btn);
      runList.appendChild(li);
    });
  }

  function openRun(runId, status) {
    currentRun = runId;
    runTitle.textContent = "Run " + runId + " (" + status + ")";
    runTitleAnalysis.textContent = "Run " + runId;
    hySec.hidden = false;
    aiSec.hidden = false;
    if (gapSec) { gapSec.hidden = false; }
    request("GET", "/runs/" + runId + "/hypotheses")
      .then(renderHypotheses)
      .catch(function (e) { warn(e.message); });
    loadAiAnalysis(runId);
    loadCoverageGaps(runId);
  }

  /* The AI panel is supplementary: a failure to read it must never disturb the
   * hypotheses the operator is here to review, so it reports its own state inline
   * instead of raising the page-level warning. */
  function loadAiAnalysis(runId) {
    aiList.innerHTML = "";
    aiEmpty.hidden = true;
    aiDiag.textContent = "Loading...";
    request("GET", "/runs/" + runId + "/ai-analysis")
      .then(renderAiAnalysis)
      .catch(function (e) {
        aiList.innerHTML = "";
        aiDiag.textContent = "AI analysis unavailable: " + e.message;
      });
  }

  function renderAiAnalysis(data) {
    aiList.innerHTML = "";
    var items = data.ai_analysis || [];
    aiEmpty.hidden = items.length > 0;
    /* Surface why there is nothing to show. Before Phase 17 an empty analysis
     * list was ambiguous between "AI was never wired" and "AI found nothing";
     * the API now reports that distinction. */
    var d = data.diagnostics || {};
    var parts = ["count: " + items.length];
    if (d.status) { parts.push("status: " + d.status); }
    if (d.enabled === false) { parts.push("AI disabled in configuration"); }
    if (d.wired === false) { parts.push("intelligence layer not wired"); }
    aiDiag.textContent = parts.join(" -- ");
    items.forEach(function (a) { aiList.appendChild(aiCard(a)); });
  }

  function aiCard(a) {
    var card = document.createElement("article");
    card.className = "card";
    card.dataset.analysisId = a.id;

    var head = document.createElement("div");
    head.className = "meta";
    head.textContent = a.id + " -- " + (a.proposal_type || "unknown") +
      " -- agent " + (a.agent_name || "") + " -- truth label " + (a.truth_label || "UNLABELLED");

    var kind = document.createElement("p");
    kind.className = "stmt";
    kind.textContent = "model: " + (a.model_used || "") +
      (a.target ? " -- target: " + a.target : "");

    card.appendChild(head);
    card.appendChild(kind);

    var ev = a.evidence;
    if (ev && ev.length) {
      var e = document.createElement("p");
      e.className = "meta";
      e.textContent = "evidence: " + ev.join(", ");
      card.appendChild(e);
    }
    if (a.created_at) {
      var t = document.createElement("p");
      t.className = "meta";
      t.textContent = "recorded: " + a.created_at;
      card.appendChild(t);
    }
    return card;
  }

  function renderHypotheses(data) {
    hyList.innerHTML = "";
    (data.hypotheses || []).forEach(function (h) {
      hyList.appendChild(hypothesisCard(h));
    });
  }

  function hypothesisCard(h) {
    var card = document.createElement("article");
    card.className = "card " + h.review_status;
    card.dataset.hid = h.id;

    var head = document.createElement("div");
    head.className = "meta";
    head.textContent = h.id + " -- step " + h.validation_step + " -- confidence " + h.confidence;

    var st = document.createElement("p");
    st.className = "stmt";
    st.textContent = h.statement;

    var meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = "truth label: " + h.truth_label + " -- severity: " + h.severity + " -- target: " + h.target;

    var acts = document.createElement("div");
    acts.className = "actrow";

    var approve = document.createElement("button");
    approve.type = "button";
    approve.className = "approve";
    approve.textContent = "Approve this validation step";
    approve.addEventListener("click", function () {
      approve.disabled = true;
      request("POST", "/runs/" + currentRun + "/hypotheses/" + h.id + "/approve", {})
        .then(function (r) { refreshReview(card, r); })
        .catch(function (e) { warn(e.message); approve.disabled = false; });
    });

    var reject = document.createElement("button");
    reject.type = "button";
    reject.className = "reject";
    reject.textContent = "Reject this validation step";
    reject.addEventListener("click", function () {
      var reason = window.prompt("Reason for rejection:", "operator review: confidence insufficient");
      if (reason === null) { return; }
      reject.disabled = true;
      request("POST", "/runs/" + currentRun + "/hypotheses/" + h.id + "/reject", { reason: reason || "operator review: rejected" })
        .then(function (r) { refreshReview(card, r); })
        .catch(function (e) { warn(e.message); reject.disabled = false; });
    });

    acts.appendChild(approve);
    acts.appendChild(reject);

    card.appendChild(head);
    card.appendChild(st);
    card.appendChild(meta);
    card.appendChild(acts);
    return card;
  }

  function refreshReview(card, payload) {
    if (!payload) { return; }
    card.className = "card " + payload.review_status;
    card.dataset.hid = payload.id;
    var acts = card.querySelectorAll(".actrow button");
    for (var i = 0; i < acts.length; i += 1) { acts[i].disabled = true; }
    var p = document.createElement("p");
    p.className = "meta";
    p.textContent = "recorded: " + payload.review_status + (payload.review_reason ? " -- " + payload.review_reason : "");
    card.appendChild(p);
    clearWarn();
  }

  function loadCoverageGaps(runId) {
    if (!gapList || !gapDiag || !gapEmpty) { return; }
    gapList.innerHTML = "";
    gapEmpty.hidden = true;
    gapDiag.textContent = "Loading...";
    request("GET", "/runs/" + runId + "/ai-coverage-gaps")
      .then(renderCoverageGaps)
      .catch(function (e) {
        gapList.innerHTML = "";
        gapDiag.textContent = "Coverage gaps unavailable: " + e.message;
      });
  }

  function renderCoverageGaps(data) {
    if (!gapList || !gapDiag || !gapEmpty) { return; }
    gapList.innerHTML = "";
    var items = data.ai_coverage_gaps || [];
    gapEmpty.hidden = items.length > 0;
    var parts = ["count: " + items.length];
    gapDiag.textContent = parts.join(" -- ");
    items.forEach(function (g) { gapList.appendChild(gapCard(g)); });
  }

  function gapCard(g) {
    var card = document.createElement("article");
    card.className = "card";
    card.dataset.gapId = g.id;
    var head = document.createElement("div");
    head.className = "meta";
    head.textContent = (g.stage || "unknown") + " -- observed " + (g.observation_count || 1) + " time(s)";
    var meta = document.createElement("p");
    meta.className = "meta";
    var bits = [];
    if (g.first_seen_at) { bits.push("first: " + g.first_seen_at); }
    if (g.last_seen_at) { bits.push("last: " + g.last_seen_at); }
    meta.textContent = bits.join(" -- ");
    card.appendChild(head);
    if (bits.length) { card.appendChild(meta); }
    return card;
  }

  function boot() {
    var saved = localStorage.getItem(KEY_STORE);
    if (saved) {
      keyInput.value = saved;
      apiKey = saved;
      keyInput.disabled = true;
      connectBtn.disabled = true;
      request("GET", "/runs")
        .then(renderRuns)
        .catch(function () {
          keyInput.disabled = false;
          connectBtn.disabled = false;
          warn("Saved key rejected; re-enter the key to connect.");
        });
    }
    connectBtn.addEventListener("click", connect);
    keyInput.addEventListener("keydown", function (e) { if (e.key === "Enter") { connect(); } });
  }

  boot();
})();
